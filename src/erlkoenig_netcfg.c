/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * erlkoenig_netcfg.c - Container network configuration via netlink.
 *
 * All operations use raw AF_NETLINK/NETLINK_ROUTE sockets.
 * The caller's network namespace is saved and restored via setns().
 *
 * Netlink message format (same as in the Erlang erlkoenig_netlink module):
 *   nlmsghdr (16 bytes) + type-specific struct + NLA attributes
 *   All integers are native endian (kernel ABI).
 *
 * Reference: man 7 netlink, man 7 rtnetlink
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "erlkoenig_netcfg.h"
#include "erlkoenig_log.h"
#include "erlkoenig_cleanup.h"

/* Maximum netlink message size */
#define NL_BUFSZ 4096

/*
 * The kernel NLA macros use signed int arithmetic which triggers
 * -Wsign-conversion. Define our own unsigned versions.
 */
#define NL_ATTR_HDRLEN	   ((size_t)4)
#define NL_ATTR_ALIGN(len) (((len) + 3U) & ~3U)

/*
 * Write an NLA header at `buf + off`.  The caller-computed `off` is
 * always 4-aligned (NL_ATTR_ALIGN above), but `buf` is a char* so
 * the compiler can't prove alignment.  memcpy stays portable on
 * strict-alignment platforms (ARM) and the compiler folds it to
 * an aligned 4-byte store on x86.
 */
static inline void nl_put_attr_hdr(void *buf, size_t off, uint16_t len,
				   uint16_t type)
{
	uint8_t *p = (uint8_t *)buf + off;
	memcpy(p, &len, sizeof(len));
	memcpy(p + sizeof(len), &type, sizeof(type));
}

/* -- Netlink helpers ---------------------------------------------- */

static int nl_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;
	/*
	 * Set a generous recv timeout. Without this, a dropped kernel reply
	 * (SO_RCVBUF overflow, kernel OOM, adversarial flood of foreign
	 * netlink traffic) wedges recv() forever and deadlocks the whole
	 * runtime. nft.c already does the same for its NETFILTER socket.
	 */
	struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) {
		int e = errno;
		LOG_ERR("nl_open: setsockopt(SO_RCVTIMEO): %s", strerror(e));
		close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

/*
 * nl_send_recv_ack - Send a netlink message and wait for the ACK.
 * Returns 0 on success (ACK with error=0), negative errno on failure.
 */
static int nl_send_recv_ack(int nlfd, void *msg, size_t msg_len)
{
	uint8_t resp[NL_BUFSZ];
	struct nlmsghdr *nh;
	struct nlmsgerr *err;
	ssize_t n;

	if (send(nlfd, msg, msg_len, 0) < 0)
		return -errno;

	do {
		n = recv(nlfd, resp, sizeof(resp), 0);
	} while (n < 0 && errno == EINTR);

	if (n < 0)
		return -errno;

	if ((size_t)n < sizeof(struct nlmsghdr))
		return -EBADMSG;

	nh = (struct nlmsghdr *)resp;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		if ((size_t)n < sizeof(struct nlmsghdr) + sizeof(int))
			return -EBADMSG;
		err = (struct nlmsgerr *)NLMSG_DATA(nh);
		if (err->error == 0)
			return 0;
		return err->error; /* Already negative */
	}

	/* Unexpected response type -- treat as success for NEWLINK etc. */
	return 0;
}

/*
 * nl_get_ifindex - Get the interface index by name.
 * Returns ifindex on success (>0), negative errno on failure.
 */
static int nl_get_ifindex(int nlfd, const char *ifname)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req;
	uint8_t resp[NL_BUFSZ];
	struct nlmsghdr *nh;
	struct ifinfomsg *ifi;
	struct nlattr *nla;
	ssize_t n;
	size_t name_len = strlen(ifname) + 1; /* include NUL */
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + name_len);

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
				      NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST;
	req.nh.nlmsg_seq = 1;

	/* IFLA_IFNAME attribute */
	nla = (struct nlattr *)req.attrs;
	nla->nla_len = attr_len;
	nla->nla_type = IFLA_IFNAME;
	memcpy(req.attrs + NL_ATTR_HDRLEN, ifname, name_len);

	if (send(nlfd, &req, req.nh.nlmsg_len, 0) < 0)
		return -errno;

	do {
		n = recv(nlfd, resp, sizeof(resp), 0);
	} while (n < 0 && errno == EINTR);

	if (n < 0)
		return -errno;

	if ((size_t)n < sizeof(struct nlmsghdr))
		return -EBADMSG;

	nh = (struct nlmsghdr *)resp;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err;
		/*
		 * Guard against truncated NLMSG_ERROR (kernel buffer full,
		 * hostile NET_ADMIN peer, etc).  Without this we'd read
		 * past the recv'd bytes into the response buffer tail.
		 */
		if ((size_t)n < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
			return -EBADMSG;
		err = (struct nlmsgerr *)NLMSG_DATA(nh);
		return err->error;
	}

	if (nh->nlmsg_type != RTM_NEWLINK)
		return -EBADMSG;

	if ((size_t)n < NLMSG_LENGTH(sizeof(struct ifinfomsg)))
		return -EBADMSG;

	ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
	return ifi->ifi_index;
}

/*
 * nl_set_up - Set an interface UP by index.
 */
static int nl_set_up(int nlfd, int ifindex)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_type = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = 2;
	req.ifi.ifi_index = ifindex;
	req.ifi.ifi_flags = IFF_UP;
	req.ifi.ifi_change = IFF_UP;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/*
 * nl_add_addr - Add an IPv4 address to an interface.
 * @ip is in network byte order.
 */
static int nl_add_addr(int nlfd, int ifindex, uint32_t ip, uint8_t prefixlen)
{
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		char attrs[64];
	} req;
	size_t off;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + 4);

	memset(&req, 0, sizeof(req));
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_prefixlen = prefixlen;
	req.ifa.ifa_index = (uint32_t)ifindex;

	off = 0;

	/* IFA_LOCAL */
	nl_put_attr_hdr(req.attrs, off, attr_len, IFA_LOCAL);
	memcpy(req.attrs + off + NL_ATTR_HDRLEN, &ip, 4);
	off += NL_ATTR_ALIGN(attr_len);

	/* IFA_ADDRESS */
	nl_put_attr_hdr(req.attrs, off, attr_len, IFA_ADDRESS);
	memcpy(req.attrs + off + NL_ATTR_HDRLEN, &ip, 4);
	off += NL_ATTR_ALIGN(attr_len);

	req.nh.nlmsg_len =
	    (uint32_t)(NLMSG_LENGTH(sizeof(struct ifaddrmsg)) + off);
	req.nh.nlmsg_type = RTM_NEWADDR;
	req.nh.nlmsg_flags =
	    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.nh.nlmsg_seq = 3;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/*
 * nl_add_default_route - Add a default route (0.0.0.0/0) via gateway.
 * @gateway is in network byte order.
 */
static int nl_add_default_route(int nlfd, uint32_t gateway)
{
	struct {
		struct nlmsghdr nh;
		struct rtmsg rt;
		char attrs[32];
	} req;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + 4);

	memset(&req, 0, sizeof(req));
	req.rt.rtm_family = AF_INET;
	req.rt.rtm_dst_len = 0; /* default route */
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = RTPROT_BOOT;
	req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rt.rtm_type = RTN_UNICAST;

	/* RTA_GATEWAY */
	*(uint16_t *)(req.attrs + 0) = attr_len;
	*(uint16_t *)(req.attrs + 2) = RTA_GATEWAY;
	memcpy(req.attrs + NL_ATTR_HDRLEN, &gateway, 4);

	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct rtmsg)) +
				      NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_NEWROUTE;
	req.nh.nlmsg_flags =
	    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.nh.nlmsg_seq = 4;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/*
 * nl_delete_link - Delete an interface by name (ignores ENODEV).
 */
static int nl_delete_link(int nlfd, const char *ifname)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req;
	size_t name_len = strlen(ifname) + 1;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + name_len);
	int ret;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
				      NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_DELLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = 1;

	/* IFLA_IFNAME */
	*(uint16_t *)(req.attrs + 0) = attr_len;
	*(uint16_t *)(req.attrs + 2) = IFLA_IFNAME;
	memcpy(req.attrs + NL_ATTR_HDRLEN, ifname, name_len);

	ret = nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
	if (ret == -ENODEV)
		return 0; /* Already gone — not an error */
	return ret;
}

/*
 * nl_create_veth - Create a veth pair.
 * @host_name:	Name of the host-side interface
 * @peer_name:	Name of the peer-side interface
 *
 * Equivalent to: ip link add $host type veth peer name $peer
 *
 * The nested attribute layout is:
 *   IFLA_IFNAME(host)
 *   IFLA_LINKINFO {
 *     IFLA_INFO_KIND("veth")
 *     IFLA_INFO_DATA {
 *       VETH_INFO_PEER {
 *         struct ifinfomsg (zeroed)
 *         IFLA_IFNAME(peer)
 *       }
 *     }
 *   }
 */
static int nl_create_veth(int nlfd, const char *host_name,
			  const char *peer_name)
{
	/*
	 * Build the message bottom-up: compute sizes first, then
	 * fill the buffer in one pass. All NLA lengths include the
	 * 4-byte header and value, padded to 4-byte boundary.
	 */
	uint8_t buf[512];
	size_t off = 0;
	struct nlmsghdr *nh;
	size_t host_len = strlen(host_name) + 1;
	size_t peer_len = strlen(peer_name) + 1;

	/* -- Compute nested sizes (inner → outer) -- */

	/* IFLA_IFNAME(peer) inside VETH_INFO_PEER */
	size_t peer_ifname_sz = NL_ATTR_ALIGN(NL_ATTR_HDRLEN + peer_len);

	/* VETH_INFO_PEER = header + ifinfomsg + IFLA_IFNAME(peer) */
	size_t veth_peer_sz = NL_ATTR_ALIGN(
	    NL_ATTR_HDRLEN + sizeof(struct ifinfomsg) + peer_ifname_sz);

	/* IFLA_INFO_DATA = header + VETH_INFO_PEER */
	size_t info_data_sz = NL_ATTR_ALIGN(NL_ATTR_HDRLEN + veth_peer_sz);

	/* IFLA_INFO_KIND("veth") */
	size_t info_kind_sz = NL_ATTR_ALIGN(NL_ATTR_HDRLEN + 5); /* "veth\0" */

	/* IFLA_LINKINFO = header + KIND + DATA */
	size_t linkinfo_sz =
	    NL_ATTR_ALIGN(NL_ATTR_HDRLEN + info_kind_sz + info_data_sz);

	/* IFLA_IFNAME(host) */
	size_t host_ifname_sz = NL_ATTR_ALIGN(NL_ATTR_HDRLEN + host_len);

	/* Total attrs */
	size_t attrs_sz = host_ifname_sz + linkinfo_sz;
	size_t msg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)) + attrs_sz;

	if (msg_len > sizeof(buf))
		return -ENOMEM;

	memset(buf, 0, msg_len);

	/* -- nlmsghdr + ifinfomsg -- */
	nh = (struct nlmsghdr *)buf;
	nh->nlmsg_len = (uint32_t)msg_len;
	nh->nlmsg_type = RTM_NEWLINK;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nh->nlmsg_seq = 1;

	/* ifinfomsg is all zero — AF_UNSPEC, no index, no flags */

	off = NLMSG_LENGTH(sizeof(struct ifinfomsg));

	/* -- IFLA_IFNAME(host) -- */
	nl_put_attr_hdr(buf, off, (uint16_t)(NL_ATTR_HDRLEN + host_len),
			IFLA_IFNAME);
	memcpy(buf + off + NL_ATTR_HDRLEN, host_name, host_len);
	off += host_ifname_sz;

	/* -- IFLA_LINKINFO (NLA_F_NESTED) -- */
	nl_put_attr_hdr(
	    buf, off, (uint16_t)(NL_ATTR_HDRLEN + info_kind_sz + info_data_sz),
	    IFLA_LINKINFO | NLA_F_NESTED);
	off += NL_ATTR_HDRLEN;

	/* IFLA_INFO_KIND("veth") */
	nl_put_attr_hdr(buf, off, (uint16_t)(NL_ATTR_HDRLEN + 5),
			IFLA_INFO_KIND);
	memcpy(buf + off + NL_ATTR_HDRLEN, "veth", 5);
	off += info_kind_sz;

	/* IFLA_INFO_DATA (NLA_F_NESTED) */
	nl_put_attr_hdr(buf, off, (uint16_t)(NL_ATTR_HDRLEN + veth_peer_sz),
			IFLA_INFO_DATA | NLA_F_NESTED);
	off += NL_ATTR_HDRLEN;

	/* VETH_INFO_PEER (NLA_F_NESTED) */
	nl_put_attr_hdr(buf, off,
			(uint16_t)(NL_ATTR_HDRLEN + sizeof(struct ifinfomsg) +
				   peer_ifname_sz),
			1 | NLA_F_NESTED); /* VETH_INFO_PEER=1 */
	off += NL_ATTR_HDRLEN;

	/* Embedded ifinfomsg (zeroed — already memset) */
	off += sizeof(struct ifinfomsg);

	/* IFLA_IFNAME(peer) */
	nl_put_attr_hdr(buf, off, (uint16_t)(NL_ATTR_HDRLEN + peer_len),
			IFLA_IFNAME);
	memcpy(buf + off + NL_ATTR_HDRLEN, peer_name, peer_len);

	return nl_send_recv_ack(nlfd, buf, msg_len);
}

/*
 * nl_set_netns_by_pid - Move an interface into another net namespace.
 * Equivalent to: ip link set $ifname netns $pid
 */
static int nl_set_netns_by_pid(int nlfd, int ifindex, pid_t pid)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
		char attrs[16];
	} req;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + 4);

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
				      NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = 2;
	req.ifi.ifi_index = ifindex;

	/* IFLA_NET_NS_PID */
	*(uint16_t *)(req.attrs + 0) = attr_len;
	*(uint16_t *)(req.attrs + 2) = IFLA_NET_NS_PID;
	*(uint32_t *)(req.attrs + NL_ATTR_HDRLEN) = (uint32_t)pid;

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/*
 * nl_rename_link - Rename an interface by index.
 * Equivalent to: ip link set $ifindex name $newname
 */
static int nl_rename_link(int nlfd, int ifindex, const char *newname)
{
	struct {
		struct nlmsghdr nh;
		struct ifinfomsg ifi;
		char attrs[64];
	} req;
	size_t name_len = strlen(newname) + 1;
	uint16_t attr_len = (uint16_t)(NL_ATTR_HDRLEN + name_len);

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct ifinfomsg)) +
				      NL_ATTR_ALIGN(attr_len));
	req.nh.nlmsg_type = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_seq = 1;
	req.ifi.ifi_index = ifindex;

	/* IFLA_IFNAME */
	*(uint16_t *)(req.attrs + 0) = attr_len;
	*(uint16_t *)(req.attrs + 2) = IFLA_IFNAME;
	memcpy(req.attrs + NL_ATTR_HDRLEN, newname, name_len);

	return nl_send_recv_ack(nlfd, &req, req.nh.nlmsg_len);
}

/* -- Public API --------------------------------------------------- */

/*
 * erlkoenig_netcfg_veth_create - Create a veth pair and move peer to container.
 * @child_pid:	PID of the container process (host pidns)
 * @host_ifname: Name of the host-side veth (e.g. "vek12345")
 * @peer_ifname: Desired name inside container (e.g. "eth0")
 * @host_ip:	Host-side IPv4 address in host byte order
 * @prefixlen:	Subnet prefix length (e.g. 24)
 *
 * Creates the veth pair, moves the peer into the container's netns,
 * renames it, configures the host side (IP + UP + rp_filter=0).
 * All operations use netlink — no shell commands.
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_netcfg_veth_create(pid_t child_pid, const char *host_ifname,
				 const char *peer_ifname, uint32_t host_ip,
				 uint8_t prefixlen)
{
	char tmp_peer[IF_NAMESIZE];
	char sysctl_path[128];
	int nlfd = -1;
	int child_nlfd = -1;
	int orig_ns = -1;
	int child_ns = -1;
	int peer_idx;
	int sysctl_fd;
	int ret;

	snprintf(tmp_peer, sizeof(tmp_peer), "vp%d", (int)child_pid);

	/* Open netlink socket in host netns */
	nlfd = nl_open();
	if (nlfd < 0) {
		ret = -errno;
		LOG_SYSCALL("nl_open(host)");
		goto out;
	}

	/* Delete stale veth if present */
	ret = nl_delete_link(nlfd, host_ifname);
	if (ret) {
		LOG_ERR("netcfg: delete_link(%s) failed: %s", host_ifname,
			strerror(-ret));
		goto out;
	}

	/* Create veth pair */
	ret = nl_create_veth(nlfd, host_ifname, tmp_peer);
	if (ret) {
		LOG_ERR("netcfg: create_veth(%s, %s) failed: %s", host_ifname,
			tmp_peer, strerror(-ret));
		goto out;
	}

	/* Get peer ifindex (in host netns, before move) */
	peer_idx = nl_get_ifindex(nlfd, tmp_peer);
	if (peer_idx < 0) {
		ret = peer_idx;
		LOG_ERR("netcfg: get_ifindex(%s) failed: %s", tmp_peer,
			strerror(-ret));
		goto out_del;
	}

	/* Move peer into container's network namespace */
	ret = nl_set_netns_by_pid(nlfd, peer_idx, child_pid);
	if (ret) {
		LOG_ERR("netcfg: set_netns(%s, pid=%d) failed: %s", tmp_peer,
			(int)child_pid, strerror(-ret));
		goto out_del;
	}

	/* Rename peer inside container netns */
	orig_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (orig_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(/proc/self/ns/net)");
		goto out_del;
	}

	{
		char ns_path[64];

		snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/net",
			 (int)child_pid);
		child_ns = open(ns_path, O_RDONLY | O_CLOEXEC);
	}
	if (child_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(child netns)");
		goto out_del;
	}

	if (setns(child_ns, CLONE_NEWNET)) {
		ret = -errno;
		LOG_SYSCALL("setns(child)");
		goto out_del;
	}

	child_nlfd = nl_open();
	if (child_nlfd < 0) {
		ret = -errno;
		LOG_SYSCALL("nl_open(child)");
		goto out_restore;
	}

	/* Rename tmp_peer → peer_ifname (e.g. "eth0") */
	peer_idx = nl_get_ifindex(child_nlfd, tmp_peer);
	if (peer_idx < 0) {
		ret = peer_idx;
		LOG_ERR("netcfg: get_ifindex(%s) in child failed: %s", tmp_peer,
			strerror(-ret));
		goto out_restore;
	}

	ret = nl_rename_link(child_nlfd, peer_idx, peer_ifname);
	if (ret) {
		LOG_ERR("netcfg: rename(%s → %s) failed: %s", tmp_peer,
			peer_ifname, strerror(-ret));
		goto out_restore;
	}

	if (child_nlfd >= 0)
		close(child_nlfd);
	child_nlfd = -1;

	/* Restore host netns — hard-fail: runtime stuck in child netns
	 * cannot reliably operate on host interfaces, AND seccomp denies
	 * unshare so we cannot even escape via new-ns creation. */
	if (setns(orig_ns, CLONE_NEWNET)) {
		LOG_ERR("FATAL: setns(restore after rename) failed: %s — "
			"exiting rather than serving from wrong netns",
			strerror(errno));
		_exit(1);
	}

	/* Configure host side: add IP, set UP */
	{
		uint32_t ip_nbo = htonl(host_ip);
		int host_idx = nl_get_ifindex(nlfd, host_ifname);

		if (host_idx < 0) {
			ret = host_idx;
			LOG_ERR("netcfg: get_ifindex(%s) failed: %s",
				host_ifname, strerror(-ret));
			goto out_del;
		}

		ret = nl_add_addr(nlfd, host_idx, ip_nbo, prefixlen);
		if (ret && ret != -EEXIST) {
			LOG_ERR("netcfg: add_addr(%s) failed: %s", host_ifname,
				strerror(-ret));
			goto out_del;
		}

		ret = nl_set_up(nlfd, host_idx);
		if (ret) {
			LOG_ERR("netcfg: set_up(%s) failed: %s", host_ifname,
				strerror(-ret));
			goto out_del;
		}
	}

	/* Disable rp_filter via /proc (no netlink equivalent) */
	snprintf(sysctl_path, sizeof(sysctl_path),
		 "/proc/sys/net/ipv4/conf/%s/rp_filter", host_ifname);
	sysctl_fd = open(sysctl_path, O_WRONLY);
	if (sysctl_fd >= 0) {
		(void)write(sysctl_fd, "0\n", 2);
		close(sysctl_fd);
	}

	LOG_INFO("netcfg: veth %s created, peer %s in pid=%d netns",
		 host_ifname, peer_ifname, (int)child_pid);
	ret = 0;
	goto out;

out_restore:
	if (setns(orig_ns, CLONE_NEWNET)) {
		LOG_ERR("FATAL: setns(restore) failed: %s — exiting",
			strerror(errno));
		_exit(1);
	}

out_del:
	if (ret)
		nl_delete_link(nlfd, host_ifname);

out:
	if (child_nlfd >= 0)
		close(child_nlfd);
	if (child_ns >= 0)
		close(child_ns);
	if (orig_ns >= 0)
		close(orig_ns);
	if (nlfd >= 0)
		close(nlfd);

	return ret;
}

/*
 * erlkoenig_netcfg_veth_destroy - Destroy a veth pair by host interface name.
 * Deleting the host side automatically destroys the peer.
 *
 * Returns 0 on success (or if already gone), negative errno on failure.
 */
int erlkoenig_netcfg_veth_destroy(const char *host_ifname)
{
	int nlfd;
	int ret;

	nlfd = nl_open();
	if (nlfd < 0) {
		ret = -errno;
		LOG_SYSCALL("nl_open");
		return ret;
	}

	ret = nl_delete_link(nlfd, host_ifname);
	if (ret)
		LOG_ERR("netcfg: delete_link(%s) failed: %s", host_ifname,
			strerror(-ret));

	close(nlfd);
	return ret;
}

/* -- In-container network setup ----------------------------------- */

int erlkoenig_netcfg_setup(pid_t child_pid, const char *ifname, uint32_t ip,
			   uint8_t prefixlen, uint32_t gateway)
{
	/* Convert host byte order → network byte order for netlink */
	ip = htonl(ip);
	gateway = htonl(gateway);
	char ns_path[64];
	int orig_ns = -1;
	int child_ns = -1;
	int nlfd = -1;
	int ifindex;
	int lo_idx;
	int ret;

	/* Save our current network namespace */
	orig_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (orig_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(/proc/self/ns/net)");
		goto out;
	}

	/* Open the child's network namespace */
	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/net", (int)child_pid);
	child_ns = open(ns_path, O_RDONLY | O_CLOEXEC);
	if (child_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(child netns)");
		goto out;
	}

	/* Enter child's network namespace */
	if (setns(child_ns, CLONE_NEWNET)) {
		ret = -errno;
		LOG_SYSCALL("setns(child)");
		goto out;
	}

	/* Open netlink socket (now inside child's netns) */
	nlfd = nl_open();
	if (nlfd < 0) {
		ret = -errno;
		LOG_SYSCALL("nl_open");
		goto out_restore;
	}

	/* Get interface index */
	ifindex = nl_get_ifindex(nlfd, ifname);
	if (ifindex < 0) {
		ret = ifindex;
		LOG_ERR("netcfg: interface '%s' not found: %s", ifname,
			strerror(-ret));
		goto out_restore;
	}

	/* Add IP address */
	ret = nl_add_addr(nlfd, ifindex, ip, prefixlen);
	if (ret) {
		LOG_ERR("netcfg: add_addr failed: %s", strerror(-ret));
		goto out_restore;
	}

	/* Set interface UP */
	ret = nl_set_up(nlfd, ifindex);
	if (ret) {
		LOG_ERR("netcfg: set_up(%s) failed: %s", ifname,
			strerror(-ret));
		goto out_restore;
	}

	/* Set loopback UP */
	lo_idx = nl_get_ifindex(nlfd, "lo");
	if (lo_idx > 0) {
		ret = nl_set_up(nlfd, lo_idx);
		if (ret) {
			LOG_ERR("netcfg: set_up(lo) failed: %s",
				strerror(-ret));
			goto out_restore;
		}
	}

	/* Add default route via gateway (skip if gateway=0, e.g. IPVLAN L3S) */
	if (gateway != 0) {
		ret = nl_add_default_route(nlfd, gateway);
		if (ret) {
			LOG_ERR("netcfg: add_default_route failed: %s",
				strerror(-ret));
			goto out_restore;
		}
	}

	LOG_INFO("netcfg: configured %s ifindex=%d in pid=%d netns", ifname,
		 ifindex, (int)child_pid);
	ret = 0;

out_restore:
	/* Restore original network namespace */
	if (setns(orig_ns, CLONE_NEWNET)) {
		LOG_ERR("FATAL: setns(restore) failed: %s — exiting",
			strerror(errno));
		_exit(1);
	}

out:
	if (nlfd >= 0)
		close(nlfd);
	if (child_ns >= 0)
		close(child_ns);
	if (orig_ns >= 0)
		close(orig_ns);

	return ret;
}

/*
 * Synchronous slave teardown — see header for rationale.
 */
int erlkoenig_netcfg_teardown_slave(int netns_fd, const char *ifname)
{
	int orig_ns = -1;
	int nlfd = -1;
	int ret = 0;

	if (netns_fd < 0 || ifname == NULL || ifname[0] == '\0')
		return -EINVAL;

	orig_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (orig_ns < 0) {
		ret = -errno;
		LOG_SYSCALL("open(/proc/self/ns/net)");
		goto out;
	}

	if (setns(netns_fd, CLONE_NEWNET)) {
		ret = -errno;
		LOG_SYSCALL("setns(child_netns for teardown)");
		goto out;
	}

	nlfd = nl_open();
	if (nlfd < 0) {
		ret = -errno;
		LOG_SYSCALL("nl_open (teardown)");
		goto out_restore;
	}

	/* nl_delete_link already returns 0 on ENODEV (already-gone) */
	ret = nl_delete_link(nlfd, ifname);
	if (ret && ret != -ENODEV)
		LOG_ERR("netcfg: teardown slave %s failed: %s", ifname,
			strerror(-ret));

out_restore:
	if (setns(orig_ns, CLONE_NEWNET)) {
		LOG_ERR("FATAL: setns(restore after teardown) failed: %s "
			"— exiting rather than serving from wrong netns",
			strerror(errno));
		_exit(1);
	}

out:
	if (nlfd >= 0)
		close(nlfd);
	if (orig_ns >= 0)
		close(orig_ns);
	return ret;
}
