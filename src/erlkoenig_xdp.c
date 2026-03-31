/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * erlkoenig_xdp.c — XDP packet steering for container networking.
 *
 * Loads an XDP program onto a host network interface that steers
 * incoming packets to container veth interfaces via BPF hash map
 * lookup + bpf_redirect(). Bypasses the kernel routing/netfilter
 * stack entirely.
 *
 * API:
 *   ek_xdp_init(ifname)              → create map, load prog, attach
 *   ek_xdp_add_route(ip, ifindex)    → map_update
 *   ek_xdp_del_route(ip)             → map_delete
 *   ek_xdp_cleanup()                 → detach + close fds
 *
 * The BPF program is defined in erlkoenig_xdp.h as a struct bpf_insn
 * array (same technique as the seccomp filters in erlkoenig_seccomp.h).
 * The map FD is patched into the instruction array before loading.
 */

#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include "erlkoenig_log.h"
#include "erlkoenig_xdp.h"
#include "erlkoenig_xdp_api.h"

/* NLA_HDRLEN is (int) — cast to size_t for arithmetic */
#define NLA_HDR ((size_t)NLA_HDRLEN)

/*
 * Global XDP state. One XDP program per runtime instance,
 * shared across all containers.
 */
struct ek_xdp_state {
	int map_fd;  /* BPF hash map fd (-1 if not initialized) */
	int prog_fd; /* BPF program fd (-1 if not loaded) */
	int link_fd; /* BPF link fd (-1 if not attached) — MUST stay open */
	int ifindex; /* Host interface index (0 if not attached) */
	char ifname[IF_NAMESIZE];
};

static struct ek_xdp_state g_xdp = {
    .map_fd = -1,
    .prog_fd = -1,
    .link_fd = -1,
    .ifindex = 0,
};

/* --- bpf() syscall wrapper --- */

static inline int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(SYS_bpf, cmd, attr, size);
}

/*
 * ek_bpf_create_map — Create a BPF hash map.
 *
 * key_size/value_size in bytes, max_entries = capacity.
 * Returns map fd on success, -errno on failure.
 */
static int ek_bpf_create_map(uint32_t key_size, uint32_t value_size,
			     uint32_t max_entries)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	int fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

	if (fd < 0) {
		LOG_ERR("bpf(MAP_CREATE): %s", strerror(errno));
		return -errno;
	}
	return fd;
}

/*
 * ek_bpf_load_xdp — Load an XDP program from an instruction array.
 *
 * Patches the map FD into the instruction array before loading.
 * Returns program fd on success, -errno on failure.
 */
static int ek_bpf_load_xdp(struct bpf_insn *insns, size_t insn_count,
			   int route_fd, int svc_fd, int backend_fd)
{
	union bpf_attr attr;
	char log_buf[4096];

	/*
	 * Patch all three map FDs into LD_MAP_FD instructions.
	 * The XDP program has three map lookups:
	 *   1. service_map  (L4 DSR — empty in runtime, used by ek_ebpfd)
	 *   2. backend_map  (L4 DSR — empty in runtime, used by ek_ebpfd)
	 *   3. route_map    (L3 steering — the map this runtime manages)
	 */
	insns[XDP_SVC_MAP_FD_IDX].imm = svc_fd;
	insns[XDP_BACKEND_MAP_FD_IDX].imm = backend_fd;
	insns[XDP_ROUTE_MAP_FD_IDX].imm = route_fd;

	/* Runtime check: route map index points to LD_MAP_FD instruction */
	if (insns[XDP_ROUTE_MAP_FD_IDX].src_reg != 1) {
		LOG_ERR(
		    "xdp: ROUTE_MAP_FD_IDX %d is not a LD_MAP_FD instruction",
		    XDP_ROUTE_MAP_FD_IDX);
		return -EINVAL;
	}

	/* Try loading without verifier log first (saves kernel memory) */
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt = (uint32_t)insn_count;
	attr.insns = (uint64_t)(uintptr_t)insns;
	attr.license = (uint64_t)(uintptr_t) "GPL";

	int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

	if (fd >= 0)
		return fd;

	/* Retry with verifier log for diagnostics */
	attr.log_level = 1;
	attr.log_size = sizeof(log_buf);
	attr.log_buf = (uint64_t)(uintptr_t)log_buf;
	log_buf[0] = '\0';

	fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

	if (fd < 0) {
		LOG_ERR("bpf(PROG_LOAD): %s", strerror(errno));
		if (log_buf[0] != '\0')
			LOG_ERR("verifier: %s", log_buf);
		return -errno;
	}
	return fd;
}

/*
 * Netlink NLA/NLMSG macros use int arithmetic internally, triggering
 * -Wsign-conversion with our strict warnings. Suppress for the netlink
 * functions — the values are always small positive sizes.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

/*
 * ek_xdp_attach — Attach an XDP program to a network interface.
 *
 * Uses netlink (RTM_SETLINK + IFLA_XDP) to attach the program.
 * Tries native driver mode first (XDP_FLAGS_DRV_MODE), falls back
 * to generic/SKB mode (XDP_FLAGS_SKB_MODE) if the driver doesn't
 * support native XDP.
 *
 * Returns 0 on success, -errno on failure.
 */

static int ek_xdp_attach(int ifindex, int prog_fd, uint32_t flags)
{
	union bpf_attr attr;

	(void)flags;

	/*
	 * BPF_LINK_CREATE (Linux 5.7+) — attach XDP program to interface.
	 * Simpler than netlink IFLA_XDP and doesn't require NLA encoding.
	 */
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.target_ifindex = (uint32_t)ifindex;
	/* BPF_XDP = 37 in enum bpf_attach_type */
#ifndef BPF_XDP
#define BPF_XDP 37
#endif
	attr.link_create.attach_type = BPF_XDP;

	int link_fd = sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr));

	if (link_fd >= 0) {
		/* MUST keep link_fd open — closing it detaches the program */
		g_xdp.link_fd = link_fd;
		return 0;
	}
	LOG_ERR("xdp: BPF_LINK_CREATE failed: %s, trying pinned fallback",
		strerror(errno));

	/*
	 * Fallback: pin the BPF program and use ip(8) to attach it.
	 * This handles generic/SKB mode and older kernels.
	 */
	char if_str[IF_NAMESIZE];

	if (!if_indextoname((unsigned int)ifindex, if_str))
		return -errno;

	char pin_path[] = "/sys/fs/bpf/erlkoenig_xdp_tmp";

	memset(&attr, 0, sizeof(attr));
	attr.pathname = (uint64_t)(uintptr_t)pin_path;
	attr.bpf_fd = (uint32_t)prog_fd;
	if (sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) < 0) {
		LOG_ERR("xdp: BPF_OBJ_PIN failed: %s", strerror(errno));
		return -errno;
	}

	pid_t pid = fork();

	if (pid < 0) {
		unlink(pin_path);
		return -errno;
	}
	if (pid == 0) {
		execlp("ip", "ip", "link", "set", "dev", if_str, "xdpgeneric",
		       "pinned", pin_path, (char *)NULL);
		_exit(127);
	}

	int status;

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	unlink(pin_path);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;

	LOG_ERR("xdp: ip link set xdpgeneric failed (exit %d)",
		WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	return -EINVAL;
}

/*
 * ek_xdp_detach — Detach XDP program from interface.
 * Uses ip(8) for reliability — same approach as attach fallback.
 */
static int ek_xdp_detach(int ifindex)
{
	char if_str[IF_NAMESIZE];

	if (!if_indextoname((unsigned int)ifindex, if_str))
		return -errno;

	pid_t pid = fork();

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		/* Remove both native and generic XDP */
		execlp("ip", "ip", "link", "set", "dev", if_str, "xdpgeneric",
		       "off", "xdp", "off", (char *)NULL);
		_exit(127);
	}

	int status;

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return -EINVAL;
}

#pragma GCC diagnostic pop

/* --- Public API --- */

/*
 * ek_xdp_init — Initialize XDP steering on a host interface.
 *
 * Creates a BPF hash map (IP → ifindex), loads the XDP steering
 * program, and attaches it to the named interface.
 *
 * Returns 0 on success, -errno on failure.
 * On failure, no resources are leaked (all cleaned up).
 */
int ek_xdp_init(const char *ifname)
{
	int ret;

	if (g_xdp.map_fd >= 0) {
		LOG_ERR("xdp: already initialized");
		return -EALREADY;
	}

	/* Resolve interface name → index */
	unsigned int idx = if_nametoindex(ifname);

	if (idx == 0) {
		LOG_ERR("xdp: interface '%s' not found", ifname);
		return -ENODEV;
	}
	LOG_INFO("xdp: resolved %s → ifindex %u", ifname, idx);

	/* Create route map: u32 (IP) → u32 (ifindex) */
	int map_fd = ek_bpf_create_map(4, 4, 65536);

	if (map_fd < 0)
		return map_fd;
	LOG_INFO("xdp: created route_map (fd=%d)", map_fd);

	/*
	 * Create service_map and backend_map (empty, needed by the shared
	 * XDP program which also supports L4 DSR via ek_ebpfd).
	 */
	int svc_fd = ek_bpf_create_map(sizeof(struct xdp_svc_key),
				       sizeof(struct xdp_svc_val), 256);
	if (svc_fd < 0) {
		close(map_fd);
		return svc_fd;
	}
	int backend_fd = ek_bpf_create_map(sizeof(struct xdp_backend_key),
					   sizeof(struct xdp_backend_val), 256);
	if (backend_fd < 0) {
		close(svc_fd);
		close(map_fd);
		return backend_fd;
	}

	/* Copy the instruction template (don't modify the static array) */
	struct bpf_insn insns[XDP_STEERING_PROG_LEN];

	memcpy(insns, xdp_steering_prog, sizeof(insns));

	/* Load XDP program (patches all three map fds) */
	int prog_fd = ek_bpf_load_xdp(insns, XDP_STEERING_PROG_LEN, map_fd,
				      svc_fd, backend_fd);

	if (prog_fd < 0) {
		close(backend_fd);
		close(svc_fd);
		close(map_fd);
		return prog_fd;
	}
	LOG_INFO("xdp: loaded steering program (fd=%d, %zu insns)", prog_fd,
		 XDP_STEERING_PROG_LEN);

	/* Attach to interface — try native mode first */
	ret = ek_xdp_attach((int)idx, prog_fd, 0);
	if (ret < 0) {
		LOG_ERR("xdp: attach to %s failed: %s", ifname, strerror(-ret));
		close(prog_fd);
		close(map_fd);
		return ret;
	}

	/* Store state */
	g_xdp.map_fd = map_fd;
	g_xdp.prog_fd = prog_fd;
	g_xdp.ifindex = (int)idx;
	snprintf(g_xdp.ifname, sizeof(g_xdp.ifname), "%s", ifname);

	/* WARN level so it's visible without ERLKOENIG_LOG=info */
	LOG_WARN(
	    "xdp: steering active on %s (ifindex=%d, map_fd=%d, prog_fd=%d)",
	    ifname, (int)idx, map_fd, prog_fd);

	return 0;
}

/*
 * ek_xdp_add_route — Add a container IP → veth ifindex mapping.
 *
 * Called after veth setup during container spawn. The IP is in
 * network byte order (as stored in the packet), ifindex is the
 * host-side veth interface index.
 *
 * Returns 0 on success, -errno on failure.
 */
int ek_xdp_add_route(uint32_t ip_net_order, uint32_t ifindex)
{
	if (g_xdp.map_fd < 0)
		return 0; /* XDP not active, silently skip */

	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)g_xdp.map_fd;
	attr.key = (uint64_t)(uintptr_t)&ip_net_order;
	attr.value = (uint64_t)(uintptr_t)&ifindex;
	attr.flags = BPF_ANY; /* create or update */

	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
		LOG_ERR("xdp: map_update failed: %s", strerror(errno));
		return -errno;
	}

	uint8_t *ip = (uint8_t *)&ip_net_order;

	LOG_INFO("xdp: route added %u.%u.%u.%u → ifindex %u", ip[0], ip[1],
		 ip[2], ip[3], ifindex);

	return 0;
}

/*
 * ek_xdp_del_route — Remove a container IP mapping.
 *
 * Called during container kill, before veth deletion.
 * Returns 0 on success, -errno on failure. ENOENT is not an error.
 */
int ek_xdp_del_route(uint32_t ip_net_order)
{
	if (g_xdp.map_fd < 0)
		return 0;

	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)g_xdp.map_fd;
	attr.key = (uint64_t)(uintptr_t)&ip_net_order;

	if (sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)) < 0) {
		if (errno == ENOENT)
			return 0; /* already removed, not an error */
		LOG_ERR("xdp: map_delete failed: %s", strerror(errno));
		return -errno;
	}

	uint8_t *ip = (uint8_t *)&ip_net_order;

	LOG_INFO("xdp: route removed %u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

	return 0;
}

/*
 * ek_xdp_is_active — Check if XDP steering is initialized.
 */
int ek_xdp_is_active(void)
{
	return g_xdp.map_fd >= 0;
}

/*
 * ek_xdp_cleanup — Detach XDP program and close all fds.
 *
 * Called at runtime shutdown. Safe to call even if not initialized.
 */
void ek_xdp_cleanup(void)
{
	/* Close link fd first — this detaches the XDP program */
	if (g_xdp.link_fd >= 0) {
		close(g_xdp.link_fd);
		g_xdp.link_fd = -1;
		LOG_INFO("xdp: detached from %s", g_xdp.ifname);
	} else if (g_xdp.ifindex > 0) {
		/* Fallback detach (ip(8) attach path) */
		int ret = ek_xdp_detach(g_xdp.ifindex);
		if (ret < 0)
			LOG_WARN("xdp: detach from %s: %s", g_xdp.ifname,
				 strerror(-ret));
		else
			LOG_INFO("xdp: detached from %s", g_xdp.ifname);
	}
	g_xdp.ifindex = 0;
	if (g_xdp.prog_fd >= 0) {
		close(g_xdp.prog_fd);
		g_xdp.prog_fd = -1;
	}
	if (g_xdp.map_fd >= 0) {
		close(g_xdp.map_fd);
		g_xdp.map_fd = -1;
	}
}
