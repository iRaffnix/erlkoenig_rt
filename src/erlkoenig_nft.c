/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * erlkoenig_nft.c - Per-container nftables via setns().
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "erlkoenig_nft.h"
#include "erlkoenig_log.h"

#define EK_NETLINK_NETFILTER 12

/*
 * nft_drain_acks - Drain all ACKs from a nftables batch.
 */
static int nft_drain_acks(int nlfd)
{
	uint8_t buf[4096];
	int first_err = 0;
	int done = 0;

	while (!done) {
		ssize_t n = recv(nlfd, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			return -(int)errno;
		}
		if (n == 0)
			break;

		/* Parse netlink messages */
		size_t off = 0;
		while (off + 16 <= (size_t)n) {
			uint32_t msg_len;
			uint16_t msg_type;
			memcpy(&msg_len, buf + off, 4);
			memcpy(&msg_type, buf + off + 4, 2);

			if (msg_len < 16 || off + msg_len > (size_t)n)
				break;

			if (msg_type == NLMSG_DONE) {
				done = 1;
				break;
			}

			if (msg_type == NLMSG_ERROR && msg_len >= 20) {
				int32_t err;
				memcpy(&err, buf + off + 16, 4);
				if (err != 0 && first_err == 0) {
					first_err = (int)err;
					LOG_ERR("nft: batch ACK error: %s",
						strerror(-err));
				}
			}

			off += ((msg_len + 3U) & ~3U);
		}
	}

	return first_err;
}

int erlkoenig_nft_apply(pid_t child_pid, const uint8_t *batch, size_t batch_len)
{
	char ns_path[64];
	int orig_ns = -1;
	int child_ns = -1;
	int nlfd = -1;
	int ret = 0;
	struct sockaddr_nl addr;
	struct timeval tv;
	ssize_t sent;

	if (!batch || batch_len == 0)
		return -EINVAL;

	/* Save original netns */
	orig_ns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (orig_ns < 0) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: open(/proc/self/ns/net)");
		goto out;
	}

	/* Open child netns */
	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/net", (int)child_pid);
	child_ns = open(ns_path, O_RDONLY | O_CLOEXEC);
	if (child_ns < 0) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: open(child netns)");
		goto out;
	}

	/* Enter child's network namespace */
	if (setns(child_ns, CLONE_NEWNET)) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: setns(child)");
		goto out;
	}

	/* Open NETLINK_NETFILTER socket (now inside child's netns) */
	nlfd =
	    socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, EK_NETLINK_NETFILTER);
	if (nlfd < 0) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: socket(NETLINK_NETFILTER)");
		goto out_restore;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	if (bind(nlfd, (struct sockaddr *)&addr, sizeof(addr))) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: bind");
		goto out_restore;
	}

	/* Set recv timeout to avoid hanging on missing ACKs */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if (setsockopt(nlfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: setsockopt(SO_RCVTIMEO)");
		goto out_restore;
	}

	/* Send the pre-built batch (atomic nft transaction) */
	sent = sendto(nlfd, batch, batch_len, 0, (struct sockaddr *)&addr,
		      sizeof(addr));
	if (sent < 0) {
		ret = -(int)errno;
		LOG_SYSCALL("nft: sendto");
		goto out_restore;
	}
	if ((size_t)sent != batch_len) {
		ret = -EIO;
		LOG_ERR("nft: short send: %zd/%zu", sent, batch_len);
		goto out_restore;
	}

	/* Drain ACKs */
	ret = nft_drain_acks(nlfd);
	if (ret == 0) {
		LOG_INFO("nft: applied %zu byte batch in pid=%d netns",
			 batch_len, (int)child_pid);
	}

out_restore:
	if (setns(orig_ns, CLONE_NEWNET))
		LOG_SYSCALL("nft: setns(restore) CRITICAL");
out:
	if (nlfd >= 0)
		close(nlfd);
	if (child_ns >= 0)
		close(child_ns);
	if (orig_ns >= 0)
		close(orig_ns);
	return ret;
}

int erlkoenig_nft_list(pid_t child_pid, uint8_t *out, size_t out_len,
		       size_t *used)
{
	(void)child_pid;
	(void)out;
	(void)out_len;
	if (used)
		*used = 0;
	return -ENOSYS;
}
