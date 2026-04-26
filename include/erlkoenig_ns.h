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
 * erlkoenig_ns.h - Container namespace setup.
 *
 * Creates a child process in isolated USER/PID/NET/MNT/UTS/IPC/CGROUP
 * namespaces. uid_map/gid_map are written by the C runtime after
 * clone(). The child prepares the rootfs and waits for GO after
 * network setup. Supports pipe mode and PTY mode for I/O.
 */

#ifndef ERLKOENIG_NS_H
#define ERLKOENIG_NS_H

#include <sys/types.h>
#include <stdint.h>

/*
 * MAX_PATH must leave room for the longest subpath we append
 * (e.g. "/dev/urandom" = 12 chars). Keep rootfs paths short.
 */
#define ERLKOENIG_MAX_PATH	 4096
#define ERLKOENIG_ROOTFS_MAX	 256
#define ERLKOENIG_MAX_ARGS	 64
#define ERLKOENIG_MAX_ENV	 128
#define ERLKOENIG_NETNS_PATH_LEN 64

#define ERLKOENIG_MAX_VOLUMES	 16
#define ERLKOENIG_MAX_MOUNT_DATA 256 /* fs-specific passthrough data */

/*
 * Legacy semantic bit — still honoured so a `read_only:` boolean
 * coming from old DSL code keeps working. New code uses `flags`
 * directly (MS_RDONLY).
 */
#define EK_VOLUME_F_READONLY (1u << 0)

/*
 * struct erlkoenig_volume - Bind-mount specification.
 *
 * @source:	 Host directory (absolute path).
 * @dest:	 Container directory (absolute path).
 * @flags:	 MS_* bits to SET on the mount (e.g. MS_RDONLY, MS_NOSUID).
 * @clear:	 MS_* bits to CLEAR (relevant for MS_REMOUNT scenarios).
 * @propagation: One of EK_PROP_* (0 = inherit, don't set propagation).
 * @recursive:	 Non-zero → apply propagation recursively (MS_REC).
 * @data:	 fs-specific passthrough string (e.g. tmpfs size=64m).
 *		 NUL-terminated, empty if unused.
 *
 * The legacy `opts` u32 bit field has been subsumed by `flags`
 * directly — the wire-format decoder translates EK_VOLUME_F_READONLY
 * into MS_RDONLY at decode time.
 */
struct erlkoenig_volume {
	char source[ERLKOENIG_MAX_PATH];
	char dest[ERLKOENIG_MAX_PATH];
	uint32_t flags;
	uint32_t clear;
	uint8_t propagation;
	uint8_t recursive;
	char data[ERLKOENIG_MAX_MOUNT_DATA];
};

/*
 * struct erlkoenig_spawn_opts - Parameters for container creation.
 * @binary_path:	Absolute path to statically linked binary
 * @argv:		NULL-terminated argument vector for execve
 * @argc:		Number of arguments (not counting NULL)
 * @envp:		NULL-terminated environment ("KEY=VALUE")
 * @envc:		Number of environment entries
 * @strbuf:		Flat storage for arg/env string data
 * @strbuf_used:	Bytes used in strbuf
 * @uid:		UID to run as inside the container
 * @gid:		GID to run as inside the container
 * @seccomp_profile:	Seccomp profile index (0 = none)
 * @rootfs_size_mb:	Rootfs tmpfs size in MB (0 = default 64 MB)
 * @caps_keep:		Bitmask of capabilities to keep (bit N = CAP_N)
 *			0 = drop all capabilities (secure default)
 * @dns_ip:		DNS server IP for /etc/resolv.conf (network byte order)
 *			0 = use default (10.0.0.1)
 * @flags:		Spawn flags (bit 0 = ERLKOENIG_SPAWN_FLAG_PTY)
 */
struct erlkoenig_spawn_opts {
	char binary_path[ERLKOENIG_MAX_PATH];
	char *argv[ERLKOENIG_MAX_ARGS + 2]; /* +2: argv[0] + NULL */
	int argc;
	char *envp[ERLKOENIG_MAX_ENV + 1]; /* +1: NULL */
	int envc;
	char strbuf[8192];
	size_t strbuf_used;
	uint32_t uid;
	uint32_t gid;
	uint8_t seccomp_profile;
	uint32_t rootfs_size_mb;
	uint64_t caps_keep;
	uint32_t dns_ip;
	uint32_t flags;
	struct erlkoenig_volume volumes[ERLKOENIG_MAX_VOLUMES];
	uint8_t num_volumes;
	/* cgroup limits (0 = no limit / no cgroup) */
	uint64_t memory_max;
	uint32_t pids_max;
	uint32_t cpu_weight;
	char image_path[ERLKOENIG_MAX_PATH]; /* EROFS image, empty = tmpfs mode
					      */
};

/*
 * struct erlkoenig_container - State of a running container.
 * @child_pid:		PID in the host PID namespace (for /proc paths +
 * logging)
 * @child_pidfd:	pidfd for the child (-1 if unavailable, kernel < 5.3)
 * @go_pipe:		Write-end of GO pipe (-1 after GO sent)
 * @stdout_fd:		Read-end of child stdout pipe (-1 if closed)
 * @stderr_fd:		Read-end of child stderr pipe (-1 if closed)
 * @exec_err_fd:	Read-end of execve error pipe (-1 after exec ok)
 * @netns_path:		Path to network namespace (e.g. /proc/<pid>/ns/net)
 * @stdin_fd:		Write-end of child stdin pipe (-1 if not available)
 * @pty_master:		PTY master FD (-1 if pipe mode)
 */
struct erlkoenig_container {
	pid_t child_pid;
	int child_pidfd;
	int go_pipe;
	int stdout_fd;
	int stderr_fd;
	int exec_err_fd;
	int stdin_fd;
	int pty_master;
	char netns_path[ERLKOENIG_NETNS_PATH_LEN];
	char rootfs_path[ERLKOENIG_ROOTFS_MAX];
};

/*
 * erlkoenig_spawn - Clone a child into new namespaces.
 * @opts:	Spawn parameters
 * @ct:		Output: container state (filled on success)
 *
 * The child will block on a pipe waiting for GO. The caller must
 * eventually call erlkoenig_go() or erlkoenig_kill() on the container.
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_spawn(const struct erlkoenig_spawn_opts *opts,
		    struct erlkoenig_container *ct);

/*
 * erlkoenig_go - Signal the child to proceed with execve.
 * @ct:		Container state
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_go(struct erlkoenig_container *ct);

/*
 * erlkoenig_cleanup - Clean up container resources.
 * @ct:		Container state
 *
 * Closes remaining FDs. Does NOT kill the child.
 */
void erlkoenig_cleanup(struct erlkoenig_container *ct);

#endif /* ERLKOENIG_NS_H */
