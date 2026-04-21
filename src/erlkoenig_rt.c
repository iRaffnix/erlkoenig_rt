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
 * erlkoenig_rt.c - Erlkoenig container runtime.
 *
 * This is the privileged C component that creates and manages
 * containerised processes in isolated Linux namespaces. It
 * communicates with the Erlang control plane via the Erlkoenig
 * wire protocol ({packet, 4} framing).
 *
 * Two I/O modes are supported:
 *
 *   Port mode (legacy, default):
 *     Erlang starts this as an Erlang Port with {packet, 4}.
 *     stdin = commands from Erlang, stdout = replies to Erlang.
 *     Connection loss (pipe break) terminates the runtime.
 *
 *   Socket mode (--socket PATH):
 *     The runtime creates a Unix Domain Socket and listens for
 *     connections. The protocol is identical ({packet, 4}).
 *     Connection loss does NOT terminate the runtime — the child
 *     process survives and the runtime waits for a reconnect.
 *     This enables crash recovery: the BEAM can crash and restart,
 *     then reconnect to the still-running container.
 *
 * Architecture: One erlkoenig_rt process per container.
 *
 * Responsibilities:
 *   - Receive commands (SPAWN, GO, KILL, QUERY_STATUS)
 *   - Create child process in new namespaces (PID, NET, MNT, UTS)
 *   - Wait for child exit, report back to Erlang
 *   - Clean up resources on exit
 *
 * stderr = debug logging (not part of protocol)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include "erlkoenig_proto.h"
#include "erlkoenig_log.h"
#include "erlkoenig_cleanup.h"
#include "erlkoenig_ns.h"
#include "erlkoenig_netcfg.h"
#include "erlkoenig_devfilter.h"
#include "erlkoenig_metrics.h"
#include "erlkoenig_nodecert.h"
#include "erlkoenig_cg.h"
#include "erlkoenig_tlv.h"
#include "erlkoenig_nft.h"
#include "ek_protocol.h"
#include "erlkoenig_cloned.h"

#include "erlkoenig_xdp_api.h"
/* Seccomp BPF macros (from erlkoenig_seccomp.h, avoid pulling
 * in the full header which has static functions used by ns.c) */
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define ERLKOENIG_MAX_MSG (64 * 1024)

/* Event loop return codes */
#define LOOP_SHUTDOWN	0 /* Graceful shutdown requested */
#define LOOP_DISCONNECT 1 /* Connection lost (socket mode) */

/* Container state */
enum erlkoenig_state {
	STATE_IDLE = 0, /* No container yet */
	STATE_CREATED,	/* Child cloned, waiting for GO */
	STATE_RUNNING,	/* Child is executing */
	STATE_STOPPED,	/* Child has exited */
};

static struct {
	enum erlkoenig_state state;
	struct erlkoenig_container ct;
	int exit_code;
	int term_signal;
	uint64_t started_at;	       /* Monotonic clock (ms) */
	int stdout_open;	       /* 1 if stdout pipe still readable */
	int stderr_open;	       /* 1 if stderr pipe still readable */
	int pty_open;		       /* 1 if pty_master still readable */
	struct ek_metrics_ctx metrics; /* eBPF tracepoint metrics */
	int exit_pending;	   /* 1 if child exited while disconnected */
	char cgroup_path[4096];	   /* per-container cgroup path */
	uint32_t container_ip_net; /* Container IP (network byte order, for XDP
				      cleanup) */
	/*
	 * Synchronous IPVLAN-slave teardown state.  Populated at
	 * successful NET_SETUP and consumed by reap_child() BEFORE
	 * REPLY_EXITED is sent, so the kernel has freed the slave
	 * before Erlang sees the child exit and the pod-sup re-spawns
	 * a replacement on the same parent dummy.  Closes the EADDRINUSE
	 * race for :one_for_all / :rest_for_one pod strategies.
	 */
	int container_netns_fd;	           /* Open fd to container's netns */
	char container_ifname[IF_NAMESIZE]; /* Slave ifname inside that netns */
} g_state;

/*
 * pidfd helpers — use pidfd when available, fall back to PID.
 *
 * pidfd eliminates PID reuse races: after waitpid(), the PID is freed
 * and can be recycled by the kernel. With pidfd, kill/wait target the
 * specific process incarnation, not just a number.
 */

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static int ct_kill(int sig)
{
	if (g_state.ct.child_pidfd >= 0)
		return (int)syscall(SYS_pidfd_send_signal,
				    g_state.ct.child_pidfd, sig, NULL, 0);
	return kill(g_state.ct.child_pid, sig);
}

static pid_t ct_waitpid(int *status, int options)
{
	if (g_state.ct.child_pidfd >= 0) {
		siginfo_t info;

		memset(&info, 0, sizeof(info));
		int ret = waitid(P_PIDFD, (id_t)g_state.ct.child_pidfd, &info,
				 WEXITED | options);
		if (ret < 0)
			return -1;
		if (info.si_pid == 0 && (options & WNOHANG))
			return 0; /* no child exited yet */
		/*
		 * Convert siginfo_t to wait status for compatibility
		 * with existing WIFEXITED/WIFSIGNALED/WEXITSTATUS macros.
		 */
		if (status) {
			if (info.si_code == CLD_EXITED)
				*status = info.si_status << 8;
			else
				*status = info.si_status; /* signal */
		}
		return info.si_pid;
	}
	return waitpid(g_state.ct.child_pid, status, options);
}

/*
 * g_write_fd - The fd used for sending protocol replies.
 * In port mode: STDOUT_FILENO (set once at startup).
 * In socket mode: the accepted connection fd (changes on reconnect).
 */
static int g_write_fd = STDOUT_FILENO;

/*
 * g_read_fd - The fd used for reading protocol commands.
 * In port mode: STDIN_FILENO (set once at startup).
 * In socket mode: the accepted connection fd (same as g_write_fd).
 */
static int g_read_fd = STDIN_FILENO;

/*
 * g_connected - Whether we have an active Erlang connection.
 * In port mode: always 1 (connection loss = exit).
 * In socket mode: 0 when disconnected, 1 when connected.
 */
static int g_connected = 1;

/*
 * g_socket_mode - Whether we're running in socket mode.
 * 0 = port mode (legacy), 1 = socket mode.
 */
static int g_socket_mode;

/* Volatile flag set by SIGCHLD handler */
static volatile sig_atomic_t g_sigchld_received;

/* Volatile flag set by SIGTERM/SIGINT handler for graceful shutdown */
static volatile sig_atomic_t g_shutdown_requested;

/*
 * Original signal mask before we block SIGCHLD/SIGTERM/SIGINT.
 * Passed to ppoll() so signals are delivered atomically during wait,
 * eliminating the race between checking flags and entering poll.
 */
static sigset_t g_orig_sigmask;

/* -- Monotonic clock helper --------------------------------------- */

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* -- Reply helpers ------------------------------------------------ */

/*
 * send_raw - Write raw bytes as a {packet,4} frame.
 * Returns -1 if not connected or write fails.
 */
static int send_raw(const uint8_t *data, size_t len)
{
	if (!g_connected)
		return -1;
	return erlkoenig_write_frame(g_write_fd, data, len);
}

/*
 * All reply functions build TLV format:
 * <<Tag:8, Ver:8, [TLV Attributes...]>>
 */

static int send_reply_ok(const uint8_t *data, uint16_t data_len)
{
	uint8_t frame[512];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, frame, sizeof(frame));
	buf_write_u8(&b, ERLKOENIG_TAG_REPLY_OK);
	buf_write_u8(&b, 1); /* ver */
	if (data_len > 0 && data)
		ek_tlv_put(&b, EK_ATTR_DATA, data, data_len);

	return send_raw(frame, b.pos);
}

static int send_reply_error(int32_t code, const char *msg)
{
	uint8_t frame[512];
	struct erlkoenig_buf b;

	if (!msg)
		msg = "unknown error";

	erlkoenig_buf_init(&b, frame, sizeof(frame));
	buf_write_u8(&b, ERLKOENIG_TAG_REPLY_ERROR);
	buf_write_u8(&b, 1);
	ek_tlv_put_i32(&b, EK_ATTR_CODE, code);
	ek_tlv_put_str(&b, EK_ATTR_MESSAGE, msg);

	return send_raw(frame, b.pos);
}

static int send_reply_container_pid(uint32_t pid, const char *netns_path)
{
	uint8_t frame[512];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, frame, sizeof(frame));
	buf_write_u8(&b, ERLKOENIG_TAG_REPLY_CONTAINER_PID);
	buf_write_u8(&b, 1);
	ek_tlv_put_u32(&b, EK_ATTR_PID, pid);
	if (netns_path && netns_path[0])
		ek_tlv_put_str(&b, EK_ATTR_NETNS_PATH, netns_path);

	return send_raw(frame, b.pos);
}

static int send_reply_exited(int32_t exit_code, uint8_t term_signal)
{
	uint8_t frame[64];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, frame, sizeof(frame));
	buf_write_u8(&b, ERLKOENIG_TAG_REPLY_EXITED);
	buf_write_u8(&b, 1);
	ek_tlv_put_i32(&b, EK_ATTR_EXIT_CODE, exit_code);
	ek_tlv_put_u8(&b, EK_ATTR_TERM_SIGNAL, term_signal);

	return send_raw(frame, b.pos);
}

static int send_reply_status(uint8_t state, uint32_t pid, uint64_t uptime_ms)
{
	uint8_t frame[64];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, frame, sizeof(frame));
	buf_write_u8(&b, ERLKOENIG_TAG_REPLY_STATUS);
	buf_write_u8(&b, 1);
	ek_tlv_put_u8(&b, EK_ATTR_STATE, state);
	ek_tlv_put_u32(&b, 2 /* PID */, pid);
	ek_tlv_put_u64(&b, EK_ATTR_UPTIME_MS, uptime_ms);

	return send_raw(frame, b.pos);
}

/* -- Command handlers --------------------------------------------- */

/*
 * Pure TLV-payload parsers (ek_parse_cmd_spawn/kill/net_setup/resize)
 * live in src/ek_protocol.c so the libFuzzer harnesses under
 * test/fuzz link against the exact same code paths that ship in
 * production. Do NOT inline parsers back here.
 */


/*
 * handle_cmd_spawn - Create a new container.
 *
 * Parses the SPAWN payload via ek_parse_cmd_spawn() (pure function),
 * then executes the spawn via erlkoenig_spawn() (syscalls).
 */
static void handle_cmd_spawn(const uint8_t *payload, size_t len)
{
	struct erlkoenig_spawn_opts opts;
	int ret;

	if (g_state.state != STATE_IDLE) {
		send_reply_error(-EBUSY, "container already exists");
		return;
	}

	ret = ek_parse_cmd_spawn(payload, len, &opts);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	LOG_INFO("SPAWN path=%s argc=%d envc=%d uid=%u gid=%u flags=0x%x",
		 opts.binary_path, opts.argc, opts.envc, opts.uid, opts.gid,
		 opts.flags);

	/* Do the actual spawn */
	ret = erlkoenig_spawn(&opts, &g_state.ct);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	g_state.state = STATE_CREATED;
	g_state.stdout_open = (g_state.ct.stdout_fd >= 0);
	g_state.stderr_open = (g_state.ct.stderr_fd >= 0);
	g_state.pty_open = (g_state.ct.pty_master >= 0);
	g_state.cgroup_path[0] = '\0';

	/* Setup cgroup if limits were requested */
	if (opts.memory_max > 0 || opts.pids_max > 0 || opts.cpu_weight > 0) {
		const char *name = strrchr(opts.binary_path, '/');

		name = name ? name + 1 : opts.binary_path;

		ret = erlkoenig_cg_setup(g_state.ct.child_pid, name,
					 opts.memory_max, opts.pids_max,
					 opts.cpu_weight, g_state.cgroup_path,
					 sizeof(g_state.cgroup_path));
		if (ret)
			LOG_WARN("cgroup setup failed: %s (continuing "
				 "without limits)",
				 strerror(-ret));

		/* Auto-start BPF metrics if cgroup exists */
		if (g_state.cgroup_path[0] != '\0') {
			ret = ek_metrics_start(g_state.cgroup_path,
					       &g_state.metrics);
			if (ret)
				LOG_WARN("auto metrics-start failed: %s",
					 strerror(-ret));
			else
				LOG_INFO("BPF metrics auto-started");
		}
	}

	send_reply_container_pid((uint32_t)g_state.ct.child_pid,
				 g_state.ct.netns_path);
}

/*
 * harden_runtime_after_go - Lock down the runtime process after CMD_GO.
 *
 * After GO, the runtime only needs to:
 *   - read/write on sockets and pipes (command I/O, output forwarding)
 *   - ppoll (event loop)
 *   - kill/waitpid (container lifecycle)
 *   - ioctl (PTY resize, FIONREAD)
 *   - accept (socket mode reconnect)
 *   - bpf/perf_event_open/mmap (metrics, if started after GO)
 *
 * What we lock down:
 *   1. Capabilities: drop everything except CAP_KILL
 *   2. Seccomp: block setup syscalls (mount, clone, execve, pivot_root,
 *      setuid/setgid, unshare, setns, reboot, module loading, etc.)
 *
 * This is a denylist approach because metrics and socket reconnect
 * require syscalls that a strict allowlist would block.
 */
static void harden_runtime_after_go(void)
{
	/*
	 * Phase 1.5: Drop all capabilities except CAP_KILL.
	 * CAP_KILL is needed to send signals to the container process.
	 * All other caps (SYS_ADMIN, NET_ADMIN, etc.) were only needed
	 * for namespace/mount/network setup which is now complete.
	 */
	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	struct __user_cap_data_struct data[2] = {
	    [0] =
		{
		    .effective = (1U << CAP_KILL),
		    .permitted = (1U << CAP_KILL),
		    .inheritable = 0,
		},
	};

	if (syscall(SYS_capset, &hdr, data))
		LOG_WARN("runtime capset(CAP_KILL only): %s", strerror(errno));
	else
		LOG_INFO("runtime capabilities reduced to CAP_KILL only");

	/*
	 * Phase 2.1: Landlock filesystem restriction.
	 *
	 * After setup, the runtime only needs its already-open FDs
	 * (socket, pipes, PTY, metrics ring buffer). It should not
	 * be able to open any new files on the host filesystem.
	 *
	 * We create an empty Landlock ruleset with all FS access rights
	 * handled, then restrict ourselves. Since no rules are added,
	 * ALL filesystem access is denied. Only pre-opened FDs still work.
	 *
	 * Landlock requires NO_NEW_PRIVS to be set first.
	 * Unprivileged (no CAP needed) and stackable.
	 * Graceful fallback on kernels without Landlock (< 5.13).
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		LOG_WARN("NO_NEW_PRIVS before Landlock: %s", strerror(errno));
	{
		/* Check Landlock ABI version */
		int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
				       LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 0) {
			LOG_INFO("Landlock not available (kernel too old)");
		} else {
			/* All filesystem access rights we want to restrict.
			 * ABI v1 supports the base set. v2+ adds REFER, v3 adds
			 * TRUNCATE. We handle what the kernel supports. */
			__u64 fs_rights = LANDLOCK_ACCESS_FS_EXECUTE |
					  LANDLOCK_ACCESS_FS_WRITE_FILE |
					  LANDLOCK_ACCESS_FS_READ_FILE |
					  LANDLOCK_ACCESS_FS_READ_DIR |
					  LANDLOCK_ACCESS_FS_REMOVE_DIR |
					  LANDLOCK_ACCESS_FS_REMOVE_FILE |
					  LANDLOCK_ACCESS_FS_MAKE_CHAR |
					  LANDLOCK_ACCESS_FS_MAKE_DIR |
					  LANDLOCK_ACCESS_FS_MAKE_REG |
					  LANDLOCK_ACCESS_FS_MAKE_SOCK |
					  LANDLOCK_ACCESS_FS_MAKE_FIFO |
					  LANDLOCK_ACCESS_FS_MAKE_BLOCK |
					  LANDLOCK_ACCESS_FS_MAKE_SYM;

			if (abi >= 2)
				fs_rights |= LANDLOCK_ACCESS_FS_REFER;
			if (abi >= 3)
				fs_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;

			struct landlock_ruleset_attr attr = {
			    .handled_access_fs = fs_rights,
			};

			int ruleset_fd =
			    (int)syscall(SYS_landlock_create_ruleset, &attr,
					 sizeof(attr), 0);
			if (ruleset_fd < 0) {
				LOG_WARN("landlock_create_ruleset: %s",
					 strerror(errno));
			} else {
				/* No rules added — deny everything.
				 * Pre-opened FDs (socket, pipes) still work. */
				if (syscall(SYS_landlock_restrict_self,
					    ruleset_fd, 0))
					LOG_WARN("landlock_restrict_self: %s",
						 strerror(errno));
				else
					LOG_INFO("Landlock: filesystem access "
						 "denied (ABI v%d)",
						 abi);
				close(ruleset_fd);
			}
		}
	}

	/*
	 * Phase 1.4: Seccomp denylist for the runtime process.
	 *
	 * Block syscalls that the runtime should never need after setup.
	 * Denylist (not allowlist) because metrics and socket reconnect
	 * need bpf(), mmap(), accept() which a strict allowlist would block.
	 */
#define RT_DENY(nr)                                                            \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1),                       \
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

	static struct sock_filter runtime_filter[] = {
	    /* Validate architecture */
	    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		     offsetof(struct seccomp_data, arch)),
#if defined(__x86_64__)
	    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__aarch64__)
	    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#endif
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
	    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		     offsetof(struct seccomp_data, nr)),
	    /* Namespace/mount operations — mostly locked down.
	     *
	     * setns() is allowed: the runtime needs to re-enter the
	     * container's network namespace in reap_child() to
	     * synchronously delete the IPVLAN slave BEFORE sending
	     * REPLY_EXITED (see erlkoenig_netcfg_teardown_slave).
	     * Without this sync point, the kernel cleans up the slave
	     * asynchronously after netns ref drops, leaving a narrow
	     * window where pod-supervisor respawn trips EADDRINUSE on
	     * the parent dummy.  setns alone (without unshare/clone)
	     * can only enter existing namespaces that the runtime
	     * already has an fd for — no new privilege.
	     */
	    RT_DENY(SYS_mount),
	    RT_DENY(SYS_umount2),
	    RT_DENY(SYS_pivot_root),
	    RT_DENY(SYS_unshare),
	    /* RT_DENY(SYS_setns) — intentionally allowed, see above */
	    /* Process creation — runtime doesn't fork after setup */
	    RT_DENY(SYS_clone),
	    RT_DENY(SYS_clone3),
	    RT_DENY(SYS_fork),
	    RT_DENY(SYS_vfork),
	    RT_DENY(SYS_execve),
	    RT_DENY(SYS_execveat),
	    /* Identity changes — UID/GID is set */
	    RT_DENY(SYS_setuid),
	    RT_DENY(SYS_setgid),
	    RT_DENY(SYS_setresuid),
	    RT_DENY(SYS_setresgid),
	    RT_DENY(SYS_setgroups),
	    /* Kernel operations — never needed */
	    RT_DENY(SYS_reboot),
	    RT_DENY(SYS_kexec_load),
	    RT_DENY(SYS_kexec_file_load),
	    RT_DENY(SYS_init_module),
	    RT_DENY(SYS_finit_module),
	    RT_DENY(SYS_delete_module),
	    /* Dangerous ops — never needed */
	    RT_DENY(SYS_ptrace),
	    RT_DENY(SYS_personality),
	    RT_DENY(SYS_swapon),
	    RT_DENY(SYS_swapoff),
	    RT_DENY(SYS_acct),
	    /* io_uring — massive kernel attack surface */
	    RT_DENY(425 /* io_uring_setup */),
	    RT_DENY(426 /* io_uring_enter */),
	    RT_DENY(427 /* io_uring_register */),
	    /* Everything else: allow (runtime needs read/write/ppoll/
	     * kill/waitpid/ioctl/mmap/bpf/accept for normal operation) */
	    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		LOG_WARN("runtime NO_NEW_PRIVS: %s", strerror(errno));
		return;
	}

	struct sock_fprog prog = {
	    .len = (unsigned short)(sizeof(runtime_filter) /
				    sizeof(runtime_filter[0])),
	    .filter = runtime_filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		LOG_WARN("runtime seccomp: %s", strerror(errno));
	else
		LOG_INFO("runtime seccomp filter installed (%u instructions)",
			 prog.len);
}

static void handle_cmd_go(void)
{
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL, "no container waiting for GO");
		return;
	}

	ret = erlkoenig_go(&g_state.ct);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	/*
	 * Check the execve error pipe. The write-end has O_CLOEXEC:
	 * if execve succeeds, it's closed (we read EOF = success).
	 * If execve fails, PID 2 writes errno before _exit(127).
	 *
	 * We read non-blocking here. The actual error may arrive
	 * later (child still in caps/seccomp setup), but we'll get
	 * the exit notification via SIGCHLD/reap_child in that case.
	 * This is a best-effort early detection.
	 */
	if (g_state.ct.exec_err_fd >= 0) {
		int exec_errno = 0;
		ssize_t n;

		/* Set non-blocking for the read attempt */
		int fl = fcntl(g_state.ct.exec_err_fd, F_GETFL);

		if (fl >= 0)
			fcntl(g_state.ct.exec_err_fd, F_SETFL, fl | O_NONBLOCK);

		n = read(g_state.ct.exec_err_fd, &exec_errno,
			 sizeof(exec_errno));

		if (n == (ssize_t)sizeof(exec_errno) && exec_errno != 0) {
			LOG_ERR("execve failed: %s", strerror(exec_errno));
			/* Don't close yet -- reap_child will handle cleanup */
		}

		/* Restore blocking mode (reap_child may read it later) */
		if (fl >= 0)
			fcntl(g_state.ct.exec_err_fd, F_SETFL, fl);
	}

	g_state.state = STATE_RUNNING;
	g_state.started_at = monotonic_ms();

	/*
	 * Lock down the runtime process now that setup is complete.
	 * Drop all caps except CAP_KILL, install seccomp denylist.
	 * This is irreversible — the runtime can never mount, clone,
	 * or change identity again.
	 */
	harden_runtime_after_go();

	send_reply_ok(NULL, 0);
}


static void handle_cmd_kill(const uint8_t *payload, size_t len)
{
	uint8_t signal_num;

	if (g_state.state != STATE_CREATED && g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL, "no container to kill");
		return;
	}

	if (ek_parse_cmd_kill(payload, len, &signal_num)) {
		send_reply_error(-EINVAL, "invalid kill command");
		return;
	}

	LOG_INFO("KILL signal=%u pid=%d", signal_num,
		 (int)g_state.ct.child_pid);

	if (ct_kill((int)signal_num)) {
		int err = errno;

		send_reply_error(-err, strerror(err));
		return;
	}

	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_net_setup - Configure networking inside the container's netns.
 *
 * Wire: <<IfName:str16, IpA:8, IpB:8, IpC:8, IpD:8,
 *          Prefixlen:8, GwA:8, GwB:8, GwC:8, GwD:8>>
 */

static void handle_cmd_net_setup(const uint8_t *payload, size_t len)
{
	struct ek_net_setup_args args;
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL, "net_setup requires state CREATED");
		return;
	}

	if (ek_parse_cmd_net_setup(payload, len, &args)) {
		send_reply_error(-EINVAL, "invalid net_setup command");
		return;
	}

	LOG_INFO("NET_SETUP if=%s ip=%u.%u.%u.%u/%u gw=%u.%u.%u.%u pid=%d",
		 args.ifname, args.ip_bytes[0], args.ip_bytes[1],
		 args.ip_bytes[2], args.ip_bytes[3], args.prefixlen,
		 args.gw_bytes[0], args.gw_bytes[1], args.gw_bytes[2],
		 args.gw_bytes[3], (int)g_state.ct.child_pid);

	ret = erlkoenig_netcfg_setup(g_state.ct.child_pid, args.ifname, args.ip,
				     args.prefixlen, args.gateway);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	/*
	 * Capture netns fd + ifname for the sync teardown in reap_child.
	 * We open a fresh fd rather than reusing any existing one so the
	 * lifetime is bound to g_state, not the netcfg_setup call.
	 */
	if (g_state.container_netns_fd >= 0) {
		close(g_state.container_netns_fd);
		g_state.container_netns_fd = -1;
	}
	{
		char ns_path[64];
		snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/net",
			 (int)g_state.ct.child_pid);
		g_state.container_netns_fd =
			open(ns_path, O_RDONLY | O_CLOEXEC);
		if (g_state.container_netns_fd < 0)
			LOG_WARN("NET_SETUP: cannot open %s for later "
				 "teardown: %s", ns_path, strerror(errno));
		/* Ifname copy, NUL-terminated */
		strncpy(g_state.container_ifname, args.ifname,
			IF_NAMESIZE - 1);
		g_state.container_ifname[IF_NAMESIZE - 1] = '\0';
	}

	/* Register XDP route if steering is active.
	 * Look up the host-side veth by convention: veth-ek-<PID%10000>.
	 * The container IP needs to be in network byte order (how it
	 * appears in packet headers — XDP reads raw packet bytes).
	 */
	if (ek_xdp_is_active()) {
		char veth_name[IF_NAMESIZE];
		snprintf(veth_name, sizeof(veth_name), "vek%d",
			 (int)g_state.ct.child_pid);
		unsigned int veth_idx = if_nametoindex(veth_name);
		if (veth_idx > 0) {
			uint32_t ip_net = htonl(args.ip);
			ek_xdp_add_route(ip_net, (uint32_t)veth_idx);
			g_state.container_ip_net = ip_net;
		} else {
			LOG_WARN("xdp: veth %s not found, skip route add",
				 veth_name);
		}
	}

	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_write_file - Write a file into the container rootfs.
 *
 * Wire: <<Path:str16, Mode:16, DataLen:32, Data/binary>>
 *
 * Path must be absolute, no ".." components, resolved relative
 * to the container rootfs. Missing parent directories are created.
 *
 * The child has already done pivot_root by the time this is called
 * (state CREATED = after spawn, before go). setns() into the child's
 * mount namespace gives us the same mount table, but our root directory
 * still points to the host root. We access the container rootfs via
 * /proc/<pid>/root which follows the child's root directory (set by
 * pivot_root to the OverlayFS merged view).
 */
static void handle_cmd_write_file(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data, *file_data;
	uint16_t path_len, mode;
	uint32_t data_len;
	char path[1024];
	char root_prefix[64];

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL, "write_file requires state CREATED");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read path");
		return;
	}
	if (path_len == 0 || path_len >= (uint16_t)sizeof(path)) {
		send_reply_error(-EINVAL, "path too long or empty");
		return;
	}
	memcpy(path, path_data, path_len);
	path[path_len] = '\0';

	if (buf_read_u16(&b, &mode)) {
		send_reply_error(-EINVAL, "failed to read mode");
		return;
	}

	if (buf_read_u32(&b, &data_len)) {
		send_reply_error(-EINVAL, "failed to read data length");
		return;
	}
	if (b.pos + data_len > b.len) {
		send_reply_error(-EINVAL, "data truncated");
		return;
	}
	file_data = b.data + b.pos;

	/* Validate path: must start with /, no .. components */
	if (path[0] != '/') {
		send_reply_error(-EINVAL, "path must be absolute");
		return;
	}
	if (strstr(path, "..")) {
		send_reply_error(-EINVAL, "path must not contain ..");
		return;
	}

	/*
	 * Write into the container rootfs via openat() on /proc/<pid>/root.
	 *
	 * After spawn, the child has done pivot_root + remount-ro. Its "/"
	 * is the OverlayFS merged view, mounted read-only.
	 *
	 * /proc/<pid>/root is a kernel magic symlink that resolves to the
	 * child's root directory. We open it as a directory FD, then use
	 * openat() for all operations relative to this FD.
	 *
	 * For the remount rw/ro we need setns() into the child's mount
	 * namespace, plus chroot so that "/" resolves to the container root.
	 * The actual file I/O uses the pre-opened directory FD.
	 */
	{
		char ns_path[64];
		_cleanup_close_ int child_mnt_fd = -1;
		_cleanup_close_ int orig_mnt_fd = -1;
		_cleanup_close_ int orig_root_fd = -1;
		_cleanup_close_ int container_root_fd = -1;

		/*
		 * Open /proc/<pid>/root as a real directory FD (not O_PATH).
		 * This crosses namespace boundaries — the kernel resolves
		 * the magic symlink to the child's root directory.
		 */
		snprintf(root_prefix, sizeof(root_prefix), "/proc/%d/root",
			 (int)g_state.ct.child_pid);
		container_root_fd = open(root_prefix, O_DIRECTORY | O_CLOEXEC);
		if (container_root_fd < 0) {
			send_reply_error(-errno, "open(container root)");
			return;
		}

		/* Save our mount namespace and root for restore */
		orig_mnt_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
		if (orig_mnt_fd < 0) {
			send_reply_error(-errno, "open(self ns/mnt)");
			return;
		}
		orig_root_fd = open("/", O_DIRECTORY | O_CLOEXEC);
		if (orig_root_fd < 0) {
			send_reply_error(-errno, "open(orig root)");
			return;
		}

		/* Enter child's mount namespace for remount */
		snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt",
			 (int)g_state.ct.child_pid);
		child_mnt_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
		if (child_mnt_fd < 0) {
			send_reply_error(-errno, "open(child ns/mnt)");
			return;
		}
		if (setns(child_mnt_fd, CLONE_NEWNS)) {
			send_reply_error(-errno, "setns(child mnt)");
			return;
		}

		/*
		 * Set our root to the container root so that mount("/", ...)
		 * targets the container's OverlayFS, not the host root.
		 */
		if (fchdir(container_root_fd)) {
			int e = errno;
			if (setns(orig_mnt_fd, CLONE_NEWNS))
				LOG_ERR("FATAL: cannot restore mnt ns: %s",
					strerror(errno));
			send_reply_error(-e, "fchdir(container root)");
			return;
		}
		if (chroot(".")) {
			int e = errno;
			if (setns(orig_mnt_fd, CLONE_NEWNS))
				LOG_ERR("FATAL: cannot restore mnt ns: %s",
					strerror(errno));
			send_reply_error(-e, "chroot(container root)");
			return;
		}

		/* Remount container rootfs read-write */
		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_BIND, NULL)) {
			int e = errno;
			if (fchdir(orig_root_fd) || chroot("."))
				LOG_ERR("FATAL: cannot restore root: %s",
					strerror(errno));
			if (setns(orig_mnt_fd, CLONE_NEWNS))
				LOG_ERR("FATAL: cannot restore mnt ns: %s",
					strerror(errno));
			send_reply_error(-e, "remount rw");
			return;
		}

		/*
		 * Write the file using openat() relative to the container
		 * root FD. The path is relative (strip leading /).
		 */
		const char *rel_path = path + 1; /* skip leading / */

		/* Create parent directories via mkdirat */
		{
			char dir[1024];

			snprintf(dir, sizeof(dir), "%s", rel_path);
			for (char *p = dir; *p; p++) {
				if (*p == '/') {
					*p = '\0';
					mkdirat(container_root_fd, dir, 0755);
					*p = '/';
				}
			}
		}

		/* Write file via openat */
		{
			int fd =
			    openat(container_root_fd, rel_path,
				   O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
				   (mode_t)mode);
			if (fd < 0) {
				int e = errno;
				mount(NULL, "/", NULL,
				      MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
				if (fchdir(orig_root_fd) || chroot("."))
					LOG_ERR(
					    "FATAL: cannot restore root: %s",
					    strerror(errno));
				if (setns(orig_mnt_fd, CLONE_NEWNS))
					LOG_ERR(
					    "FATAL: cannot restore mnt ns: %s",
					    strerror(errno));
				send_reply_error(-e, "open failed");
				return;
			}

			size_t written = 0;

			while (written < data_len) {
				ssize_t n = write(fd, file_data + written,
						  data_len - written);
				if (n < 0) {
					if (errno == EINTR)
						continue;
					int e = errno;
					close(fd);
					mount(NULL, "/", NULL,
					      MS_REMOUNT | MS_RDONLY | MS_BIND,
					      NULL);
					if (fchdir(orig_root_fd) || chroot("."))
						LOG_ERR("FATAL: cannot restore "
							"root: %s",
							strerror(errno));
					if (setns(orig_mnt_fd, CLONE_NEWNS))
						LOG_ERR("FATAL: cannot restore "
							"mnt ns: %s",
							strerror(errno));
					send_reply_error(-e, "write failed");
					return;
				}
				written += (size_t)n;
			}
			close(fd);
		}

		/*
		 * Restore read-only rootfs.  On failure we log and proceed
		 * to the chroot/setns restore — a stuck RW remount is bad
		 * but a stuck chroot is worse (we'd operate on container
		 * root for every subsequent request).
		 */
		if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND,
			  NULL))
			LOG_ERR("remount ro after write_file: %s",
				strerror(errno));

		/*
		 * Restore original root and mount namespace.  A failure here
		 * means the runtime process is stuck inside the container
		 * rootfs — subsequent commands would see the wrong
		 * filesystem view.  Terminate rather than risk it: the
		 * supervisor will spawn a fresh runtime on the next request.
		 */
		if (fchdir(orig_root_fd) || chroot(".")) {
			LOG_ERR("FATAL: cannot restore root after write_file: %s",
				strerror(errno));
			_exit(1);
		}
		if (setns(orig_mnt_fd, CLONE_NEWNS)) {
			LOG_ERR("FATAL: cannot restore mount namespace: %s",
				strerror(errno));
			_exit(1);
		}
	}

	LOG_DBG("WRITE_FILE %s mode=%04o size=%u", path, mode, data_len);
	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_stdin - Send data to container stdin or PTY.
 * Fire-and-forget: no reply sent.
 *
 * Wire: <<DataLen:16, Data/binary>>
 */
static void handle_cmd_stdin(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	uint16_t data_len;
	const uint8_t *data;
	int fd;

	if (g_state.state != STATE_RUNNING) {
		/* Silently drop -- fire-and-forget semantics */
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	if (buf_read_u16(&b, &data_len) || b.pos + data_len > b.len)
		return;
	data = b.data + b.pos;

	/* Choose target FD: PTY master or stdin pipe */
	if (g_state.ct.pty_master >= 0)
		fd = g_state.ct.pty_master;
	else if (g_state.ct.stdin_fd >= 0)
		fd = g_state.ct.stdin_fd;
	else
		return;

	size_t total = 0;

	while (total < data_len) {
		ssize_t n = write(fd, data + total, data_len - total);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			LOG_WARN("write(stdin): %s", strerror(errno));
			return;
		}
		total += (size_t)n;
	}
}

/*
 * handle_cmd_resize - Resize container PTY.
 *
 * Wire: <<Rows:16, Cols:16>>
 */

static void handle_cmd_resize(const uint8_t *payload, size_t len)
{
	uint16_t rows, cols;

	if (g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL, "no running container");
		return;
	}

	if (g_state.ct.pty_master < 0) {
		send_reply_error(-EINVAL, "not in PTY mode");
		return;
	}

	if (ek_parse_cmd_resize(payload, len, &rows, &cols)) {
		send_reply_error(-EINVAL, "invalid resize command");
		return;
	}

	struct winsize ws = {
	    .ws_row = rows,
	    .ws_col = cols,
	};

	if (ioctl(g_state.ct.pty_master, TIOCSWINSZ, &ws)) {
		send_reply_error(-errno, "TIOCSWINSZ failed");
		return;
	}

	LOG_DBG("RESIZE rows=%u cols=%u", rows, cols);
	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_device_filter - Attach eBPF device filter to container cgroup.
 *
 * Wire format: <<CgroupPath:str16, RuleCount:8, Rules/binary>>
 * Each rule:   <<Type:8, Major:32/signed, Minor:32/signed, Access:8>>
 *
 * If RuleCount == 0, uses the built-in OCI default allowlist.
 * Must be called in STATE_CREATED (before GO), after cgroup setup.
 */
static void handle_cmd_device_filter(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data;
	uint16_t path_len;
	uint8_t rule_count;
	int ret;

	if (g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL,
				 "device filter requires CREATED state");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	/* Read cgroup path */
	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read cgroup path");
		return;
	}

	char cgroup_path[512];
	if (path_len >= sizeof(cgroup_path)) {
		send_reply_error(-ENAMETOOLONG, "cgroup path too long");
		return;
	}
	memcpy(cgroup_path, path_data, path_len);
	cgroup_path[path_len] = '\0';

	/* Read rule count */
	if (buf_read_u8(&b, &rule_count)) {
		send_reply_error(-EINVAL, "failed to read rule count");
		return;
	}

	if (rule_count == 0) {
		/* Use default OCI allowlist */
		LOG_DBG("DEVICE_FILTER cgroup=%s rules=default(%zu)",
			cgroup_path, ek_default_dev_rules_count);
		ret = ek_devfilter_attach(cgroup_path, ek_default_dev_rules,
					  ek_default_dev_rules_count);
	} else {
		/* Parse custom rules from payload */
		struct ek_dev_rule rules[64];
		if (rule_count > 64) {
			send_reply_error(-E2BIG, "too many device rules");
			return;
		}

		for (uint8_t i = 0; i < rule_count; i++) {
			uint8_t type, access;
			int32_t major, minor;

			if (buf_read_u8(&b, &type) ||
			    buf_read_i32(&b, &major) ||
			    buf_read_i32(&b, &minor) ||
			    buf_read_u8(&b, &access)) {
				send_reply_error(-EINVAL,
						 "failed to read device rule");
				return;
			}
			rules[i].type = (int32_t)type;
			rules[i].major = major;
			rules[i].minor = minor;
			rules[i].access = (uint32_t)access;
		}

		LOG_DBG("DEVICE_FILTER cgroup=%s rules=%u", cgroup_path,
			rule_count);
		ret =
		    ek_devfilter_attach(cgroup_path, rules, (size_t)rule_count);
	}

	if (ret < 0) {
		send_reply_error((int32_t)ret, "device filter attach failed");
	} else {
		send_reply_ok(NULL, 0);
	}
}

/*
 * handle_cmd_metrics_start - Start eBPF tracepoint metrics.
 *
 * Wire: <<CgroupPath:str16>>
 *
 * Loads BPF programs for fork/exec/exit/oom tracepoints,
 * filtered by the container's cgroup ID. Events stream back
 * as REPLY_METRICS_EVENT frames.
 */
static void handle_cmd_metrics_start(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data;
	uint16_t path_len;
	int ret;

	if (g_state.state != STATE_CREATED && g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL,
				 "metrics requires CREATED or RUNNING state");
		return;
	}

	if (g_state.metrics.ringbuf_fd >= 0) {
		send_reply_error(-EALREADY, "metrics already active");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	if (buf_read_str16(&b, &path_data, &path_len)) {
		send_reply_error(-EINVAL, "failed to read cgroup path");
		return;
	}

	char cgroup_path[512];
	if (path_len >= sizeof(cgroup_path)) {
		send_reply_error(-ENAMETOOLONG, "cgroup path too long");
		return;
	}
	memcpy(cgroup_path, path_data, path_len);
	cgroup_path[path_len] = '\0';

	LOG_INFO("METRICS_START cgroup=%s", cgroup_path);

	ret = ek_metrics_start(cgroup_path, &g_state.metrics);
	if (ret < 0) {
		send_reply_error((int32_t)ret, "metrics start failed");
	} else {
		send_reply_ok(NULL, 0);
	}
}

static void handle_cmd_metrics_stop(void)
{
	LOG_INFO("METRICS_STOP");
	ek_metrics_stop(&g_state.metrics);
	send_reply_ok(NULL, 0);
}

/*
 * metrics_event_callback - Serialize a metrics event as a protocol frame.
 *
 * Called from ek_metrics_consume() for each ring buffer event.
 * Sends REPLY_METRICS_EVENT: <<Type:8, Pid:32, Tgid:32, Ts:64, Data/binary>>
 */
static void metrics_event_callback(const struct ek_metrics_event *ev,
				   void *userdata)
{
	(void)userdata;
	uint8_t frame[128];
	uint8_t event_data[64];
	struct erlkoenig_buf eb, fb;

	/* Build event data blob: <<Type:8, PID:32, TGID:32, Ts:64, payload>> */
	erlkoenig_buf_init(&eb, event_data, sizeof(event_data));
	buf_write_u8(&eb, ev->type);
	buf_write_u32(&eb, ev->pid);
	buf_write_u32(&eb, ev->tgid);
	buf_write_u64(&eb, ev->timestamp_ns);

	switch (ev->type) {
	case EK_METRICS_FORK:
		buf_write_u32(&eb, ev->fork_ev.child_pid);
		break;
	case EK_METRICS_EXEC:
		buf_write_bytes(&eb, (const uint8_t *)ev->exec_ev.comm, 16);
		break;
	case EK_METRICS_EXIT:
		buf_write_i32(&eb, ev->exit_ev.exit_code);
		break;
	case EK_METRICS_OOM:
		buf_write_u32(&eb, ev->oom_ev.victim_pid);
		break;
	default:
		return;
	}

	/* TLV frame: <<Tag:8, Ver:8, EVENT_DATA TLV>> */
	erlkoenig_buf_init(&fb, frame, sizeof(frame));
	buf_write_u8(&fb, ERLKOENIG_TAG_REPLY_METRICS_EVENT);
	buf_write_u8(&fb, 1);
	ek_tlv_put(&fb, EK_ATTR_EVENT_DATA, event_data, (uint16_t)eb.pos);

	send_raw(frame, fb.pos);
}

/*
 * handle_cmd_query_status - Report container status.
 *
 * Enhanced for crash recovery: includes exit code and signal
 * so a reconnecting Erlang node can learn what happened while
 * it was disconnected.
 *
 * Reply: <<State:8, Pid:32, ExitCode:32/signed, TermSignal:8, Uptime:64>>
 *   State 0 = idle, 1 = alive (created or running), 2 = stopped
 */
static void handle_cmd_query_status(void)
{
	uint8_t state = 0;
	uint32_t pid = 0;
	uint64_t uptime_ms = 0;

	switch (g_state.state) {
	case STATE_IDLE:
		state = 0;
		break;
	case STATE_CREATED:
	case STATE_RUNNING:
		state = 1;
		pid = (uint32_t)g_state.ct.child_pid;
		if (g_state.started_at > 0) {
			uint64_t now = monotonic_ms();
			if (now > g_state.started_at)
				uptime_ms = now - g_state.started_at;
		}
		break;
	case STATE_STOPPED:
		state = 2;
		break;
	}

	send_reply_status(state, pid, uptime_ms);

	/*
	 * If the child exited while we were disconnected (socket mode),
	 * send the REPLY_EXITED notification so the Erlang side gets
	 * the same event it would have received if connected at the
	 * time of exit. This is sent AFTER the status reply so the
	 * reconnecting Erlang node sees the correct state transition.
	 */
	if (g_state.exit_pending) {
		g_state.exit_pending = 0;
		send_reply_exited((int32_t)g_state.exit_code,
				  (uint8_t)g_state.term_signal);
	}
}

/* -- Child reaping ------------------------------------------------ */

/*
 * reap_child - Check if the child has exited (non-blocking).
 *
 * Called from the event loop when SIGCHLD was received or
 * periodically as a safety net.
 *
 * In socket mode, if the Erlang connection is down, the exit
 * status is buffered and sent when the connection is restored.
 */
static void reap_child(void)
{
	int status;
	pid_t ret;

	if (g_state.state != STATE_CREATED && g_state.state != STATE_RUNNING)
		return;

	do {
		ret = ct_waitpid(&status, WNOHANG);
	} while (ret < 0 && errno == EINTR);

	if (ret <= 0)
		return;

	/* Child has exited -- check execve error pipe for diagnostics */
	int32_t exit_code = 0;
	uint8_t term_signal = 0;

	if (g_state.ct.exec_err_fd >= 0) {
		int exec_errno = 0;
		ssize_t en;

		do {
			en = read(g_state.ct.exec_err_fd, &exec_errno,
				  sizeof(exec_errno));
		} while (en < 0 && errno == EINTR);

		if (en == (ssize_t)sizeof(exec_errno) && exec_errno != 0)
			LOG_ERR("execve(/app) failed: %s",
				strerror(exec_errno));

		close(g_state.ct.exec_err_fd);
		g_state.ct.exec_err_fd = -1;
	}

	if (WIFSIGNALED(status)) {
		term_signal = (uint8_t)WTERMSIG(status);
		exit_code = -1;
		LOG_INFO("child killed by signal %u", term_signal);
	} else if (WIFEXITED(status)) {
		exit_code = (int32_t)WEXITSTATUS(status);
		/*
		 * The container's mini-init (PID 1) can't die from
		 * signals (kernel protection), so it uses the shell
		 * convention: exit(128 + signal_number). Decode this
		 * back into a proper signal report.
		 */
		if (exit_code > 128 && exit_code < 256) {
			term_signal = (uint8_t)(exit_code - 128);
			exit_code = -1;
			LOG_INFO("child killed by signal %u "
				 "(via init exit code)",
				 term_signal);
		} else {
			LOG_INFO("child exited with code %d", exit_code);
		}
	}

	g_state.state = STATE_STOPPED;
	g_state.exit_code = exit_code;
	g_state.term_signal = term_signal;

	/*
	 * SYNC SLAVE TEARDOWN — see g_state.container_netns_fd comment.
	 * Must happen BEFORE REPLY_EXITED, so Erlang's gen_statem exit
	 * event observers only see the container as dead AFTER the
	 * kernel has freed the IPVLAN slave.  Without this, the
	 * pod-supervisor can respawn a replacement on the same parent
	 * dummy before the kernel cleans up the dying slave, tripping
	 * EADDRINUSE in the new `ip addr add`.
	 */
	if (g_state.container_netns_fd >= 0 &&
	    g_state.container_ifname[0] != '\0') {
		int tdret = erlkoenig_netcfg_teardown_slave(
				g_state.container_netns_fd,
				g_state.container_ifname);
		if (tdret && tdret != -ENODEV)
			LOG_WARN("slave teardown %s failed: %s",
				 g_state.container_ifname,
				 strerror(-tdret));
		else
			LOG_INFO("slave %s torn down before REPLY_EXITED",
				 g_state.container_ifname);
		close(g_state.container_netns_fd);
		g_state.container_netns_fd = -1;
		g_state.container_ifname[0] = '\0';
	}

	if (g_connected) {
		send_reply_exited(exit_code, term_signal);
	} else {
		/*
		 * Socket mode, disconnected: buffer the exit status.
		 * It will be sent when Erlang reconnects and queries status.
		 */
		g_state.exit_pending = 1;
		LOG_INFO("child exited while disconnected, buffering status");
	}

	/* Remove XDP route before veth is destroyed */
	if (g_state.container_ip_net != 0) {
		ek_xdp_del_route(g_state.container_ip_net);
		g_state.container_ip_net = 0;
	}

	erlkoenig_cleanup(&g_state.ct);

	/* Teardown container cgroup (if any) */
	if (g_state.cgroup_path[0] != '\0') {
		ek_metrics_stop(&g_state.metrics);
		erlkoenig_cg_teardown(g_state.cgroup_path);
		g_state.cgroup_path[0] = '\0';
	}

	/*
	 * Reset to IDLE so a new container can be spawned on the
	 * same runtime instance. This enables the CLI shell pattern
	 * where one runtime serves multiple sequential containers.
	 *
	 * The Erlang orchestrator starts one RT per container and
	 * never reuses, but the CLI needs this for interactive use.
	 */
	g_state.state = STATE_IDLE;
	g_state.ct.child_pid = -1;
	g_state.ct.child_pidfd = -1;
	g_state.ct.go_pipe = -1;
	g_state.ct.stdout_fd = -1;
	g_state.ct.stderr_fd = -1;
	g_state.ct.exec_err_fd = -1;
	g_state.ct.stdin_fd = -1;
	g_state.ct.pty_master = -1;
	g_state.stdout_open = 0;
	g_state.stderr_open = 0;
	g_state.pty_open = 0;
	g_state.exit_pending = 0;
	LOG_INFO("runtime reset to IDLE — ready for new container");
}

/* -- Child output forwarding -------------------------------------- */

/*
 * forward_output - Read from a child pipe and send as protocol frame.
 * @fd:		Read-end of the child's stdout or stderr pipe
 * @tag:	ERLKOENIG_TAG_REPLY_STDOUT or ERLKOENIG_TAG_REPLY_STDERR
 *
 * Returns 1 if data was forwarded, 0 on EOF, -1 on error.
 */
static int forward_output(int fd, uint8_t tag)
{
	uint8_t buf[4096];
	ssize_t n;

	n = read(fd, buf, sizeof(buf));
	if (n > 0) {
		/* Streaming: raw <<Tag:8, Data/binary>> (no TLV) */
		uint8_t frame[1 + 4096];
		frame[0] = tag;
		memcpy(frame + 1, buf, (size_t)n);
		send_raw(frame, 1 + (size_t)n);
		return 1;
	}
	if (n == 0)
		return 0; /* EOF */
	if (errno == EINTR || errno == EAGAIN)
		return 1; /* Retry later */
	return -1;
}

/* -- Signal handling ---------------------------------------------- */

static void sigchld_handler(int sig)
{
	(void)sig;
	g_sigchld_received = 1;
}

static void shutdown_handler(int sig)
{
	(void)sig;
	g_shutdown_requested = 1;
}

static int setup_signals(void)
{
	/* SIGCHLD: non-blocking reap notification */
	struct sigaction sa = {
	    .sa_handler = sigchld_handler,
	    .sa_flags = SA_NOCLDSTOP,
	};
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGCHLD, &sa, NULL)) {
		LOG_SYSCALL("sigaction(SIGCHLD)");
		return -errno;
	}

	/* SIGTERM/SIGINT: graceful shutdown (socket mode needs this) */
	sa = (struct sigaction){
	    .sa_handler = shutdown_handler,
	};
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL)) {
		LOG_SYSCALL("sigaction(SIGTERM)");
		return -errno;
	}
	if (sigaction(SIGINT, &sa, NULL)) {
		LOG_SYSCALL("sigaction(SIGINT)");
		return -errno;
	}

	/*
	 * Block SIGCHLD, SIGTERM, SIGINT after handler installation.
	 * These signals are only delivered during ppoll() via the
	 * original (unblocked) mask — this eliminates the race
	 * between checking g_sigchld_received and entering ppoll.
	 */
	sigset_t block_mask;

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGCHLD);
	sigaddset(&block_mask, SIGTERM);
	sigaddset(&block_mask, SIGINT);
	if (sigprocmask(SIG_BLOCK, &block_mask, &g_orig_sigmask)) {
		LOG_SYSCALL("sigprocmask(SIG_BLOCK)");
		return -errno;
	}

	return 0;
}

/* -- Protocol handshake ------------------------------------------- */

/*
 * do_handshake - Protocol version 1 TLV handshake.
 *
 * Client sends: <<Version:8>> (1 byte)
 * Server responds: <<Version:8>> (1 byte)
 * Version mismatch → reject.
 *
 * Returns 0 on success, -1 on failure.
 */
static int do_handshake(int read_fd, int write_fd)
{
	uint8_t hs_buf[64];
	ssize_t hs_len;

	hs_len = erlkoenig_read_frame(read_fd, hs_buf, sizeof(hs_buf));
	if (hs_len < 1) {
		LOG_ERR("handshake: expected >= 1 byte, got %zd", hs_len);
		return -1;
	}

	uint8_t peer_version = hs_buf[0];

	if (peer_version != ERLKOENIG_PROTOCOL_VERSION) {
		LOG_ERR("handshake: peer version %d, we speak %d", peer_version,
			ERLKOENIG_PROTOCOL_VERSION);
		uint8_t reply = ERLKOENIG_PROTOCOL_VERSION;
		erlkoenig_write_frame(write_fd, &reply, 1);
		return -1;
	}

	/* Reply with our version */
	uint8_t reply = ERLKOENIG_PROTOCOL_VERSION;
	if (erlkoenig_write_frame(write_fd, &reply, 1) < 0) {
		LOG_ERR("handshake: failed to send reply");
		return -1;
	}
	LOG_INFO("handshake ok (protocol v%d)", peer_version);
	return 0;
}

/* -- Dispatch ----------------------------------------------------- */

/*
 * handle_cmd_nft_setup - Apply nftables batch in container netns.
 *
 * TLV payload contains a single critical attribute: the raw nftables
 * netlink batch binary (BATCH_BEGIN + messages + BATCH_END).
 */
static void handle_cmd_nft_setup(const uint8_t *payload, size_t len)
{
	struct erlkoenig_buf b;
	struct ek_tlv attr;
	const uint8_t *batch = NULL;
	size_t batch_len = 0;

	if (g_state.state != STATE_CREATED && g_state.state != STATE_RUNNING) {
		send_reply_error(-EINVAL,
				 "nft_setup requires state CREATED or RUNNING");
		return;
	}

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	while (ek_tlv_next(&b, &attr) == 0) {
		uint16_t type = attr.type & (uint16_t)~EK_TLV_CRITICAL_BIT;
		switch (type) {
		case 0x01: /* EK_ATTR_NFT_BATCH */
			batch = attr.value;
			batch_len = attr.len;
			break;
		default:
			if (attr.type & EK_TLV_CRITICAL_BIT) {
				send_reply_error(
				    -EPROTO,
				    "unknown critical attr in nft_setup");
				return;
			}
			break;
		}
	}

	if (!batch || batch_len == 0) {
		send_reply_error(-EINVAL, "nft_setup: missing batch payload");
		return;
	}

	LOG_INFO("NFT_SETUP batch=%zu bytes pid=%d", batch_len,
		 (int)g_state.ct.child_pid);

	int ret = erlkoenig_nft_apply(g_state.ct.child_pid, batch, batch_len);
	if (ret) {
		send_reply_error((int32_t)ret, strerror(-ret));
		return;
	}

	send_reply_ok(NULL, 0);
}

/*
 * handle_cmd_nft_list - Dump nftables ruleset from container netns.
 */
static void handle_cmd_nft_list(void)
{
	if (g_state.state != STATE_RUNNING && g_state.state != STATE_CREATED) {
		send_reply_error(-EINVAL,
				 "nft_list requires state CREATED or RUNNING");
		return;
	}

	/* TODO: structured dump via erlkoenig_nft_list() */
	send_reply_error(-ENOSYS, "nft_list not yet implemented");
}

/*
 * dispatch_command - Route a received command to its handler.
 * @buf:	Payload (starts with tag byte)
 * @len:	Payload length (including tag)
 */
static void dispatch_command(const uint8_t *buf, size_t len)
{
	if (len < 2) {
		send_reply_error(-EINVAL, "message too short (need tag+ver)");
		return;
	}

	uint8_t tag = buf[0];
	/* uint8_t ver = buf[1]; — available for per-command versioning */
	const uint8_t *payload = buf + 2;
	size_t payload_len = len - 2;

	LOG_DBG("received tag=0x%02X (%s) ver=%u payload=%zu bytes", tag,
		erlkoenig_tag_name(tag), buf[1], payload_len);

	switch (tag) {
	case ERLKOENIG_TAG_CMD_SPAWN:
		handle_cmd_spawn(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_GO:
		handle_cmd_go();
		break;
	case ERLKOENIG_TAG_CMD_KILL:
		handle_cmd_kill(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_NET_SETUP:
		handle_cmd_net_setup(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_WRITE_FILE:
		handle_cmd_write_file(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_QUERY_STATUS:
		handle_cmd_query_status();
		break;
	case ERLKOENIG_TAG_CMD_STDIN:
		handle_cmd_stdin(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_RESIZE:
		handle_cmd_resize(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_DEVICE_FILTER:
		handle_cmd_device_filter(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_METRICS_START:
		handle_cmd_metrics_start(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_METRICS_STOP:
		handle_cmd_metrics_stop();
		break;
	case ERLKOENIG_TAG_CMD_NFT_SETUP:
		handle_cmd_nft_setup(payload, payload_len);
		break;
	case ERLKOENIG_TAG_CMD_NFT_LIST:
		handle_cmd_nft_list();
		break;
	default:
		LOG_WARN("unknown command tag 0x%02X", tag);
		send_reply_error(-ENOSYS, "unknown command");
		break;
	}
}

/* -- Event loop --------------------------------------------------- */

/*
 * event_loop - Main command/output polling loop.
 *
 * Polls the command fd for incoming commands and child output fds
 * for stdout/stderr data. Reaps children on SIGCHLD.
 *
 * Returns:
 *   LOOP_SHUTDOWN    - Graceful shutdown (port mode: stdin closed;
 *                      socket mode: SIGTERM or child dead + no container)
 *   LOOP_DISCONNECT  - Connection lost (socket mode only)
 */
static int event_loop(void)
{
	uint8_t msg_buf[ERLKOENIG_MAX_MSG];
	ssize_t msg_len;

	for (;;) {
		struct pollfd pfds[5];
		nfds_t nfds = 1;
		nfds_t metrics_pfd_idx = 0; /* 0 = not in pfds */
		int pret;

		/* Check for graceful shutdown request (SIGTERM/SIGINT) */
		if (g_shutdown_requested) {
			LOG_INFO("shutdown signal received");
			return LOOP_SHUTDOWN;
		}

		/* Check for child exit */
		if (g_sigchld_received) {
			g_sigchld_received = 0;
			reap_child();
		}

		/* Always poll the command fd */
		pfds[0].fd = g_read_fd;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;

		/* Poll child stdout if open and connected */
		if (g_connected && g_state.stdout_open &&
		    g_state.ct.stdout_fd >= 0) {
			pfds[nfds].fd = g_state.ct.stdout_fd;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		/* Poll child stderr if open and connected */
		if (g_connected && g_state.stderr_open &&
		    g_state.ct.stderr_fd >= 0) {
			pfds[nfds].fd = g_state.ct.stderr_fd;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		/* Poll PTY master if open and connected (PTY mode) */
		if (g_connected && g_state.pty_open &&
		    g_state.ct.pty_master >= 0) {
			pfds[nfds].fd = g_state.ct.pty_master;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		/* Poll eBPF ring buffer for metrics events */
		if (g_connected) {
			int mfd = ek_metrics_poll_fd(&g_state.metrics);
			if (mfd >= 0) {
				metrics_pfd_idx = nfds;
				pfds[nfds].fd = mfd;
				pfds[nfds].events = POLLIN;
				pfds[nfds].revents = 0;
				nfds++;
			}
		}

		/*
		 * ppoll with original (unblocked) sigmask: SIGCHLD,
		 * SIGTERM, SIGINT are blocked normally but unblocked
		 * atomically during ppoll. This eliminates the race
		 * between checking g_sigchld_received and blocking.
		 *
		 * No timeout needed: signals (SIGCHLD, SIGTERM, SIGINT)
		 * interrupt ppoll via the unblocked sigmask, and I/O
		 * events wake us via the polled FDs. The timeout was
		 * 100ms before — caused unnecessary 200ms latency for
		 * short-lived containers.
		 */
		pret = ppoll(pfds, nfds, NULL, &g_orig_sigmask);
		if (pret < 0) {
			if (errno == EINTR)
				continue;
			LOG_SYSCALL("ppoll");
			return LOOP_SHUTDOWN;
		}
		if (pret == 0)
			continue; /* Timeout, recheck SIGCHLD */

		/* Check command fd */
		if (pfds[0].revents & POLLNVAL) {
			LOG_ERR("command fd invalid");
			return g_socket_mode ? LOOP_DISCONNECT : LOOP_SHUTDOWN;
		}

		if (pfds[0].revents & POLLIN) {
			msg_len = erlkoenig_read_frame(g_read_fd, msg_buf,
						       sizeof(msg_buf));
			if (msg_len < 0) {
				if (g_socket_mode) {
					LOG_INFO(
					    "connection lost (read error)");
					return LOOP_DISCONNECT;
				}
				LOG_INFO("stdin closed, shutting down");
				return LOOP_SHUTDOWN;
			}
			dispatch_command(msg_buf, (size_t)msg_len);
		}

		if (pfds[0].revents & (POLLERR | POLLHUP)) {
			if (g_socket_mode) {
				LOG_INFO("connection lost (POLLHUP/POLLERR)");
				return LOOP_DISCONNECT;
			}
			LOG_INFO("stdin closed, shutting down");
			return LOOP_SHUTDOWN;
		}

		/* Forward child stdout/stderr/pty output */
		for (nfds_t i = 1; i < nfds; i++) {
			/* Skip metrics fd -- handled separately below */
			if (metrics_pfd_idx > 0 && i == metrics_pfd_idx)
				continue;

			if (!(pfds[i].revents & (POLLIN | POLLHUP)))
				continue;

			int fd = pfds[i].fd;
			uint8_t tag;
			int *open_flag;

			if (fd == g_state.ct.stdout_fd) {
				tag = ERLKOENIG_TAG_REPLY_STDOUT;
				open_flag = &g_state.stdout_open;
			} else if (fd == g_state.ct.pty_master) {
				tag = ERLKOENIG_TAG_REPLY_STDOUT;
				open_flag = &g_state.pty_open;
			} else {
				tag = ERLKOENIG_TAG_REPLY_STDERR;
				open_flag = &g_state.stderr_open;
			}

			if (pfds[i].revents & POLLIN) {
				if (forward_output(fd, tag) == 0)
					*open_flag = 0; /* EOF */
			} else {
				/* POLLHUP without POLLIN = EOF */
				*open_flag = 0;
			}
		}

		/* Consume eBPF ring buffer events */
		if (metrics_pfd_idx > 0 &&
		    (pfds[metrics_pfd_idx].revents & POLLIN)) {
			ek_metrics_consume(&g_state.metrics,
					   metrics_event_callback, NULL);
		}
	}
}

/* -- Socket mode -------------------------------------------------- */

/*
 * create_listen_socket - Create and bind a Unix Domain Socket.
 * @path:	Filesystem path for the socket
 *
 * Removes any stale socket at the path, creates a new one,
 * and starts listening with a backlog of 1 (only one Erlang
 * connection at a time per container).
 *
 * Returns the listen fd on success, -1 on error.
 */
static int create_listen_socket(const char *path)
{
	int fd = -1;
	struct sockaddr_un addr;

	if (strlen(path) >= sizeof(addr.sun_path)) {
		LOG_ERR("socket path too long: %s", path);
		return -1;
	}

	/* Remove stale socket from a previous run */
	unlink(path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		LOG_SYSCALL("socket(AF_UNIX)");
		return -1;
	}

	addr = (struct sockaddr_un){
	    .sun_family = AF_UNIX,
	};
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_SYSCALL("bind");
		goto err;
	}

	/*
	 * Socket permissions: owner (root) + group (erlkoenig) only.
	 * The ExecStartPost in the systemd unit sets the socket group
	 * to erlkoenig after creation. 0660 ensures only root and
	 * members of the erlkoenig group can connect.
	 *
	 * SECURITY: 0666 was previously used here, which allowed
	 * ANY local user to send commands (SPAWN, KILL) to the
	 * container runtime. Fixed to 0660.
	 */
	if (chmod(path, 0660) < 0) {
		LOG_SYSCALL("chmod");
		goto err;
	}

	/* Backlog 1: only one Erlang connection per container */
	if (listen(fd, 1) < 0) {
		LOG_SYSCALL("listen");
		goto err;
	}

	return fd;

err:
	close(fd);
	return -1;
}

/*
 * run_socket_mode - Socket mode main loop.
 * @sock_path:		Path for the Unix Domain Socket
 *
 * Creates a listen socket and enters the accept-event-reconnect loop.
 * The child process survives connection loss. The runtime exits only
 * on SIGTERM/SIGINT or when the child has exited and no reconnect
 * is expected.
 */
static int run_socket_mode(const char *sock_path)
{
	int listen_fd;
	int rc = 0;

	listen_fd = create_listen_socket(sock_path);
	if (listen_fd < 0)
		return 1;

	LOG_INFO("socket mode: listening on %s", sock_path);

	/* Outer loop: accept connections, survive disconnects */
	for (;;) {
		int conn_fd;

		/* Check for shutdown before blocking on accept */
		if (g_shutdown_requested) {
			LOG_INFO("shutdown signal received");
			break;
		}

		/*
		 * Check if child is dead and there's nothing to
		 * reconnect for. In socket mode with no container
		 * (STATE_IDLE) or a stopped container, we still wait
		 * for at least one connection so Erlang can query status.
		 * After delivering the exit status on reconnect, we
		 * continue listening until shutdown.
		 */
		if (g_sigchld_received) {
			g_sigchld_received = 0;
			reap_child();
		}

		LOG_INFO("waiting for connection on %s", sock_path);

		/*
		 * Use ppoll on the listen fd to allow SIGCHLD/SIGTERM
		 * to interrupt the wait. accept() alone would block
		 * until a connection arrives, ignoring signals.
		 */
		{
			struct pollfd pfd;
			struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};

			pfd.fd = listen_fd;
			pfd.events = POLLIN;
			pfd.revents = 0;

			int pr = ppoll(&pfd, 1, &timeout, &g_orig_sigmask);

			if (pr < 0) {
				if (errno == EINTR)
					continue;
				LOG_SYSCALL("ppoll(listen)");
				rc = 1;
				break;
			}
			if (pr == 0)
				continue; /* Timeout, re-check signals */

			if (!(pfd.revents & POLLIN))
				continue;
		}

		conn_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
		if (conn_fd < 0) {
			if (errno == EINTR)
				continue;
			LOG_SYSCALL("accept4");
			rc = 1;
			break;
		}

		LOG_INFO("connection accepted (fd=%d)", conn_fd);

		/* Set the connection as our I/O channel */
		g_read_fd = conn_fd;
		g_write_fd = conn_fd;
		g_connected = 1;

		/* Perform protocol handshake */
		if (do_handshake(conn_fd, conn_fd) < 0) {
			LOG_WARN("handshake failed, closing connection");
			close(conn_fd);
			g_connected = 0;
			g_read_fd = -1;
			g_write_fd = -1;
			continue;
		}

		/* Run the event loop until disconnect or shutdown */
		int loop_rc = event_loop();

		/* Connection is done -- clean up */
		close(conn_fd);
		g_connected = 0;
		g_read_fd = -1;
		g_write_fd = -1;

		if (loop_rc == LOOP_SHUTDOWN) {
			LOG_INFO("graceful shutdown requested");
			break;
		}

		/* LOOP_DISCONNECT: connection lost, go back to accept */
		LOG_INFO("connection lost, waiting for reconnect...");
	}

	close(listen_fd);
	unlink(sock_path);

	/* Final cleanup: kill child if still alive on shutdown */
	ek_metrics_stop(&g_state.metrics);

	if (g_state.state == STATE_CREATED || g_state.state == STATE_RUNNING) {
		LOG_INFO("killing child pid=%d on shutdown",
			 (int)g_state.ct.child_pid);
		ct_kill(SIGKILL);
		while (ct_waitpid(NULL, 0) < 0 && errno == EINTR)
			;
		erlkoenig_cleanup(&g_state.ct);
	}

	LOG_INFO("exiting (socket mode)");
	return rc;
}

/*
 * run_port_mode - Legacy port mode (STDIN/STDOUT pipes).
 *
 * This is the original behavior: reads commands from stdin,
 * writes replies to stdout. Connection loss terminates the runtime.
 */
static int run_port_mode(void)
{
	g_read_fd = STDIN_FILENO;
	g_write_fd = STDOUT_FILENO;
	g_connected = 1;
	g_socket_mode = 0;

	/* Protocol handshake */
	if (do_handshake(STDIN_FILENO, STDOUT_FILENO) < 0)
		return 1;

	/* Run event loop until stdin closes */
	event_loop();

	/* Cleanup: stop metrics and kill child if still alive */
	ek_metrics_stop(&g_state.metrics);

	if (g_state.state == STATE_CREATED || g_state.state == STATE_RUNNING) {
		LOG_INFO("killing child pid=%d on shutdown",
			 (int)g_state.ct.child_pid);
		ct_kill(SIGKILL);
		while (ct_waitpid(NULL, 0) < 0 && errno == EINTR)
			;
		erlkoenig_cleanup(&g_state.ct);
	}

	LOG_INFO("exiting (port mode)");
	return 0;
}

/* -- Argument parsing --------------------------------------------- */

static void print_usage(const char *argv0)
{
	fprintf(
	    stderr,
	    "Usage: %s [OPTIONS]\n"
	    "\n"
	    "Options:\n"
	    "  --socket PATH   Run in socket mode (Unix Domain Socket)\n"
	    "  --cgroup PATH   Move into cgroup before any allocation\n"
	    "  --xdp IFACE     Enable XDP packet steering on host interface\n"
	    "  --id ID         Container ID for log messages\n"
	    "  --help          Show this help\n"
	    "\n"
	    "Without --socket, runs in legacy port mode (STDIN/STDOUT).\n"
	    "Without --xdp, uses kernel routing (default).\n",
	    argv0);
}

int main(int argc, char *argv[])
{
	const char *sock_path = NULL;
	const char *container_id = NULL;
	const char *xdp_iface = NULL;
	const char *cgroup_procs = NULL;

	static const struct option long_opts[] = {
	    {"socket", required_argument, NULL, 's'},
	    {"cgroup", required_argument, NULL, 'c'},
	    {"xdp", required_argument, NULL, 'x'},
	    {"id", required_argument, NULL, 'i'},
	    {"help", no_argument, NULL, 'h'},
	    {NULL, 0, NULL, 0},
	};

	int opt;

	while ((opt = getopt_long(argc, argv, "s:c:x:i:h", long_opts, NULL)) !=
	       -1) {
		switch (opt) {
		case 's':
			sock_path = optarg;
			break;
		case 'c':
			cgroup_procs = optarg;
			break;
		case 'x':
			xdp_iface = optarg;
			break;
		case 'i':
			container_id = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	/*
	 * Move into container cgroup BEFORE any allocation.
	 * This must happen before erlkoenig_log_init() or any malloc —
	 * otherwise memory is charged to the beam cgroup.
	 */
	if (cgroup_procs) {
		int fd = open(cgroup_procs, O_WRONLY);
		if (fd >= 0) {
			dprintf(fd, "%d", (int)getpid());
			close(fd);
		}
	}

	/*
	 * CVE-2019-5736 defense: copy self into a sealed memfd and
	 * re-exec from it, so a compromised privileged container cannot
	 * rewrite the on-disk runtime binary via /proc/<rt-pid>/exe.
	 * Best-effort: falls through unprotected on old kernels / LSM
	 * denials. Idempotent via ERLKOENIG_RT_CLONED sentinel.
	 * Runs AFTER cgroup move so the ~172 KB memfd counts toward the
	 * container cgroup, not the beam. Must run BEFORE we open any
	 * fd that we care about keeping, since re-exec closes everything
	 * non-CLOEXEC.
	 */
	ek_cloned_reexec(argv);

	erlkoenig_log_init();

	if (container_id)
		LOG_INFO("starting (pid=%d uid=%d id=%s)", (int)getpid(),
			 (int)getuid(), container_id);
	else
		LOG_INFO("starting (pid=%d uid=%d)", (int)getpid(),
			 (int)getuid());

	/* Ignore SIGPIPE: on broken connection we want write() to
	 * return EPIPE, not kill the process. Essential in both modes. */
	signal(SIGPIPE, SIG_IGN);

	if (setup_signals())
		return 1;

	memset(&g_state, 0, sizeof(g_state));
	g_state.state = STATE_IDLE;
	g_state.ct.child_pid = -1;
	g_state.ct.child_pidfd = -1;
	g_state.ct.go_pipe = -1;
	g_state.ct.stdout_fd = -1;
	g_state.ct.stderr_fd = -1;
	g_state.ct.exec_err_fd = -1;
	g_state.ct.stdin_fd = -1;
	g_state.ct.pty_master = -1;
	g_state.container_netns_fd = -1;
	ek_metrics_ctx_init(&g_state.metrics);

	/* Initialize XDP packet steering if requested */
	if (xdp_iface) {
		if (ek_xdp_init(xdp_iface) < 0)
			LOG_WARN("XDP init failed on %s — falling back to "
				 "kernel routing",
				 xdp_iface);
	}

	/*
	 * Load node certificate hash (before handshake).
	 * If no cert exists, hash is all zeros -- v1 fallback behavior.
	 */
	int rc;

	if (sock_path) {
		g_socket_mode = 1;
		rc = run_socket_mode(sock_path);
	} else {
		rc = run_port_mode();
	}

	ek_xdp_cleanup();
	return rc;
}
