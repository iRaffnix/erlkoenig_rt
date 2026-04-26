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
 * erlkoenig_seccomp.h - Seccomp-BPF profiles for container processes.
 *
 * Provides predefined syscall filter profiles that are applied
 * BEFORE execve() in the container's PID 2 (app process).
 *
 * Profiles use classic BPF (cBPF), NOT eBPF. The kernel requires
 * this format for seccomp filters -- eBPF is not allowed here due
 * to the larger attack surface (maps, helpers, etc.).
 *
 * Profile IDs:
 *   0 = none     (no filter, full syscall access)
 *   1 = default  (server workloads: network, files, mmap)
 *   2 = strict   (minimal: read/write/exit only)
 *   3 = network  (network allowed, no fork/exec)
 *
 * Usage:
 *   erlkoenig_apply_seccomp(profile_id);  // before execve()
 *
 * The filter runs in SECCOMP_RET_KILL_PROCESS mode: a denied
 * syscall kills the entire process group immediately with SIGSYS.
 */

#ifndef ERLKOENIG_SECCOMP_H
#define ERLKOENIG_SECCOMP_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "erlkoenig_log.h"

/* Seccomp profile IDs (must match Erlang side) */
#define SECCOMP_PROFILE_NONE	0
#define SECCOMP_PROFILE_DEFAULT 1
#define SECCOMP_PROFILE_STRICT	2
#define SECCOMP_PROFILE_NETWORK 3

/*
 * BPF macros for readability.
 *
 * seccomp BPF operates on struct seccomp_data:
 *   int   nr;          // syscall number
 *   __u32 arch;        // AUDIT_ARCH_*
 *   __u64 instruction_pointer;
 *   __u64 args[6];
 */

/* Load the syscall number */
#define SC_LOAD_NR                                                             \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))

/* Load the architecture */
#define SC_LOAD_ARCH                                                           \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch))

/* Load syscall argument N (low 32 bits) */
#define SC_LOAD_ARG(n)                                                         \
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS,                                     \
		 offsetof(struct seccomp_data, args[n]))

/* Allow the syscall */
#define SC_ALLOW BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

/* Kill the process on denied syscall.
 * In debug mode (ERLKOENIG_SECCOMP_LOG env), log instead of kill
 * so violations appear in dmesg/audit without crashing. */
#define SC_KILL BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/* Log-only variant for debugging (replaces SC_KILL in filters) */
#define SC_LOG BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_LOG)

/* Jump if syscall number equals val (true: jt, false: jf) */
#define SC_JUMP_EQ(val, jt, jf)                                                \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (val), (jt), (jf))

/* Validate architecture (kill process on unexpected arch) */
#if defined(__x86_64__)
#define SC_CHECK_ARCH SC_LOAD_ARCH, SC_JUMP_EQ(AUDIT_ARCH_X86_64, 1, 0), SC_KILL
#elif defined(__aarch64__)
#define SC_CHECK_ARCH                                                          \
	SC_LOAD_ARCH, SC_JUMP_EQ(AUDIT_ARCH_AARCH64, 1, 0), SC_KILL
#else
#error "Unsupported architecture for seccomp filters"
#endif

/*
 * ALLOW_SYSCALL(nr) - Allow a single syscall.
 *
 * Jumps to ALLOW if nr matches, falls through otherwise.
 * Must be followed by more ALLOW_SYSCALL or SC_KILL.
 *
 * The jump offset 0 means "next instruction" for the true branch.
 * We use a trick: the true branch jumps to the ALLOW at the end.
 * This doesn't work directly -- instead we build a whitelist
 * where each check falls through to the next, and the final
 * instruction is SC_KILL (deny).
 */

/* ================================================================
 * Profile: STRICT
 *
 * Absolute minimum for a pure computation process.
 * No filesystem, no network, no fork.
 *
 * Includes execve (needed for initial exec before filter takes
 * effect on the new binary) and libc init syscalls (arch_prctl
 * for TLS, set_tid_address, prlimit64, rseq).
 * ================================================================ */
static struct sock_filter seccomp_strict[] = {
    SC_CHECK_ARCH,
    SC_LOAD_NR,
    /* Bootstrap: needed for execve()/execveat() + glibc/musl static init.
     * execveat is the runtime's preferred AT_EMPTY_PATH path (ns.c:1663),
     * and execve is the fallback (ns.c:1677). Both are bootstrap-only —
     * after the binary's main() runs, neither is reachable for re-exec
     * inside STRICT (no clone/fork to gain a new exec target). */
    SC_JUMP_EQ(SYS_execve, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_execveat, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_arch_prctl, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_set_tid_address, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_set_robust_list, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rseq, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_prlimit64, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_readlinkat, 0, 1),
    SC_ALLOW,
    /* I/O */
    SC_JUMP_EQ(SYS_read, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_write, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_readv, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_writev, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_close, 0, 1),
    SC_ALLOW,
    /* Process */
    SC_JUMP_EQ(SYS_exit, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_exit_group, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rt_sigreturn, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rt_sigaction, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rt_sigprocmask, 0, 1),
    SC_ALLOW,
    /* Memory */
    SC_JUMP_EQ(SYS_brk, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_mmap, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_munmap, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_mprotect, 0, 1),
    SC_ALLOW,
    /* Misc */
    SC_JUMP_EQ(SYS_clock_gettime, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_clock_nanosleep, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_nanosleep, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_getrandom, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_futex, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_getpid, 0, 1),
    SC_ALLOW,
    SC_KILL,
};

/* ================================================================
 * Profile: NETWORK
 *
 * Network server without fork/exec.
 * Allows sockets, accept, bind, listen, but no process creation.
 *
 * Includes execve (needed for initial exec) and libc init syscalls.
 * After execve, the binary can't fork new processes to exec into,
 * and the container filesystem only has /app anyway.
 * ================================================================ */
static struct sock_filter seccomp_network[] = {
    SC_CHECK_ARCH,
    SC_LOAD_NR,
    /* Bootstrap: needed for execve()/execveat() + glibc/musl static init.
     * execveat is the runtime's AT_EMPTY_PATH bootstrap (ns.c:1663). */
    SC_JUMP_EQ(SYS_execve, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_execveat, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_arch_prctl, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_set_tid_address, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_set_robust_list, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rseq, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_prlimit64, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_readlinkat, 0, 1),
    SC_ALLOW,
    /* I/O */
    SC_JUMP_EQ(SYS_read, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_write, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_readv, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_writev, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_close, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_dup2, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_dup3, 0, 1),
    SC_ALLOW,
    /* Network */
    SC_JUMP_EQ(SYS_socket, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_bind, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_listen, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_accept, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_accept4, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_connect, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_sendto, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_recvfrom, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_sendmsg, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_recvmsg, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_setsockopt, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_getsockopt, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_getsockname, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_getpeername, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_shutdown, 0, 1),
    SC_ALLOW,
    /* Poll/epoll */
    SC_JUMP_EQ(SYS_poll, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_ppoll, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_epoll_create1, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_epoll_ctl, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_epoll_wait, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_select, 0, 1),
    SC_ALLOW,
    /* Memory */
    SC_JUMP_EQ(SYS_brk, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_mmap, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_munmap, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_mprotect, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_mremap, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_madvise, 0, 1),
    SC_ALLOW,
    /* Signals/process */
    SC_JUMP_EQ(SYS_exit, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_exit_group, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rt_sigreturn, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rt_sigaction, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_rt_sigprocmask, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_sigaltstack, 0, 1),
    SC_ALLOW,
    /* File (read-only, no open with write) */
    SC_JUMP_EQ(SYS_openat, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_fstat, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_newfstatat, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_lseek, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_fcntl, 0, 1),
    SC_ALLOW,
    /*
     * ioctl with argument filtering: only allow safe network ioctls.
     * If syscall != ioctl, skip the arg-check block entirely.
     * FIONREAD  (0x541B) = bytes available for read
     * FIONBIO   (0x5421) = set non-blocking mode
     * TIOCGWINSZ (0x5413) = get terminal window size (used by libc)
     *
     * Jump offsets: jt = forward on match, jf = forward on mismatch
     * Layout (instructions after the ioctl check):
     *   +0: LOAD_ARG(1)
     *   +1: FIONREAD?   jt=3 → ALLOW, jf=0 → next
     *   +2: FIONBIO?    jt=2 → ALLOW, jf=0 → next
     *   +3: TIOCGWINSZ? jt=1 → ALLOW, jf=0 → KILL
     *   +4: SC_KILL
     *   +5: SC_ALLOW
     *   +6: SC_LOAD_NR (restore for subsequent checks)
     */
    SC_JUMP_EQ(SYS_ioctl, 0, 7),
    SC_LOAD_ARG(1),
    SC_JUMP_EQ(FIONREAD, 3, 0),
    SC_JUMP_EQ(FIONBIO, 2, 0),
    SC_JUMP_EQ(TIOCGWINSZ, 1, 0),
    SC_KILL,
    SC_ALLOW,
    SC_LOAD_NR,
    /* Time */
    SC_JUMP_EQ(SYS_clock_gettime, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_gettimeofday, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_nanosleep, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_clock_nanosleep, 0, 1),
    SC_ALLOW,
    /* Misc */
    SC_JUMP_EQ(SYS_getpid, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_gettid, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_getrandom, 0, 1),
    SC_ALLOW,
    SC_JUMP_EQ(SYS_futex, 0, 1),
    SC_ALLOW,
    SC_KILL,
};

/* ================================================================
 * Profile: DEFAULT
 *
 * General-purpose server. Like NETWORK but also allows fork,
 * exec (within the container), and filesystem writes.
 *
 * Blocks dangerous syscalls: reboot, kexec, module loading,
 * mount/umount, ptrace, personality changes.
 *
 * This is a DENYLIST approach (block known-dangerous, allow rest)
 * which is more permissive but compatible with most binaries.
 * ================================================================ */
static struct sock_filter seccomp_default[] = {
    SC_CHECK_ARCH,
    SC_LOAD_NR,
    /* Block dangerous syscalls */
    SC_JUMP_EQ(SYS_reboot, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_kexec_load, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_kexec_file_load, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_init_module, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_finit_module, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_delete_module, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_mount, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_umount2, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_pivot_root, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_ptrace, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_personality, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_swapon, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_swapoff, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_sethostname, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_setdomainname, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_acct, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_unshare, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_setns, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_keyctl, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_add_key, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_request_key, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_bpf, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_userfaultfd, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_perf_event_open, 0, 1),
    SC_KILL,
    /* io_uring — massive kernel attack surface, blocked by
     * Docker, Podman, and Google. Not needed by any workload. */
    SC_JUMP_EQ(425 /* io_uring_setup */, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(426 /* io_uring_enter */, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(427 /* io_uring_register */, 0, 1),
    SC_KILL,
    /* process_vm_readv/writev — cross-process memory access.
     * Mitigated by CAP_SYS_PTRACE drop + PID namespace, but
     * blocked explicitly for defense in depth. */
    SC_JUMP_EQ(SYS_process_vm_readv, 0, 1),
    SC_KILL,
    SC_JUMP_EQ(SYS_process_vm_writev, 0, 1),
    SC_KILL,
    /* Everything else: allow */
    SC_ALLOW,
};

/* ================================================================
 * Apply seccomp filter
 * ================================================================ */

/*
 * erlkoenig_apply_seccomp - Install a seccomp-BPF filter.
 * @profile:	Profile ID (SECCOMP_PROFILE_*)
 *
 * Must be called BEFORE execve(). Sets PR_SET_NO_NEW_PRIVS first
 * (required by seccomp for unprivileged processes).
 *
 * Returns 0 on success, -errno on failure.
 * Profile 0 (NONE) is a no-op.
 */
static int erlkoenig_apply_seccomp(uint8_t profile)
{
	struct sock_filter *filter;
	size_t filter_len;
	struct sock_fprog prog;

	switch (profile) {
	case SECCOMP_PROFILE_NONE:
		return 0;
	case SECCOMP_PROFILE_DEFAULT:
		filter = seccomp_default;
		filter_len =
		    sizeof(seccomp_default) / sizeof(seccomp_default[0]);
		break;
	case SECCOMP_PROFILE_STRICT:
		filter = seccomp_strict;
		filter_len = sizeof(seccomp_strict) / sizeof(seccomp_strict[0]);
		break;
	case SECCOMP_PROFILE_NETWORK:
		filter = seccomp_network;
		filter_len =
		    sizeof(seccomp_network) / sizeof(seccomp_network[0]);
		break;
	default:
		LOG_ERR("unknown seccomp profile: %u", profile);
		return -EINVAL;
	}

	/*
	 * PR_SET_NO_NEW_PRIVS is required before installing a seccomp
	 * filter. It ensures the process (and children) can't gain
	 * privileges via execve of setuid/setgid binaries.
	 * Also set in erlkoenig_drop_caps() — idempotent, kept as
	 * defense-in-depth in case caps are not dropped.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		LOG_SYSCALL("prctl(NO_NEW_PRIVS)");
		return -errno;
	}

	/*
	 * Debug mode: replace SECCOMP_RET_KILL_PROCESS with
	 * SECCOMP_RET_LOG so denied syscalls appear in dmesg/auditd
	 * without killing the process. Activated by setting
	 * ERLKOENIG_SECCOMP_LOG=1 in the environment.
	 *
	 * SECURITY: copy to stack buffer — never mutate the static
	 * filter arrays. Once mutated, they stay in LOG mode for the
	 * lifetime of the process, even if the env var is removed.
	 */
	struct sock_filter local_filter[256];

	if (filter_len > sizeof(local_filter) / sizeof(local_filter[0])) {
		LOG_ERR("seccomp filter too large: %zu", filter_len);
		return -E2BIG;
	}
	memcpy(local_filter, filter, filter_len * sizeof(local_filter[0]));

	{
		const char *debug_env = getenv("ERLKOENIG_SECCOMP_LOG");

		if (debug_env && debug_env[0] == '1') {
			for (size_t i = 0; i < filter_len; i++) {
				if (local_filter[i].code == (BPF_RET | BPF_K) &&
				    local_filter[i].k ==
					SECCOMP_RET_KILL_PROCESS)
					local_filter[i].k = SECCOMP_RET_LOG;
			}
			LOG_WARN("seccomp debug mode: LOG instead of KILL");
		}
	}

	prog.len = (unsigned short)filter_len;
	prog.filter = local_filter;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		LOG_SYSCALL("prctl(SECCOMP)");
		return -errno;
	}

	LOG_INFO("seccomp profile %u installed (%zu instructions)", profile,
		 filter_len);
	return 0;
}

#endif /* ERLKOENIG_SECCOMP_H */
