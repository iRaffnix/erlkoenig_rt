/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * ek_fault_shim.c — LD_PRELOAD syscall fault injector.
 *
 * Fails the Nth call to a named syscall with a chosen errno, so we can
 * exercise error-cleanup paths in privileged code under ASan/UBSan.
 *
 * Environment variables (all honoured once, via constructor):
 *   EK_FAULT_SYSCALL=name  — target name (see TABLE below)
 *   EK_FAULT_NTH=N         — 1-based; fail the N-th call to that target
 *   EK_FAULT_ERRNO=code    — numeric errno (default ENOMEM=12)
 *   EK_FAULT_LOG=1         — log injected calls to stderr
 *
 * Targets:
 *   glibc wrappers:  mount umount2 mkdir chdir symlink unshare setns
 *                    prctl rmdir open openat close
 *   raw syscall():   pivot_root clone3 setns_raw
 *
 * Build:
 *   gcc -fPIC -shared -D_GNU_SOURCE -g -O0 \
 *       -o ek_fault_shim.so ek_fault_shim.c -ldl
 *
 * Use:
 *   EK_FAULT_SYSCALL=mount EK_FAULT_NTH=3 EK_FAULT_ERRNO=28 \
 *     LD_PRELOAD=./ek_fault_shim.so ./test_container_setup
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static const char *target_name;
static long target_nth;
static int target_errno = ENOMEM;
static int log_enabled;
static const char *target_path_substr;

#define CTR(sc) static atomic_long n_##sc
CTR(mount); CTR(umount2); CTR(mkdir); CTR(chdir); CTR(symlink);
CTR(unshare); CTR(setns); CTR(prctl); CTR(rmdir); CTR(open);
CTR(openat); CTR(close); CTR(pivot_root); CTR(clone3);
CTR(sendto); CTR(recvfrom); CTR(send); CTR(recv); CTR(ioctl);
#undef CTR

__attribute__((constructor))
static void ek_fault_init(void)
{
	target_name = getenv("EK_FAULT_SYSCALL");
	const char *n = getenv("EK_FAULT_NTH");
	const char *e = getenv("EK_FAULT_ERRNO");

	target_nth = n ? strtol(n, NULL, 10) : 0;
	if (e)
		target_errno = atoi(e);
	log_enabled = getenv("EK_FAULT_LOG") ? 1 : 0;
	target_path_substr = getenv("EK_FAULT_PATH");  /* substring filter */
}

/* Check path-substring filter. If EK_FAULT_PATH is set, only paths that
 * contain the substring are candidates for injection. */
static inline int path_matches(const char *path)
{
	if (!target_path_substr || !*target_path_substr)
		return 1;
	return path && strstr(path, target_path_substr) != NULL;
}

static inline int should_fail(const char *name, atomic_long *counter)
{
	if (!target_name || target_nth <= 0)
		return 0;
	if (strcmp(target_name, name) != 0)
		return 0;
	long n = atomic_fetch_add(counter, 1) + 1;
	if (n != target_nth)
		return 0;
	if (log_enabled)
		fprintf(stderr, "[FAULT] errno=%d injected on %s call #%ld\n",
			target_errno, name, n);
	return 1;
}

#define WRAP(ret, fn, proto_args, proto_cast, args_forward)                    \
	ret fn proto_args                                                      \
	{                                                                      \
		static ret (*real) proto_cast;                                 \
		if (!real)                                                     \
			real = dlsym(RTLD_NEXT, #fn);                          \
		if (should_fail(#fn, &n_##fn)) {                               \
			errno = target_errno;                                  \
			return -1;                                             \
		}                                                              \
		return real args_forward;                                      \
	}

int mount(const char *src, const char *tgt, const char *fst,
	  unsigned long fl, const void *d)
{
	static int (*real)(const char *, const char *, const char *,
			   unsigned long, const void *);
	if (!real)
		real = dlsym(RTLD_NEXT, "mount");
	long n = atomic_fetch_add(&n_mount, 1) + 1;
	if (log_enabled && target_name && strcmp(target_name, "mount") == 0)
		fprintf(stderr, "[FAULT:trace] mount#%ld src=%s tgt=%s fs=%s fl=0x%lx\n",
			n, src ? src : "(null)", tgt ? tgt : "(null)",
			fst ? fst : "(null)", fl);
	if (target_name && strcmp(target_name, "mount") == 0 && n == target_nth) {
		if (log_enabled)
			fprintf(stderr,
				"[FAULT] errno=%d injected on mount call #%ld (src=%s tgt=%s fs=%s fl=0x%lx)\n",
				target_errno, n, src ? src : "(null)",
				tgt ? tgt : "(null)", fst ? fst : "(null)", fl);
		errno = target_errno;
		return -1;
	}
	return real(src, tgt, fst, fl, d);
}

WRAP(int, umount2, (const char *t, int f), (const char *, int), (t, f))
WRAP(int, mkdir, (const char *p, mode_t m), (const char *, mode_t), (p, m))
WRAP(int, chdir, (const char *p), (const char *), (p))
WRAP(int, symlink, (const char *t, const char *l), (const char *, const char *), (t, l))
WRAP(int, unshare, (int f), (int), (f))
WRAP(int, setns, (int fd, int t), (int, int), (fd, t))
WRAP(int, rmdir, (const char *p), (const char *), (p))

int prctl(int option, unsigned long a2, unsigned long a3,
	  unsigned long a4, unsigned long a5)
{
	static int (*real)(int, unsigned long, unsigned long, unsigned long,
			   unsigned long);
	if (!real)
		real = dlsym(RTLD_NEXT, "prctl");
	if (should_fail("prctl", &n_prctl)) {
		errno = target_errno;
		return -1;
	}
	return real(option, a2, a3, a4, a5);
}

/* open/openat are variadic (3rd arg is mode when O_CREAT) — handle both */
int open(const char *path, int flags, ...)
{
	static int (*real2)(const char *, int);
	static int (*real3)(const char *, int, mode_t);
	if (!real2) {
		real2 = dlsym(RTLD_NEXT, "open");
		real3 = (void *)real2;
	}
	if (path_matches(path) && should_fail("open", &n_open)) {
		if (log_enabled)
			fprintf(stderr,
				"[FAULT] errno=%d injected on open path=%s\n",
				target_errno, path ? path : "(null)");
		errno = target_errno;
		return -1;
	}
	if (flags & O_CREAT) {
		va_list ap;
		mode_t m;
		va_start(ap, flags);
		m = va_arg(ap, mode_t);
		va_end(ap);
		return real3(path, flags, m);
	}
	return real2(path, flags);
}

int openat(int dirfd, const char *path, int flags, ...)
{
	static int (*real2)(int, const char *, int);
	static int (*real3)(int, const char *, int, mode_t);
	if (!real2) {
		real2 = dlsym(RTLD_NEXT, "openat");
		real3 = (void *)real2;
	}
	if (should_fail("openat", &n_openat)) {
		errno = target_errno;
		return -1;
	}
	if (flags & O_CREAT) {
		va_list ap;
		mode_t m;
		va_start(ap, flags);
		m = va_arg(ap, mode_t);
		va_end(ap);
		return real3(dirfd, path, flags, m);
	}
	return real2(dirfd, path, flags);
}

/* Netlink + socket I/O hooks — for netcfg / nft comms fault injection */

#include <sys/socket.h>

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest, socklen_t addrlen)
{
	static ssize_t (*real)(int, const void *, size_t, int,
			       const struct sockaddr *, socklen_t);
	if (!real)
		real = dlsym(RTLD_NEXT, "sendto");
	if (should_fail("sendto", &n_sendto)) {
		errno = target_errno;
		return -1;
	}
	return real(sockfd, buf, len, flags, dest, addrlen);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src, socklen_t *addrlen)
{
	static ssize_t (*real)(int, void *, size_t, int, struct sockaddr *,
			       socklen_t *);
	if (!real)
		real = dlsym(RTLD_NEXT, "recvfrom");
	if (should_fail("recvfrom", &n_recvfrom)) {
		errno = target_errno;
		return -1;
	}
	return real(sockfd, buf, len, flags, src, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	static ssize_t (*real)(int, const void *, size_t, int);
	if (!real)
		real = dlsym(RTLD_NEXT, "send");
	if (should_fail("send", &n_send)) {
		errno = target_errno;
		return -1;
	}
	return real(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	static ssize_t (*real)(int, void *, size_t, int);
	if (!real)
		real = dlsym(RTLD_NEXT, "recv");
	if (should_fail("recv", &n_recv)) {
		errno = target_errno;
		return -1;
	}
	return real(sockfd, buf, len, flags);
}

int ioctl(int fd, unsigned long req, ...)
{
	static int (*real)(int, unsigned long, void *);
	if (!real)
		real = dlsym(RTLD_NEXT, "ioctl");
	va_list ap;
	void *arg;
	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (should_fail("ioctl", &n_ioctl)) {
		errno = target_errno;
		return -1;
	}
	return real(fd, req, arg);
}

/*
 * syscall() wrapper — intercepts raw syscalls that don't have a glibc
 * wrapper we're hooking (pivot_root, clone3). Forwards everything else.
 */
long syscall(long nr, ...)
{
	va_list ap;
	long a[6];

	va_start(ap, nr);
	a[0] = va_arg(ap, long);
	a[1] = va_arg(ap, long);
	a[2] = va_arg(ap, long);
	a[3] = va_arg(ap, long);
	a[4] = va_arg(ap, long);
	a[5] = va_arg(ap, long);
	va_end(ap);

	switch (nr) {
#ifdef SYS_pivot_root
	case SYS_pivot_root:
		if (should_fail("pivot_root", &n_pivot_root)) {
			errno = target_errno;
			return -1;
		}
		break;
#endif
#ifdef SYS_clone3
	case SYS_clone3:
		if (should_fail("clone3", &n_clone3)) {
			errno = target_errno;
			return -1;
		}
		break;
#endif
	default:
		break;
	}

	static long (*real)(long, long, long, long, long, long, long);
	if (!real)
		real = dlsym(RTLD_NEXT, "syscall");
	return real(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}
