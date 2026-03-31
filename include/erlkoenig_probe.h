/*
 * erlkoenig_probe.h - Feature/capability detection for test skipping.
 *
 * Probe functions that detect what the current environment supports.
 * Used by tests to gracefully skip when capabilities are missing
 * (e.g., running without root in CI).
 *
 * Usage:
 *   if (!probe_has_root()) {
 *       printf("SKIP: needs root\n");
 *       return 77;  // automake SKIP convention
 *   }
 */

#ifndef ERLKOENIG_PROBE_H
#define ERLKOENIG_PROBE_H

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Are we running as root (UID 0)? */
static inline bool probe_has_root(void)
{
	return geteuid() == 0;
}

/* Can we create user namespaces? (may be disabled by sysctl) */
static inline bool probe_has_userns(void)
{
	int pid = (int)syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0);

	if (pid == 0)
		_exit(0);
	if (pid > 0) {
		waitpid(pid, NULL, 0);
		return true;
	}
	return false;
}

/* Can we create network namespaces? (needs root or CAP_SYS_ADMIN) */
static inline bool probe_has_netns(void)
{
	if (!probe_has_root())
		return false;
	int pid = (int)syscall(SYS_clone, CLONE_NEWNET | SIGCHLD, 0);

	if (pid == 0)
		_exit(0);
	if (pid > 0) {
		waitpid(pid, NULL, 0);
		return true;
	}
	return false;
}

/* Is cgroup v2 available? */
static inline bool probe_has_cgroup_v2(void)
{
	struct stat st;

	return stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0;
}

/* Is Landlock available? */
static inline bool probe_has_landlock(void)
{
	int v = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
			     1 /* LANDLOCK_CREATE_RULESET_VERSION */);
	return v >= 0;
}

/* Is the current process running under ASan? */
static inline bool probe_running_with_asan(void)
{
#if defined(__SANITIZE_ADDRESS__)
	return true;
#else
	return false;
#endif
}

/* Print test skip info and return 77 (automake skip convention) */
#define SKIP_TEST(reason)                                                      \
	do {                                                                   \
		fprintf(stderr, "SKIP: %s\n", reason);                         \
		return 77;                                                     \
	} while (0)

#define REQUIRE_ROOT()                                                         \
	do {                                                                   \
		if (!probe_has_root())                                         \
			SKIP_TEST("needs root");                               \
	} while (0)

#define REQUIRE_CGROUP_V2()                                                    \
	do {                                                                   \
		if (!probe_has_cgroup_v2())                                    \
			SKIP_TEST("needs cgroup v2");                          \
	} while (0)

#define REQUIRE_LANDLOCK()                                                     \
	do {                                                                   \
		if (!probe_has_landlock())                                     \
			SKIP_TEST("needs landlock");                           \
	} while (0)

#endif /* ERLKOENIG_PROBE_H */
