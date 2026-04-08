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

/* Can we create and configure cgroups? (needs delegation) */
static inline bool probe_has_cgroup_delegation(void)
{
	if (!probe_has_cgroup_v2())
		return false;

	/* Find our own cgroup path (same as erlkoenig_cg_detect_base).
	 * We must be able to enable subtree_control AND create children
	 * in our actual cgroup, not just the root. */
	char buf[4096];
	int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return false;
	buf[n] = '\0';

	/* Parse "0::/path\n" */
	char *p = strstr(buf, "0::");
	if (!p)
		return false;
	p += 3;
	char *nl = strchr(p, '\n');
	if (nl) *nl = '\0';

	char base[4096];
	snprintf(base, sizeof(base), "/sys/fs/cgroup%s", p);

	/* Test if we can actually create a child cgroup with working
	 * pids.max. This requires subtree_control delegation which
	 * is not available on all systems (e.g. Hetzner Cloud VPS). */
	char test_cg[4096 + 64];
	snprintf(test_cg, sizeof(test_cg), "%s/ek-cg-probe", base);
	if (mkdir(test_cg, 0755) && errno != EEXIST)
		return false;

	char knob[4096 + 64];
	snprintf(knob, sizeof(knob), "%s/pids.max", test_cg);
	FILE *f = fopen(knob, "we");
	if (!f) {
		rmdir(test_cg);
		return false;
	}
	int ok = (fprintf(f, "100") > 0 && fflush(f) == 0 && !ferror(f));
	fclose(f);
	rmdir(test_cg);
	return ok;
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
