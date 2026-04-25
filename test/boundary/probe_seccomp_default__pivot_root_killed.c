/*
 * probe_seccomp_default__pivot_root_killed.c
 *
 * Asserts: pivot_root() is in DEFAULT denylist (seccomp.h:400).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_pivot_root, "/", "/");
	PROBE_FINDING("pivot_root() returned %ld errno=%d (%s) — expected "
		      "SIGSYS kill",
		      r, errno, strerror(errno));
}
