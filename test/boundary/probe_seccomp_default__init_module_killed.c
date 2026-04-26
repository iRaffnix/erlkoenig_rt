/*
 * probe_seccomp_default__init_module_killed.c
 *
 * Asserts: init_module() is in DEFAULT denylist (seccomp.h:390).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_init_module, NULL, 0, "");
	PROBE_FINDING("init_module() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
