/*
 * probe_seccomp_default__keyctl_killed.c
 *
 * Asserts: keyctl() is in DEFAULT denylist (seccomp.h:420). Kernel
 * keyring operations have been a recurring exploit surface.
 *
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_keyctl, 0, 0, 0, 0, 0);
	PROBE_FINDING("keyctl() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
