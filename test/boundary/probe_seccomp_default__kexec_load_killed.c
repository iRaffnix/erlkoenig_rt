/*
 * probe_seccomp_default__kexec_load_killed.c
 *
 * Asserts: kexec_load() is in DEFAULT denylist (seccomp.h:386).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_kexec_load, 0, 0, NULL, 0);
	PROBE_FINDING("kexec_load() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
