/*
 * probe_seccomp_strict__openat_killed.c
 *
 * Asserts: openat() is NOT in the STRICT allowlist.
 *
 * Expected: SIGSYS kill.
 * Profile: STRICT.
 */

#include <fcntl.h>
#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
	PROBE_FINDING("openat() returned %ld errno=%d (%s) under STRICT — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
