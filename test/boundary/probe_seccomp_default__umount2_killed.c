/*
 * probe_seccomp_default__umount2_killed.c
 *
 * Asserts: umount2() is in DEFAULT denylist (seccomp.h:398).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/mount.h>

#include "probe_common.h"

int main(void)
{
	int r = umount2("/tmp", 0);
	PROBE_FINDING("umount2() returned %d errno=%d (%s) — expected "
		      "SIGSYS kill",
		      r, errno, strerror(errno));
}
