/*
 * probe_seccomp_default__unshare_killed.c
 *
 * Asserts: unshare() is in DEFAULT denylist (seccomp.h:416).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sched.h>

#include "probe_common.h"

int main(void)
{
	int r = unshare(CLONE_NEWUSER);
	PROBE_FINDING("unshare(CLONE_NEWUSER) returned %d errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
