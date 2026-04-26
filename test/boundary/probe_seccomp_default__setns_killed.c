/*
 * probe_seccomp_default__setns_killed.c
 *
 * Asserts: setns() is in DEFAULT denylist (seccomp.h:418).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sched.h>
#include <fcntl.h>

#include "probe_common.h"

int main(void)
{
	/* fd doesn't matter; seccomp checks the call before the fd */
	int r = setns(0, 0);
	PROBE_FINDING("setns() returned %d errno=%d (%s) — expected "
		      "SIGSYS kill",
		      r, errno, strerror(errno));
}
