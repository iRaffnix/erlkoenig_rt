/*
 * probe_seccomp_default__perf_event_open_killed.c
 *
 * Asserts: perf_event_open() is in DEFAULT denylist (seccomp.h:430).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_perf_event_open, NULL, 0, -1, -1, 0);
	PROBE_FINDING("perf_event_open() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
