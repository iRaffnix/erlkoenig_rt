/*
 * probe_pidns__cannot_see_host_pids.c
 *
 * Asserts: kill(host_pid, 0) for very high PIDs returns ESRCH, not
 * EPERM. EPERM would mean the host PID exists in our namespace and we
 * lack permission; ESRCH means the PID does not exist in our view.
 *
 * Tries PIDs 100, 1000, 10000 — at least one should exist on a typical
 * host with normal init+services running. Inside the container's
 * PID namespace, those host PIDs are invisible → ESRCH.
 *
 * Profile: DEFAULT.
 */

#include <signal.h>

#include "probe_common.h"

int main(void)
{
	int probe_pids[] = {100, 1000, 10000};
	int saw_esrch = 0;
	int saw_eperm = 0;

	for (size_t i = 0; i < sizeof(probe_pids) / sizeof(probe_pids[0]);
	     i++) {
		int r = kill(probe_pids[i], 0);
		if (r == 0)
			PROBE_FINDING(
			    "kill(%d, 0) succeeded — saw a process that "
			    "should be host-only",
			    probe_pids[i]);
		if (errno == EPERM)
			saw_eperm = 1;
		if (errno == ESRCH)
			saw_esrch = 1;
	}

	if (saw_eperm && !saw_esrch)
		PROBE_FINDING("kill() returned EPERM for host PIDs but never "
			      "ESRCH — host PIDs visible in container namespace");

	PROBE_OK("host PIDs invisible in container PID namespace");
}
