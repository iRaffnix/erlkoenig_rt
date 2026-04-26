/*
 * probe_seccomp_default__ptrace_killed.c
 *
 * Asserts: ptrace() is in DEFAULT denylist (seccomp.h:402). Belt-and-
 * braces alongside CAP_SYS_PTRACE drop and the PID namespace.
 *
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/ptrace.h>

#include "probe_common.h"

int main(void)
{
	long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	PROBE_FINDING("ptrace(PTRACE_TRACEME) returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
