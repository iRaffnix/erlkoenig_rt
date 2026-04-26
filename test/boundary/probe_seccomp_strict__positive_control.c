/*
 * probe_seccomp_strict__positive_control.c
 *
 * Positive control for STRICT seccomp profile: a probe that does
 * nothing forbidden should run to completion. If THIS probe gets
 * killed by SIGSYS, the harness has a bug — most likely a libc
 * static-init syscall not in the STRICT allowlist (seccomp.h:133).
 *
 * Profile: STRICT.
 * Expected: exit 0.
 */

#include "probe_common.h"

int main(void)
{
	PROBE_OK("strict positive control — libc init survived seccomp filter");
}
