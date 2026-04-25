/*
 * probe_seccomp_strict__bpf_killed.c
 *
 * Asserts: bpf() is NOT in the STRICT allowlist (it's an explicit
 * deny in DEFAULT, and not listed in STRICT's allowlist either).
 *
 * Expected: SIGSYS kill.
 * Profile: STRICT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_bpf, 0, NULL, 0);
	PROBE_FINDING("bpf() returned %ld errno=%d (%s) under STRICT — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
