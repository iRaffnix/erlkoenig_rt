/*
 * probe_seccomp_default__bpf_killed.c
 *
 * Asserts: bpf() is in DEFAULT denylist (seccomp.h:426). This is the
 * primary mitigation against eBPF verifier bugs (CVE-2022-23222 class).
 *
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_bpf, 0, NULL, 0);
	PROBE_FINDING("bpf() returned %ld errno=%d (%s) — expected SIGSYS kill",
		      r, errno, strerror(errno));
}
