/*
 * probe_seccomp_default__process_vm_readv_killed.c
 *
 * Asserts: process_vm_readv() is in DEFAULT denylist (seccomp.h:443).
 * Defence-in-depth alongside CAP_SYS_PTRACE drop and PID namespace.
 *
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_process_vm_readv, 0, NULL, 0, NULL, 0, 0);
	PROBE_FINDING("process_vm_readv() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
