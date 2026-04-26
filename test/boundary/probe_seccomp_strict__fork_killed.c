/*
 * probe_seccomp_strict__fork_killed.c
 *
 * Asserts: fork()/clone() with no namespace flags is NOT in STRICT
 * allowlist. STRICT is "pure compute, no fork".
 *
 * fork() on Linux uses clone() under the hood. Neither clone nor
 * clone3 is in the STRICT allowlist.
 *
 * Expected: SIGSYS kill.
 * Profile: STRICT.
 */

#include <unistd.h>

#include "probe_common.h"

int main(void)
{
	pid_t p = fork();
	PROBE_FINDING("fork() returned %d errno=%d (%s) under STRICT — "
		      "expected SIGSYS kill",
		      (int)p, errno, strerror(errno));
}
