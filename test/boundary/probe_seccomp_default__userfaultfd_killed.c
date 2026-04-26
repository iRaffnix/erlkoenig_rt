/*
 * probe_seccomp_default__userfaultfd_killed.c
 *
 * Asserts: userfaultfd() is in DEFAULT denylist (seccomp.h:428).
 * Userfaultfd has been weaponised to widen race windows in
 * heap-corruption / use-after-free kernel bugs.
 *
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	long r = syscall(SYS_userfaultfd, 0);
	PROBE_FINDING("userfaultfd() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
