/*
 * probe_seccomp_default__io_uring_setup_killed.c
 *
 * Asserts: io_uring_setup() is in DEFAULT denylist (seccomp.h:434).
 * io_uring is blocked by Docker, Podman, Google due to large kernel
 * attack surface and history of bugs.
 *
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/syscall.h>

#include "probe_common.h"

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

int main(void)
{
	long r = syscall(SYS_io_uring_setup, 1, NULL);
	PROBE_FINDING("io_uring_setup() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
