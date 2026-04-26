/*
 * probe_seccomp_default__reboot_killed.c
 *
 * Asserts: reboot() is in DEFAULT denylist (seccomp.h:384).
 * Expected: SIGSYS kill.
 * Profile: DEFAULT.
 */

#include <sys/reboot.h>
#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	/* Use raw syscall — glibc reboot() requires CAP_SYS_BOOT and
	 * may short-circuit with EPERM before even invoking the syscall.
	 */
	long r = syscall(SYS_reboot, 0xfee1dead, 672274793,
			 RB_AUTOBOOT, NULL);
	PROBE_FINDING("reboot() returned %ld errno=%d (%s) — "
		      "expected SIGSYS kill",
		      r, errno, strerror(errno));
}
