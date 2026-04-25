/*
 * probe_mountns__remount_root_rw_denied.c
 *
 * Asserts: from inside the container, a remount of "/" to RW must be
 * denied. Defence comes from (a) DEFAULT seccomp blocking mount
 * (causes SIGSYS), or (b) cap drop removing CAP_SYS_ADMIN (would
 * cause EPERM if seccomp didn't kill first).
 *
 * Under DEFAULT this is identical to probe_seccomp_default__mount_killed
 * (the seccomp filter triggers first). The probe exists separately to
 * document the mount-NS layer's *intent*: even if seccomp ever stopped
 * blocking mount, cap drop should still keep this denied.
 *
 * Expected: SIGSYS kill (under current DEFAULT). If seccomp is removed
 * the expectation would shift to EPERM.
 *
 * Profile: DEFAULT.
 */

#include <sys/mount.h>

#include "probe_common.h"

int main(void)
{
	int r = mount(NULL, "/", NULL, MS_REMOUNT | MS_BIND, NULL);
	if (r == 0)
		PROBE_FINDING("remount-rw of / SUCCEEDED — boundary leak");
	if (errno == EPERM)
		PROBE_OK("remount-rw of / denied with EPERM (cap drop)");
	PROBE_FINDING("remount-rw returned errno=%d (%s) — expected SIGSYS "
		      "kill or EPERM",
		      errno, strerror(errno));
}
