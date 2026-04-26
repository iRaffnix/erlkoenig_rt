/*
 * probe_seccomp_default__mount_killed.c
 *
 * Asserts: under DEFAULT seccomp, mount() is in the denylist
 * (seccomp.h:396) and the call triggers SECCOMP_RET_KILL_PROCESS.
 *
 * Expected outcome (driver checks WTERMSIG): killed by SIGSYS.
 * If the call returns at all, that is a finding.
 *
 * Profile: DEFAULT.
 */

#include <sys/mount.h>

#include "probe_common.h"

int main(void)
{
	int r = mount("tmpfs", "/tmp", "tmpfs", 0, "size=1m");
	PROBE_FINDING("mount() returned %d errno=%d (%s) — expected "
		      "SIGSYS kill via seccomp DEFAULT denylist",
		      r, errno, strerror(errno));
}
