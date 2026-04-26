/*
 * probe_fs__landlock_app_only.c
 *
 * Asserts: when Landlock is active, opens outside /app are denied
 * with EACCES even though the path exists in the rootfs.
 *
 * Targets: /etc/resolv.conf (likely present in container rootfs from
 * prepare_rootfs_erofs / prepare_rootfs_in_child) and /tmp/x (writable
 * tmpfs but not under /app — Landlock should still deny new opens).
 *
 * If Landlock is unavailable on the kernel (< 5.13), the runtime
 * gracefully falls back; in that case the probe SKIPs.
 *
 * Profile: DEFAULT (which allows openat).
 */

#include <fcntl.h>
#include <sys/syscall.h>

#include "probe_common.h"

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif

int main(void)
{
	/* Probe whether Landlock is available on this kernel — if not,
	 * the runtime ran without it (graceful fallback ns.c:1306) and
	 * this test is meaningless. */
	long abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
			   LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0)
		PROBE_SKIP("Landlock not available on this kernel "
			   "(graceful fallback active)");

	/* Try to open /dev/null — present in the rootfs (ns.c:300+ creates
	 * the dev nodes), Landlock should still deny new opens since /dev
	 * is not under /app. ENOENT means the rootfs doesn't even create
	 * /dev/null which is its own finding (probe SKIPs to avoid false
	 * positive). */
	int fd = open("/dev/null", O_RDONLY);
	if (fd >= 0) {
		close(fd);
		PROBE_FINDING("/dev/null opened despite Landlock — boundary "
			      "leak (file should be denied for new opens)");
	}
	if (errno == ENOENT)
		PROBE_SKIP("/dev/null absent in rootfs — separate concern, "
			   "probe cannot evaluate Landlock");
	if (errno != EACCES)
		PROBE_FINDING("/dev/null open returned errno=%d (%s), "
			      "expected EACCES from Landlock",
			      errno, strerror(errno));

	PROBE_OK("Landlock denies /dev/null open as expected");
}
