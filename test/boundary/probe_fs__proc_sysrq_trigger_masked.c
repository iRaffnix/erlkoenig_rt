/*
 * probe_fs__proc_sysrq_trigger_masked.c
 *
 * Asserts: /proc/sysrq-trigger is masked. Writing to it can trigger
 * host-wide actions (sync, reboot, OOM kill). Bind-mount to /dev/null
 * makes writes silently no-op (or denied).
 *
 * The probe attempts an O_WRONLY open WITHOUT writing — opening for
 * read first is enough to verify the mask state. We do NOT write
 * 'b' to the file even if it opens; that would be exercising a leak
 * if one existed.
 *
 * Profile: DEFAULT.
 */

#include <fcntl.h>
#include <sys/stat.h>

#include "probe_common.h"

int main(void)
{
	struct stat st;
	if (stat("/proc/sysrq-trigger", &st) != 0) {
		if (errno == ENOENT)
			PROBE_OK("/proc/sysrq-trigger not present");
		PROBE_FINDING("/proc/sysrq-trigger stat failed: %s",
			      strerror(errno));
	}

	/* If the bind-mount to /dev/null is active, this opens but the
	 * underlying inode is the character device /dev/null, which
	 * silently absorbs writes. We assert the bind-mount IS active
	 * by checking that the inode/device matches /dev/null. */
	struct stat null_st;
	if (stat("/dev/null", &null_st) == 0) {
		if (st.st_dev == null_st.st_dev && st.st_ino == null_st.st_ino)
			PROBE_OK("/proc/sysrq-trigger bind-mounted from /dev/null");
	}

	/* If we got here, the inode does NOT match /dev/null. Either
	 * /dev/null doesn't exist (very unusual) or sysrq-trigger is
	 * NOT bound to it.  Open it RDONLY and check whether reading
	 * returns useful data — sysrq-trigger does not normally allow
	 * reading, so EINVAL/EACCES is also acceptable.  Anything else
	 * means the mask is incomplete. */
	int fd = open("/proc/sysrq-trigger", O_RDONLY);
	if (fd < 0) {
		if (errno == EACCES || errno == EPERM || errno == EINVAL)
			PROBE_OK("/proc/sysrq-trigger inaccessible: %s",
				 strerror(errno));
		PROBE_FINDING("/proc/sysrq-trigger open returned %s",
			      strerror(errno));
	}
	close(fd);
	PROBE_FINDING("/proc/sysrq-trigger opened RDONLY without bind-to-null "
		      "(dev=%lu ino=%lu, /dev/null dev=%lu ino=%lu)",
		      (unsigned long)st.st_dev, (unsigned long)st.st_ino,
		      (unsigned long)null_st.st_dev,
		      (unsigned long)null_st.st_ino);
}
