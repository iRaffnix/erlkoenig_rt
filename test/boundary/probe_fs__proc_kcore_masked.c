/*
 * probe_fs__proc_kcore_masked.c
 *
 * Asserts: /proc/kcore is masked per ek_mask_paths (ns.c:1025–1028).
 * Reading from /proc/kcore should yield 0 bytes (bind-mounted from
 * /dev/null) or fail open with ENOENT/EACCES.
 *
 * If the file opens AND read returns >0 bytes, the kernel-memory
 * window is exposed — this is a finding.
 *
 * Profile: DEFAULT.
 */

#include <fcntl.h>
#include <sys/stat.h>

#include "probe_common.h"

int main(void)
{
	struct stat st;
	if (stat("/proc/kcore", &st) != 0) {
		if (errno == ENOENT)
			PROBE_OK("/proc/kcore not present (kernel without it)");
		PROBE_FINDING("/proc/kcore stat failed unexpectedly: %s",
			      strerror(errno));
	}

	int fd = open("/proc/kcore", O_RDONLY);
	if (fd < 0) {
		if (errno == EACCES || errno == EPERM)
			PROBE_OK("/proc/kcore open denied: %s", strerror(errno));
		PROBE_FINDING("/proc/kcore open failed unexpectedly: %s",
			      strerror(errno));
	}

	char buf[64];
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n > 0)
		PROBE_FINDING(
		    "/proc/kcore opened AND read %zd bytes — kernel memory "
		    "leak path active",
		    n);

	PROBE_OK("/proc/kcore masked (read returned %zd)", n);
}
