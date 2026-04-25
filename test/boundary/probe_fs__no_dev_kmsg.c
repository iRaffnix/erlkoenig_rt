/*
 * probe_fs__no_dev_kmsg.c
 *
 * Asserts: /dev/kmsg is not readable from inside the container.
 * /dev/kmsg leaks the kernel ring buffer (host-wide kernel logs),
 * which is an info disclosure across the boundary.
 *
 * Profile: DEFAULT.
 */

#include <fcntl.h>
#include <sys/stat.h>

#include "probe_common.h"

int main(void)
{
	struct stat st;
	if (stat("/dev/kmsg", &st) != 0) {
		if (errno == ENOENT)
			PROBE_OK("/dev/kmsg not present");
		PROBE_FINDING("/dev/kmsg stat failed: %s", strerror(errno));
	}

	int fd = open("/dev/kmsg", O_RDONLY);
	if (fd < 0) {
		if (errno == EACCES || errno == EPERM)
			PROBE_OK("/dev/kmsg open denied: %s", strerror(errno));
		PROBE_FINDING("/dev/kmsg open failed unexpectedly: %s",
			      strerror(errno));
	}

	/* If we opened, the file IS exposed. Reading would confirm,
	 * but the open itself is the breach. Don't read. */
	close(fd);
	PROBE_FINDING("/dev/kmsg opened RDONLY — kernel log leak path");
}
