/*
 * probe_fs__proc_keys_masked.c
 *
 * Asserts: /proc/keys is masked. Same pattern as kcore.
 * Profile: DEFAULT.
 */

#include <fcntl.h>
#include <sys/stat.h>

#include "probe_common.h"

int main(void)
{
	struct stat st;
	if (stat("/proc/keys", &st) != 0) {
		if (errno == ENOENT)
			PROBE_OK("/proc/keys not present");
		PROBE_FINDING("/proc/keys stat failed: %s", strerror(errno));
	}

	int fd = open("/proc/keys", O_RDONLY);
	if (fd < 0) {
		if (errno == EACCES || errno == EPERM)
			PROBE_OK("/proc/keys open denied: %s", strerror(errno));
		PROBE_FINDING("/proc/keys open failed unexpectedly: %s",
			      strerror(errno));
	}

	char buf[64];
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n > 0)
		PROBE_FINDING(
		    "/proc/keys opened AND read %zd bytes — keyring leak", n);

	PROBE_OK("/proc/keys masked");
}
