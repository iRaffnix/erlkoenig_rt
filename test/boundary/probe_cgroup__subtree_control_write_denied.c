/*
 * probe_cgroup__subtree_control_write_denied.c
 *
 * Asserts: write to /sys/fs/cgroup/cgroup.subtree_control fails. The
 * container is in its own cgroup namespace; modifying subtree_control
 * could be an avenue for cgroup-mgmt manipulation.
 *
 * Defence comes from: (a) /sys/fs/cgroup may be RO-mounted or
 * unmounted in the container rootfs; (b) cap drop removes
 * CAP_SYS_RESOURCE; (c) Landlock denies opens outside /app.
 *
 * Profile: DEFAULT.
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "probe_common.h"

int main(void)
{
	const char *p = "/sys/fs/cgroup/cgroup.subtree_control";
	struct stat st;
	if (stat(p, &st) != 0) {
		if (errno == EACCES || errno == ENOENT)
			PROBE_OK("%s not visible/accessible: %s", p,
				 strerror(errno));
		PROBE_FINDING("stat %s failed unexpectedly: %s", p,
			      strerror(errno));
	}

	int fd = open(p, O_WRONLY);
	if (fd >= 0) {
		close(fd);
		PROBE_FINDING("write-open of %s succeeded — cgroup tree-control "
			      "writable from container", p);
	}
	if (errno == EACCES || errno == EROFS || errno == EPERM)
		PROBE_OK("%s write-open denied: %s", p, strerror(errno));
	PROBE_FINDING("write-open of %s returned unexpected errno=%d (%s)", p,
		      errno, strerror(errno));
}
