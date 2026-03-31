/*
 * syscall_write_rootfs.c - Versucht ins Rootfs und /tmp zu schreiben.
 *
 * Testet Read-Only Rootfs:
 *   1. Schreibversuch nach /testfile (soll EROFS/EACCES ergeben)
 *   2. Schreibversuch nach /tmp/testfile (soll funktionieren)
 *
 * Build: gcc -static -o ../build/syscall_write_rootfs syscall_write_rootfs.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	int fd;

	/* 1. Try writing to read-only rootfs */
	dprintf(STDERR_FILENO, "rootfs_write: creating /testfile...\n");
	fd = open("/testfile", O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		dprintf(STDERR_FILENO,
			"rootfs_write: /testfile FAILED: %s (expected!)\n",
			strerror(errno));
	} else {
		dprintf(STDERR_FILENO,
			"rootfs_write: /testfile SUCCEEDED (?! rootfs not read-only)\n");
		close(fd);
	}

	/* 2. Try writing to /tmp (should work) */
	dprintf(STDERR_FILENO, "rootfs_write: creating /tmp/testfile...\n");
	fd = open("/tmp/testfile", O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		dprintf(STDERR_FILENO,
			"rootfs_write: /tmp/testfile FAILED: %s\n",
			strerror(errno));
	} else {
		write(fd, "hello from container\n", 21);
		close(fd);
		dprintf(STDERR_FILENO,
			"rootfs_write: /tmp/testfile SUCCEEDED (writable!)\n");
	}

	sleep(2);
	return 0;
}
