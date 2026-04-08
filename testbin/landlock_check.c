/*
 * landlock_check.c - Verify Landlock filesystem isolation in container.
 *
 * Tries to open files that should be blocked by Landlock:
 *   - /etc/hostname  (should fail with EACCES)
 *   - /proc/self/status (should fail with EACCES)
 *   - /tmp (writable tmpfs — open should succeed or EACCES depending on Landlock)
 *
 * Also verifies:
 *   - stdin/stdout/stderr still work (pre-opened FDs)
 *   - write to stdout works
 *
 * Output on stdout:
 *   BLOCKED /etc/hostname        — Landlock active
 *   OPEN /etc/hostname           — Landlock NOT active
 *   ENOENT /etc/hostname         — File doesn't exist (minimal rootfs)
 *   BLOCKED /proc/self/status    — Landlock active
 *   STDIO OK                     — Pre-opened FDs work
 *   DONE                         — Test completed
 *
 * Build: musl-gcc -static -o landlock_check landlock_check.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void check_path(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd >= 0) {
		printf("OPEN %s\n", path);
		close(fd);
	} else if (errno == EACCES) {
		printf("BLOCKED %s\n", path);
	} else if (errno == ENOENT) {
		printf("ENOENT %s\n", path);
	} else {
		printf("ERROR %s errno=%d %s\n", path, errno, strerror(errno));
	}
	fflush(stdout);
}

static void check_create(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

	if (fd >= 0) {
		printf("CREATED %s\n", path);
		close(fd);
		unlink(path);
	} else if (errno == EACCES) {
		printf("BLOCKED_CREATE %s\n", path);
	} else {
		printf("ERROR_CREATE %s errno=%d %s\n", path, errno,
		       strerror(errno));
	}
	fflush(stdout);
}

int main(void)
{
	/* Test 1: Can we read files? Should be BLOCKED by Landlock */
	check_path("/etc/hostname");
	check_path("/etc/passwd");
	check_path("/proc/self/status");

	/* Test 2: Can we create files? Should be BLOCKED */
	check_create("/tmp/landlock_test");

	/* Test 3: stdin/stdout still work (pre-opened FDs) */
	if (write(STDOUT_FILENO, "STDIO OK\n", 9) == 9) {
		/* good */
	} else {
		_exit(1);
	}

	printf("DONE\n");
	fflush(stdout);
	return 0;
}
