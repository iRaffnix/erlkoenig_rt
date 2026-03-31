/*
 * syscall_mount.c - Versucht mount() nach kurzem Sleep.
 *
 * Dient als Seccomp-Testbinary: "default" Profil blockiert mount
 * (Denylist), der Prozess wird mit SIGSYS getoetet.
 * Mit "none" ueberlebt er (mount schlaegt trotzdem fehl wegen
 * fehlender Rechte, aber der Prozess lebt weiter).
 *
 * Build: gcc -static -o ../build/syscall_mount syscall_mount.c
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

int main(void)
{
	dprintf(STDERR_FILENO, "syscall_mount: attempting mount()...\n");
	sleep(1);

	/* Attempt to mount proc -- will fail with EPERM normally,
	 * but seccomp kills before the kernel even checks permissions. */
	int ret = mount("proc", "/proc", "proc", 0, NULL);
	if (ret < 0) {
		dprintf(STDERR_FILENO,
			"syscall_mount: mount() returned EPERM "
			"(expected without root, but process survived!)\n");
	} else {
		dprintf(STDERR_FILENO,
			"syscall_mount: mount() succeeded (?!)\n");
		umount("/proc");
	}

	dprintf(STDERR_FILENO, "syscall_mount: process still alive\n");
	sleep(2);
	return 0;
}
