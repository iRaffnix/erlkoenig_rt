/*
 * syscall_fork.c - Versucht fork() nach kurzem Sleep.
 *
 * Dient als Seccomp-Testbinary: "strict" und "network" Profile
 * blockieren fork/clone -- der Prozess wird mit SIGSYS getoetet.
 * Mit "default" oder "none" ueberlebt er.
 *
 * Build: gcc -static -o ../build/syscall_fork syscall_fork.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	dprintf(STDERR_FILENO, "syscall_fork: attempting fork()...\n");
	sleep(1);

	pid_t pid = fork();
	if (pid < 0) {
		dprintf(STDERR_FILENO, "syscall_fork: fork() failed\n");
		return 1;
	}

	if (pid == 0) {
		/* child */
		dprintf(STDERR_FILENO, "syscall_fork: child alive (pid %d)\n",
			getpid());
		_exit(0);
	}

	/* parent */
	waitpid(pid, NULL, 0);
	dprintf(STDERR_FILENO, "syscall_fork: fork() succeeded!\n");
	sleep(2);
	return 0;
}
