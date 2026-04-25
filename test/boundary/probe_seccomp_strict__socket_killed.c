/*
 * probe_seccomp_strict__socket_killed.c
 *
 * Asserts: socket() is NOT in the STRICT allowlist (seccomp.h:133).
 * Calling socket() must trigger SECCOMP_RET_KILL_PROCESS.
 *
 * Expected: SIGSYS kill (driver checks WTERMSIG).
 * Profile: STRICT.
 */

#include <sys/socket.h>

#include "probe_common.h"

int main(void)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	PROBE_FINDING("socket() returned fd=%d errno=%d (%s) under STRICT — "
		      "expected SIGSYS kill",
		      s, errno, strerror(errno));
}
