/*
 * probe_pidns__init_low_pid.c
 *
 * Asserts: container PID is 1 or 2 (mini-init at PID 1, app at PID 2
 * per ns.c:1571). If getpid() returns a high PID, we're not actually
 * in a separate PID namespace.
 *
 * Profile: DEFAULT.
 */

#include <unistd.h>

#include "probe_common.h"

int main(void)
{
	pid_t pid = getpid();
	if (pid > 10)
		PROBE_FINDING("getpid() = %d — expected 1 or 2 inside container "
			      "PID namespace; high PID indicates namespace "
			      "isolation broken or probe spawned via shell",
			      (int)pid);
	PROBE_OK("getpid() = %d (in container PID namespace)", (int)pid);
}
