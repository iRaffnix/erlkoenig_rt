/*
 * probe_nnp__no_new_privs_set.c
 *
 * Asserts: PR_GET_NO_NEW_PRIVS returns 1 — the runtime set the flag
 * before seccomp/Landlock and locked it.
 *
 * Profile: DEFAULT.
 */

#include <sys/prctl.h>

#include "probe_common.h"

int main(void)
{
	int v = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (v < 0)
		PROBE_FINDING("PR_GET_NO_NEW_PRIVS failed: %s",
			      strerror(errno));
	if (v != 1)
		PROBE_FINDING("PR_GET_NO_NEW_PRIVS = %d, expected 1", v);
	PROBE_OK("NO_NEW_PRIVS = 1");
}
