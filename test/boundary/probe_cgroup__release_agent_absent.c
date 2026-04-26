/*
 * probe_cgroup__release_agent_absent.c
 *
 * Asserts: /sys/fs/cgroup/release_agent is not present (cgroup v2
 * does not have release_agent — it was a v1-only feature exploited in
 * CVE-2022-0492). The container should be cgroup v2 only.
 *
 * Profile: DEFAULT.
 */

#include <sys/stat.h>

#include "probe_common.h"

int main(void)
{
	struct stat st;
	if (stat("/sys/fs/cgroup/release_agent", &st) != 0) {
		if (errno == ENOENT || errno == EACCES)
			PROBE_OK("release_agent not present (%s)",
				 strerror(errno));
		PROBE_FINDING("stat release_agent failed unexpectedly: %s",
			      strerror(errno));
	}
	PROBE_FINDING("release_agent file present in container — cgroup v1 "
		      "or hybrid setup, exploitable per CVE-2022-0492 class");
}
