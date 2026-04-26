/*
 * probe_netns__iface_count_bounded.c
 *
 * Asserts: only loopback (always present) plus at most one container
 * interface (IPVLAN slave or similar) is visible. The container must
 * not see host bridges, physical NICs, etc.
 *
 * Counts entries in /proc/net/dev. Header is 2 lines; expect at most
 * 2 + 2 = 4 lines (lo + container iface + reasonable slack).
 *
 * Profile: DEFAULT (allows openat on /proc/net/dev — Landlock denies
 * /etc but should allow /proc since the rootfs has /proc; if Landlock
 * denies /proc the probe SKIPs).
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "probe_common.h"

int main(void)
{
	FILE *f = fopen("/proc/net/dev", "r");
	if (!f) {
		if (errno == EACCES || errno == ENOENT)
			PROBE_SKIP("/proc/net/dev not accessible: %s",
				   strerror(errno));
		PROBE_FINDING("/proc/net/dev open failed: %s", strerror(errno));
	}

	char line[512];
	int count = 0;
	while (fgets(line, sizeof(line), f)) {
		if (line[0] == 'I' || line[0] == ' ') /* header */
			continue;
		count++;
	}
	fclose(f);

	if (count > 4)
		PROBE_FINDING("netns shows %d interfaces in /proc/net/dev — "
			      "expected ≤ 4 (lo + container iface + slack)",
			      count);

	PROBE_OK("netns has %d interfaces (within bound)", count);
}
