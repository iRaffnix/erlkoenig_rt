/*
 * probe_netns__no_raw_socket.c
 *
 * Asserts: AF_INET SOCK_RAW socket creation must fail (no CAP_NET_RAW).
 *
 * Profile: DEFAULT.
 */

#include <netinet/in.h>
#include <sys/socket.h>

#include "probe_common.h"

int main(void)
{
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s >= 0) {
		PROBE_FINDING("AF_INET SOCK_RAW socket() succeeded — "
			      "CAP_NET_RAW not properly dropped (fd=%d)", s);
	}
	if (errno != EPERM)
		PROBE_FINDING("raw socket() returned errno=%d (%s); expected "
			      "EPERM",
			      errno, strerror(errno));
	PROBE_OK("AF_INET SOCK_RAW socket denied (EPERM)");
}
