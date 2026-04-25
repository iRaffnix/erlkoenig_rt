/*
 * probe_netns__no_packet_socket.c
 *
 * Asserts: AF_PACKET socket creation must fail (no CAP_NET_RAW after
 * cap drop). Without CAP_NET_RAW the socket() returns EPERM.
 *
 * Profile: DEFAULT (which allows the socket syscall).
 */

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#include "probe_common.h"

int main(void)
{
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s >= 0) {
		PROBE_FINDING(
		    "AF_PACKET SOCK_RAW socket() succeeded — CAP_NET_RAW "
		    "not properly dropped (fd=%d)",
		    s);
	}
	if (errno != EPERM && errno != EAFNOSUPPORT)
		PROBE_FINDING(
		    "AF_PACKET socket() returned errno=%d (%s); expected EPERM",
		    errno, strerror(errno));
	PROBE_OK("AF_PACKET socket denied: %s", strerror(errno));
}
