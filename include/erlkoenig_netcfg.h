/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * erlkoenig_netcfg.h - Container network configuration via netlink.
 *
 * Two-phase network setup for containers:
 *
 * Phase 1 (host): erlkoenig_netcfg_veth_create()
 *   - Create veth pair via netlink (RTM_NEWLINK + IFLA_LINKINFO)
 *   - Move peer into container netns (IFLA_NET_NS_PID)
 *   - Rename peer, configure host side (IP, UP, rp_filter)
 *
 * Phase 2 (container): erlkoenig_netcfg_setup()
 *   - Enter container netns via setns()
 *   - Assign IPv4 address, set interface + loopback UP
 *   - Add default route via gateway
 *
 * All operations use raw AF_NETLINK/NETLINK_ROUTE sockets.
 */

#ifndef ERLKOENIG_NETCFG_H
#define ERLKOENIG_NETCFG_H

#include <stdint.h>
#include <sys/types.h>

/*
 * erlkoenig_netcfg_veth_create - Create veth pair and prepare host side.
 * @child_pid:	 PID of the container process (host pidns)
 * @host_ifname: Host-side interface name (e.g. "vek12345")
 * @peer_ifname: Desired name inside container (e.g. "eth0")
 * @host_ip:	 Host-side IPv4 address in host byte order
 * @prefixlen:	 Subnet prefix length (e.g. 24)
 *
 * Creates the veth pair, moves the peer into the container's netns,
 * renames it, then configures the host side (IP + UP + rp_filter=0).
 *
 * Returns 0 on success, negative errno on failure.
 * On failure, the veth pair is cleaned up automatically.
 */
int erlkoenig_netcfg_veth_create(pid_t child_pid, const char *host_ifname,
				 const char *peer_ifname, uint32_t host_ip,
				 uint8_t prefixlen);

/*
 * erlkoenig_netcfg_veth_destroy - Destroy a veth pair by host interface name.
 * Deleting the host side automatically destroys the peer.
 *
 * Returns 0 on success (or if already gone), negative errno on failure.
 */
int erlkoenig_netcfg_veth_destroy(const char *host_ifname);

/*
 * erlkoenig_netcfg_setup - Configure networking inside a container's netns.
 * @child_pid:	PID of the container process (host pidns)
 * @ifname:	Interface name inside the netns (e.g. "eth0")
 * @ip:		IPv4 address in host byte order
 * @prefixlen:	Subnet prefix length (e.g. 24)
 * @gateway:	Gateway IPv4 address in host byte order
 *
 * Enters the child's network namespace via setns(), configures
 * the interface, then restores the caller's original namespace.
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_netcfg_setup(pid_t child_pid, const char *ifname, uint32_t ip,
			   uint8_t prefixlen, uint32_t gateway);

#endif /* ERLKOENIG_NETCFG_H */
