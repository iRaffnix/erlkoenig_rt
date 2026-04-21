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
 * ek_protocol.h - TLV command-payload parsers.
 *
 * Pure functions that take attacker-controlled bytes over the
 * control socket and populate typed option structs. No I/O,
 * no globals, no syscalls. The only failure mode is a negative
 * errno return — never a crash, never silent truncation, never
 * an out-of-bounds access.
 *
 * These parsers are extracted from erlkoenig_rt.c so the libFuzzer
 * harnesses under test/fuzz link against the EXACT same code that
 * runs in production. Previously the harnesses kept their own copy
 * of parse_cmd_spawn, which drifted from reality and stopped
 * compiling.
 */

#ifndef EK_PROTOCOL_H
#define EK_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <net/if.h>

#include "erlkoenig_ns.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * struct ek_net_setup_args - Typed NET_SETUP payload.
 *
 * @ifname:    Interface name inside the container netns (bounded,
 *             NUL-terminated, non-empty on success).
 * @ip:        Container IPv4 address (host byte order).
 * @gateway:   Default route next-hop (host byte order).
 * @prefixlen: Address prefix length (0..32, not range-checked here).
 * @ip_bytes:  Pre-decomposed IP for logging (big-endian).
 * @gw_bytes:  Pre-decomposed gateway for logging.
 */
struct ek_net_setup_args {
	char ifname[IF_NAMESIZE];
	uint32_t ip;
	uint32_t gateway;
	uint8_t prefixlen;
	uint8_t ip_bytes[4];
	uint8_t gw_bytes[4];
};

/*
 * ek_parse_cmd_spawn - Parse a SPAWN command payload.
 *
 * @payload: Raw bytes from the control socket (attacker-controlled).
 * @len:     Length of @payload in bytes.
 * @opts:    Output — fully initialised on success, zeroed + partial
 *           on error.
 *
 * Returns 0 on success, negative errno on parse error:
 *   -EINVAL        — wire corruption / missing required field
 *   -EPROTO        — unknown critical TLV
 *   -ENAMETOOLONG  — path / path element too long
 *   -E2BIG         — too many args / env entries / volumes
 *   -ENOMEM        — strbuf / volume data buffer exhausted
 */
int ek_parse_cmd_spawn(const uint8_t *payload, size_t len,
		       struct erlkoenig_spawn_opts *opts);

/*
 * ek_parse_cmd_kill - Parse a KILL command payload.
 *
 * @signal_out: Output signal number (1..64 on success).
 *
 * Returns 0 on success, -EINVAL on invalid/missing signal,
 * -EPROTO on unknown critical TLV.
 */
int ek_parse_cmd_kill(const uint8_t *payload, size_t len,
		      uint8_t *signal_out);

/*
 * ek_parse_cmd_net_setup - Parse a NET_SETUP command payload.
 *
 * Wire: TLV stream with EK_ATTR_IFNAME + EK_ATTR_CONTAINER_IP
 *       + EK_ATTR_GATEWAY_IP + EK_ATTR_PREFIXLEN.
 *
 * Returns 0 on success, negative errno on error.
 */
int ek_parse_cmd_net_setup(const uint8_t *payload, size_t len,
			   struct ek_net_setup_args *args);

/*
 * ek_parse_cmd_resize - Parse a RESIZE command payload (PTY rows/cols).
 *
 * Returns 0 on success. -EINVAL if rows or cols is 0.
 */
int ek_parse_cmd_resize(const uint8_t *payload, size_t len,
			uint16_t *rows, uint16_t *cols);

#ifdef __cplusplus
}
#endif

#endif /* EK_PROTOCOL_H */
