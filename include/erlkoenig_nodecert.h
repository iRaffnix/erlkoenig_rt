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
 * erlkoenig_nodecert.h - Node certificate verification.
 *
 * Reads the node certificate from /etc/erlkoenig/node.pem
 * and computes its SHA-256 hash for the v2 handshake.
 *
 * The full chain validation happens on the Erlang side;
 * the C side only computes the hash and compares it during
 * the handshake to ensure both sides use the same cert.
 *
 * If no node cert exists, the hash is all zeros and the
 * handshake falls back to v1 behavior (no cert check).
 */

#ifndef ERLKOENIG_NODECERT_H
#define ERLKOENIG_NODECERT_H

#include <stdint.h>
#include <stddef.h>

#define EK_NODE_CERT_HASH_LEN 32

/*
 * Load node certificate and compute SHA-256 hash.
 *
 * Tries these paths in order:
 *   1. $ERLKOENIG_NODE_CERT (environment variable)
 *   2. /etc/erlkoenig/node.pem
 *
 * @param hash_out  Output: 32-byte SHA-256 hash (zeroed if no cert found)
 * @return          0 if cert loaded, -1 if not found (hash is zeroed)
 */
int ek_nodecert_load_hash(uint8_t hash_out[EK_NODE_CERT_HASH_LEN]);

/*
 * Compare two node cert hashes.
 *
 * @return 0 if equal, nonzero if different.
 *         Returns 0 if both are all-zeros (no cert on either side).
 */
int ek_nodecert_hash_compare(const uint8_t a[EK_NODE_CERT_HASH_LEN],
			     const uint8_t b[EK_NODE_CERT_HASH_LEN]);

/*
 * Check if a hash is all zeros (no cert loaded).
 */
int ek_nodecert_hash_is_zero(const uint8_t hash[EK_NODE_CERT_HASH_LEN]);

#endif /* ERLKOENIG_NODECERT_H */
