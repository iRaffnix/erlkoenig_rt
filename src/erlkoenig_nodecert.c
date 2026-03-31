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
 * erlkoenig_nodecert.c - Node certificate hash computation.
 *
 * Reads the PEM-encoded node certificate and computes its SHA-256
 * hash for the v2 handshake. Uses a minimal SHA-256 implementation
 * (no OpenSSL/mbedTLS dependency) to keep the static musl build clean.
 *
 * The SHA-256 is computed over the raw file contents (PEM including
 * headers and base64). Both sides must read the same file, so the
 * hash matches as long as the file is identical.
 */

#include "erlkoenig_nodecert.h"
#include "erlkoenig_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Minimal SHA-256 (no external dependency)                            */
/* ------------------------------------------------------------------ */

/*
 * SHA-256 implementation based on FIPS 180-4.
 * Single-file, no dynamic allocation, suitable for static builds.
 */

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

struct sha256_ctx {
	uint32_t h[8];
	uint8_t block[64];
	size_t block_len;
	uint64_t total_len;
};

static inline uint32_t rotr32(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}

static void sha256_init(struct sha256_ctx *ctx)
{
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
	ctx->block_len = 0;
	ctx->total_len = 0;
}

static void sha256_transform(struct sha256_ctx *ctx, const uint8_t *data)
{
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h;

	for (int i = 0; i < 16; i++)
		w[i] = ((uint32_t)data[i * 4] << 24) |
		       ((uint32_t)data[i * 4 + 1] << 16) |
		       ((uint32_t)data[i * 4 + 2] << 8) |
		       ((uint32_t)data[i * 4 + 3]);

	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
			      (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

static void sha256_update(struct sha256_ctx *ctx, const uint8_t *data,
			  size_t len)
{
	ctx->total_len += len;

	/* Fill partial block */
	if (ctx->block_len > 0) {
		size_t need = 64 - ctx->block_len;
		size_t take = len < need ? len : need;
		memcpy(ctx->block + ctx->block_len, data, take);
		ctx->block_len += take;
		data += take;
		len -= take;
		if (ctx->block_len == 64) {
			sha256_transform(ctx, ctx->block);
			ctx->block_len = 0;
		}
	}

	/* Process full blocks */
	while (len >= 64) {
		sha256_transform(ctx, data);
		data += 64;
		len -= 64;
	}

	/* Buffer remaining */
	if (len > 0) {
		memcpy(ctx->block, data, len);
		ctx->block_len = len;
	}
}

static void sha256_final(struct sha256_ctx *ctx, uint8_t hash[32])
{
	uint64_t total_bits = ctx->total_len * 8;

	/* Padding: 1 bit, zeros, 64-bit length */
	uint8_t pad = 0x80;
	sha256_update(ctx, &pad, 1);

	uint8_t zero = 0;
	while (ctx->block_len != 56)
		sha256_update(ctx, &zero, 1);

	uint8_t len_be[8];
	for (int i = 7; i >= 0; i--) {
		len_be[i] = (uint8_t)(total_bits & 0xff);
		total_bits >>= 8;
	}
	sha256_update(ctx, len_be, 8);

	/* Output hash (big-endian) */
	for (int i = 0; i < 8; i++) {
		hash[i * 4] = (uint8_t)(ctx->h[i] >> 24);
		hash[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
		hash[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
		hash[i * 4 + 3] = (uint8_t)(ctx->h[i]);
	}
}

/* ------------------------------------------------------------------ */
/* Node certificate hash                                               */
/* ------------------------------------------------------------------ */

/* Maximum cert file size (PEM with chain, generous limit) */
#define MAX_CERT_FILE_SIZE (64 * 1024)

static const char *cert_paths[] = {
    "/etc/erlkoenig/node.pem",
    NULL,
};

int ek_nodecert_load_hash(uint8_t hash_out[EK_NODE_CERT_HASH_LEN])
{
	const char *path;
	int fd = -1;

	memset(hash_out, 0, EK_NODE_CERT_HASH_LEN);

	/* Check environment override first */
	path = getenv("ERLKOENIG_NODE_CERT");
	if (path) {
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			LOG_WARN("nodecert: $ERLKOENIG_NODE_CERT=%s: %s", path,
				 strerror(errno));
			return -1;
		}
	}

	/* Try default paths */
	if (fd < 0) {
		for (int i = 0; cert_paths[i]; i++) {
			fd = open(cert_paths[i], O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				path = cert_paths[i];
				break;
			}
		}
	}

	if (fd < 0) {
		LOG_DBG("nodecert: no node certificate found");
		return -1;
	}

	/* Read entire file */
	uint8_t buf[MAX_CERT_FILE_SIZE];
	size_t total = 0;
	ssize_t n;

	while (total < sizeof(buf)) {
		n = read(fd, buf + total, sizeof(buf) - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			LOG_ERR("nodecert: read(%s): %s", path,
				strerror(errno));
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		total += (size_t)n;
	}
	close(fd);

	if (total == 0) {
		LOG_WARN("nodecert: %s is empty", path);
		return -1;
	}

	/* Compute SHA-256 of the raw PEM file */
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, buf, total);
	sha256_final(&ctx, hash_out);

	LOG_INFO("nodecert: loaded %s (%zu bytes, hash=%02x%02x%02x%02x...)",
		 path, total, hash_out[0], hash_out[1], hash_out[2],
		 hash_out[3]);

	return 0;
}

int ek_nodecert_hash_compare(const uint8_t a[EK_NODE_CERT_HASH_LEN],
			     const uint8_t b[EK_NODE_CERT_HASH_LEN])
{
	/* Constant-time comparison to prevent timing attacks */
	uint8_t diff = 0;
	for (int i = 0; i < EK_NODE_CERT_HASH_LEN; i++)
		diff |= a[i] ^ b[i];
	return diff != 0;
}

int ek_nodecert_hash_is_zero(const uint8_t hash[EK_NODE_CERT_HASH_LEN])
{
	uint8_t acc = 0;
	for (int i = 0; i < EK_NODE_CERT_HASH_LEN; i++)
		acc |= hash[i];
	return acc == 0;
}
