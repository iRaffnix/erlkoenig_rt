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
 * erlkoenig_buf.h - Wire format buffer primitives.
 *
 * Generic read/write helpers for big-endian wire encoding and
 * {packet, 4} framed I/O. Not protocol-specific -- this file
 * contains no message tags or definitions.
 *
 * Buffer management follows the Linux kernel pattern:
 *   - A cursor (data, len, pos) tracks position and bounds
 *   - Every read/write checks bounds BEFORE accessing memory
 *   - Functions return 0 on success, -1 on overflow
 *   - No dynamic allocation
 */

#ifndef ERLKOENIG_BUF_H
#define ERLKOENIG_BUF_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>

/* -- Buffer cursor ------------------------------------------------ */

struct erlkoenig_buf {
	uint8_t *data;
	size_t len;
	size_t pos;
};

static inline void erlkoenig_buf_init(struct erlkoenig_buf *b, uint8_t *data,
				      size_t len)
{
	b->data = data;
	b->len = len;
	b->pos = 0;
}

static inline size_t erlkoenig_buf_remaining(const struct erlkoenig_buf *b)
{
	return b->len - b->pos;
}

static inline int erlkoenig_buf_check(const struct erlkoenig_buf *b, size_t n)
{
	return (b->pos + n <= b->len) ? 0 : -1;
}

/* -- Readers (big-endian wire -> host) ---------------------------- */

static inline int buf_read_u8(struct erlkoenig_buf *b, uint8_t *out)
{
	if (erlkoenig_buf_check(b, 1))
		return -1;
	*out = b->data[b->pos++];
	return 0;
}

static inline int buf_read_u16(struct erlkoenig_buf *b, uint16_t *out)
{
	if (erlkoenig_buf_check(b, 2))
		return -1;
	memcpy(out, b->data + b->pos, 2);
	*out = ntohs(*out);
	b->pos += 2;
	return 0;
}

static inline int buf_read_u32(struct erlkoenig_buf *b, uint32_t *out)
{
	if (erlkoenig_buf_check(b, 4))
		return -1;
	memcpy(out, b->data + b->pos, 4);
	*out = ntohl(*out);
	b->pos += 4;
	return 0;
}

static inline int buf_read_i32(struct erlkoenig_buf *b, int32_t *out)
{
	uint32_t raw;
	if (buf_read_u32(b, &raw))
		return -1;
	*out = (int32_t)raw;
	return 0;
}

static inline int buf_read_u64(struct erlkoenig_buf *b, uint64_t *out)
{
	if (erlkoenig_buf_check(b, 8))
		return -1;
	uint32_t hi, lo;
	memcpy(&hi, b->data + b->pos, 4);
	memcpy(&lo, b->data + b->pos + 4, 4);
	*out = ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
	b->pos += 8;
	return 0;
}

static inline int buf_read_bytes(struct erlkoenig_buf *b, uint8_t *out,
				 size_t n)
{
	if (erlkoenig_buf_check(b, n))
		return -1;
	memcpy(out, b->data + b->pos, n);
	b->pos += n;
	return 0;
}

/*
 * Read a length-prefixed string (<<Len:16, Data:Len/binary>>).
 * Returns a pointer into the buffer (zero-copy).
 */
static inline int buf_read_str16(struct erlkoenig_buf *b, const uint8_t **out,
				 uint16_t *len)
{
	if (buf_read_u16(b, len))
		return -1;
	if (erlkoenig_buf_check(b, *len))
		return -1;
	*out = b->data + b->pos;
	b->pos += *len;
	return 0;
}

static inline int buf_read_str8(struct erlkoenig_buf *b, const uint8_t **out,
				uint8_t *len)
{
	if (buf_read_u8(b, len))
		return -1;
	if (erlkoenig_buf_check(b, *len))
		return -1;
	*out = b->data + b->pos;
	b->pos += *len;
	return 0;
}

static inline int buf_read_bin16(struct erlkoenig_buf *b, const uint8_t **out,
				 uint16_t *len)
{
	return buf_read_str16(b, out, len);
}

static inline int buf_read_bin32(struct erlkoenig_buf *b, const uint8_t **out,
				 uint32_t *len)
{
	if (buf_read_u32(b, len))
		return -1;
	if (erlkoenig_buf_check(b, *len))
		return -1;
	*out = b->data + b->pos;
	b->pos += *len;
	return 0;
}

/* -- Writers (host -> big-endian wire) ---------------------------- */

static inline int buf_write_u8(struct erlkoenig_buf *b, uint8_t val)
{
	if (erlkoenig_buf_check(b, 1))
		return -1;
	b->data[b->pos++] = val;
	return 0;
}

static inline int buf_write_u16(struct erlkoenig_buf *b, uint16_t val)
{
	if (erlkoenig_buf_check(b, 2))
		return -1;
	val = htons(val);
	memcpy(b->data + b->pos, &val, 2);
	b->pos += 2;
	return 0;
}

static inline int buf_write_u32(struct erlkoenig_buf *b, uint32_t val)
{
	if (erlkoenig_buf_check(b, 4))
		return -1;
	val = htonl(val);
	memcpy(b->data + b->pos, &val, 4);
	b->pos += 4;
	return 0;
}

static inline int buf_write_i32(struct erlkoenig_buf *b, int32_t val)
{
	return buf_write_u32(b, (uint32_t)val);
}

static inline int buf_write_u64(struct erlkoenig_buf *b, uint64_t val)
{
	if (erlkoenig_buf_check(b, 8))
		return -1;
	uint32_t hi = htonl((uint32_t)(val >> 32));
	uint32_t lo = htonl((uint32_t)(val & 0xFFFFFFFF));
	memcpy(b->data + b->pos, &hi, 4);
	memcpy(b->data + b->pos + 4, &lo, 4);
	b->pos += 8;
	return 0;
}

static inline int buf_write_bytes(struct erlkoenig_buf *b, const uint8_t *data,
				  size_t n)
{
	if (erlkoenig_buf_check(b, n))
		return -1;
	memcpy(b->data + b->pos, data, n);
	b->pos += n;
	return 0;
}

static inline int buf_write_str16(struct erlkoenig_buf *b, const char *str,
				  uint16_t len)
{
	if (buf_write_u16(b, len))
		return -1;
	return buf_write_bytes(b, (const uint8_t *)str, len);
}

static inline int buf_write_str8(struct erlkoenig_buf *b, const char *str,
				 uint8_t len)
{
	if (buf_write_u8(b, len))
		return -1;
	return buf_write_bytes(b, (const uint8_t *)str, len);
}

static inline int buf_write_bin16(struct erlkoenig_buf *b, const uint8_t *data,
				  uint16_t len)
{
	return buf_write_str16(b, (const char *)data, len);
}

static inline int buf_write_bin32(struct erlkoenig_buf *b, const uint8_t *data,
				  uint32_t len)
{
	if (buf_write_u32(b, len))
		return -1;
	return buf_write_bytes(b, data, len);
}

/* -- Framed I/O ({packet, 4}) ------------------------------------- */

/*
 * Read one {packet, 4} frame from fd.
 * Returns payload length on success, -1 on EOF/error.
 * EINTR is handled internally.
 */
static inline ssize_t erlkoenig_read_frame(int fd, uint8_t *buf, size_t bufsz)
{
	uint32_t pkt_len;
	size_t got = 0;

	while (got < 4) {
		ssize_t r = read(fd, ((uint8_t *)&pkt_len) + got, 4 - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;
		got += (size_t)r;
	}
	pkt_len = ntohl(pkt_len);

	if (pkt_len > bufsz)
		return -1;

	got = 0;
	while (got < pkt_len) {
		ssize_t r = read(fd, buf + got, pkt_len - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return -1;
		got += (size_t)r;
	}

	return (ssize_t)pkt_len;
}

/*
 * Write one {packet, 4} frame to fd using writev() for atomicity.
 * The header (4-byte length) and payload are sent in a single
 * syscall via scatter-gather I/O, avoiding partial-frame issues.
 * Returns 0 on success, -1 on error.
 */
static inline int erlkoenig_write_frame(int fd, const uint8_t *buf, size_t len)
{
	uint32_t pkt_len = htonl((uint32_t)len);
	struct iovec iov[2];
	size_t total;
	ssize_t written;

	iov[0].iov_base = &pkt_len;
	iov[0].iov_len = 4;
	iov[1].iov_base = (void *)(uintptr_t)buf;
	iov[1].iov_len = len;

	total = 4 + len;
	while (total > 0) {
		written = writev(fd, iov, 2);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (written == 0)
			return -1;
		total -= (size_t)written;
		if (total == 0)
			break;
		/* Advance iov past written bytes (partial writev) */
		size_t consumed = (size_t)written;

		if (consumed >= iov[0].iov_len) {
			consumed -= iov[0].iov_len;
			iov[0].iov_len = 0;
			iov[0].iov_base = (uint8_t *)iov[1].iov_base + consumed;
			iov[0].iov_len = 0;
			iov[1].iov_base = (uint8_t *)iov[1].iov_base + consumed;
			iov[1].iov_len -= consumed;
		} else {
			iov[0].iov_base = (uint8_t *)iov[0].iov_base + consumed;
			iov[0].iov_len -= consumed;
		}
	}

	return 0;
}

#endif /* ERLKOENIG_BUF_H */
