/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * erlkoenig_tlv.h - TLV (Tag-Length-Value) primitives for wire protocol.
 *
 * Each attribute:
 *   <<Type:16/big, Len:16/big, Value:Len/bytes>>
 *
 * Type semantics:
 *   Bit 15 (0x8000) = Critical flag
 *   - Optional unknown (< 0x8000): skip silently
 *   - Critical unknown (>= 0x8000): reject message (-EPROTO)
 *
 * Messages:
 *   <<Tag:8, Ver:8, [TLV Attributes...]>>
 *   Streaming (STDIN/STDOUT/STDERR): raw bytes, no TLV
 */

#ifndef ERLKOENIG_TLV_H
#define ERLKOENIG_TLV_H

#include <stdint.h>
#include <string.h>

#include "erlkoenig_buf.h"

#define EK_TLV_HDR_SIZE	4 /* Type(2) + Len(2) */
#define EK_TLV_CRITICAL_BIT 0x8000

/* Parsed TLV attribute */
struct ek_tlv {
	uint16_t type;
	uint16_t len;
	const uint8_t *value;
};

/*
 * Read the next TLV attribute from the buffer.
 * Returns 0 on success, -1 when no more data.
 */
static inline int ek_tlv_next(struct erlkoenig_buf *b, struct ek_tlv *out)
{
	if (buf_read_u16(b, &out->type))
		return -1;
	if (buf_read_u16(b, &out->len))
		return -1;
	if (b->pos + out->len > b->len)
		return -1;
	out->value = b->data + b->pos;
	b->pos += out->len;
	return 0;
}

/* Read a uint8 from a TLV value */
static inline uint8_t ek_tlv_u8(const struct ek_tlv *a)
{
	return (a->len >= 1) ? a->value[0] : 0;
}

/* Read a uint16 (big-endian) from a TLV value */
static inline uint16_t ek_tlv_u16(const struct ek_tlv *a)
{
	if (a->len < 2)
		return 0;
	return (uint16_t)((uint16_t)a->value[0] << 8 | a->value[1]);
}

/* Read a uint32 (big-endian) from a TLV value */
static inline uint32_t ek_tlv_u32(const struct ek_tlv *a)
{
	if (a->len < 4)
		return 0;
	return (uint32_t)a->value[0] << 24 | (uint32_t)a->value[1] << 16 |
	       (uint32_t)a->value[2] << 8 | (uint32_t)a->value[3];
}

/* Read an int32 (big-endian) from a TLV value */
static inline int32_t ek_tlv_i32(const struct ek_tlv *a)
{
	return (int32_t)ek_tlv_u32(a);
}

/* Read a uint64 (big-endian) from a TLV value */
static inline uint64_t ek_tlv_u64(const struct ek_tlv *a)
{
	if (a->len < 8)
		return 0;
	return (uint64_t)ek_tlv_u32(&(struct ek_tlv){
		       .value = a->value, .len = 4}) << 32 |
	       ek_tlv_u32(
		   &(struct ek_tlv){.value = a->value + 4, .len = 4});
}

/* -- TLV Writers -------------------------------------------------- */

/* Write a TLV with raw bytes value */
static inline void ek_tlv_put(struct erlkoenig_buf *b, uint16_t type,
			      const void *data, uint16_t len)
{
	buf_write_u16(b, type);
	buf_write_u16(b, len);
	if (len > 0 && data)
		buf_write_bytes(b, data, len);
}

/* Write a TLV with uint8 value */
static inline void ek_tlv_put_u8(struct erlkoenig_buf *b, uint16_t type,
				 uint8_t val)
{
	ek_tlv_put(b, type, &val, 1);
}

/* Write a TLV with uint16 value (big-endian) */
static inline void ek_tlv_put_u16(struct erlkoenig_buf *b, uint16_t type,
				  uint16_t val)
{
	uint8_t buf2[2];

	buf2[0] = (uint8_t)(val >> 8);
	buf2[1] = (uint8_t)(val);
	ek_tlv_put(b, type, buf2, 2);
}

/* Write a TLV with uint32 value (big-endian) */
static inline void ek_tlv_put_u32(struct erlkoenig_buf *b, uint16_t type,
				  uint32_t val)
{
	uint8_t buf4[4];

	buf4[0] = (uint8_t)(val >> 24);
	buf4[1] = (uint8_t)(val >> 16);
	buf4[2] = (uint8_t)(val >> 8);
	buf4[3] = (uint8_t)(val);
	ek_tlv_put(b, type, buf4, 4);
}

/* Write a TLV with int32 value (big-endian) */
static inline void ek_tlv_put_i32(struct erlkoenig_buf *b, uint16_t type,
				  int32_t val)
{
	ek_tlv_put_u32(b, type, (uint32_t)val);
}

/* Write a TLV with uint64 value (big-endian) */
static inline void ek_tlv_put_u64(struct erlkoenig_buf *b, uint16_t type,
				  uint64_t val)
{
	uint8_t buf8[8];

	buf8[0] = (uint8_t)(val >> 56);
	buf8[1] = (uint8_t)(val >> 48);
	buf8[2] = (uint8_t)(val >> 40);
	buf8[3] = (uint8_t)(val >> 32);
	buf8[4] = (uint8_t)(val >> 24);
	buf8[5] = (uint8_t)(val >> 16);
	buf8[6] = (uint8_t)(val >> 8);
	buf8[7] = (uint8_t)(val);
	ek_tlv_put(b, type, buf8, 8);
}

/* Write a TLV with string value (no null terminator in wire format) */
static inline void ek_tlv_put_str(struct erlkoenig_buf *b, uint16_t type,
				  const char *str)
{
	ek_tlv_put(b, type, str, (uint16_t)strlen(str));
}

#endif /* ERLKOENIG_TLV_H */
