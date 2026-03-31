/*
 * fuzz_kill_parser.c - libFuzzer target for parse_cmd_kill.
 *
 * Feeds random bytes to the KILL command parser and verifies
 * it never crashes, never aborts, always returns a clean error code.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *     -I include -D_GNU_SOURCE \
 *     test/fuzz/fuzz_kill_parser.c -o fuzz_kill
 *
 * Run:
 *   ./fuzz_kill -max_len=65536 -timeout=5
 *
 * The parser must be extracted from erlkoenig_rt.c into a
 * standalone compilation unit. For now, we include the source
 * directly (the parser is a static function).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

/* Pull in the buffer helpers and TLV primitives needed by the parser */
#include "erlkoenig_buf.h"
#include "erlkoenig_tlv.h"
#include "erlkoenig_proto.h"

/*
 * Forward-declare parse_cmd_kill. Since it's static in erlkoenig_rt.c,
 * we need to either:
 *   a) Move it to a separate .c file (proper solution, future)
 *   b) Include the relevant section (hack, but works for fuzzing)
 *
 * For now, we replicate the parser here as a standalone function.
 * This will be replaced when parse_cmd_kill moves to protocol_parse.c
 * (RT-004 full refactor).
 */

static int parse_cmd_kill(const uint8_t *payload, size_t len,
			  uint8_t *signal_out)
{
	struct erlkoenig_buf b;
	struct ek_tlv attr;

	*signal_out = 0;
	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	while (ek_tlv_next(&b, &attr) == 0) {
		if (attr.type == EK_ATTR_SIGNAL)
			*signal_out = ek_tlv_u8(&attr);
		else if (attr.type & EK_TLV_CRITICAL_BIT)
			return -EPROTO;
	}
	if (*signal_out == 0 || *signal_out > 64)
		return -EINVAL;
	return 0;
}

/*
 * libFuzzer entry point.
 *
 * Invariant: parse_cmd_kill MUST NOT crash, abort, or access
 * memory outside the input buffer, regardless of input content.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t signal_out;

	parse_cmd_kill(data, size, &signal_out);

	return 0;
}
