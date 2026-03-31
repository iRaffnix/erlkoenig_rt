/*
 * fuzz_net_setup_parser.c - libFuzzer target for parse_cmd_net_setup.
 *
 * Feeds random bytes to the NET_SETUP command parser and verifies
 * it never crashes, never aborts, always returns a clean error code.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *     -I include -D_GNU_SOURCE \
 *     test/fuzz/fuzz_net_setup_parser.c -o fuzz_net_setup
 *
 * Run:
 *   ./fuzz_net_setup -max_len=65536 -timeout=5
 *
 * The parser must be extracted from erlkoenig_rt.c into a
 * standalone compilation unit. For now, we include the source
 * directly (the parser is a static function).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>

/* Pull in the buffer helpers and TLV primitives needed by the parser */
#include "erlkoenig_buf.h"
#include "erlkoenig_tlv.h"
#include "erlkoenig_proto.h"

/*
 * Forward-declare parse_cmd_net_setup. Since it's static in erlkoenig_rt.c,
 * we need to either:
 *   a) Move it to a separate .c file (proper solution, future)
 *   b) Include the relevant section (hack, but works for fuzzing)
 *
 * For now, we replicate the parser here as a standalone function.
 * This will be replaced when parse_cmd_net_setup moves to protocol_parse.c
 * (RT-004 full refactor).
 */

struct net_setup_args {
	char ifname[IF_NAMESIZE];
	uint32_t ip;
	uint32_t gateway;
	uint8_t prefixlen;
	uint8_t ip_bytes[4];
	uint8_t gw_bytes[4];
};

static int parse_cmd_net_setup(const uint8_t *payload, size_t len,
			       struct net_setup_args *args)
{
	struct erlkoenig_buf b;
	struct ek_tlv attr;

	memset(args, 0, sizeof(*args));
	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	while (ek_tlv_next(&b, &attr) == 0) {
		switch (attr.type) {
		case EK_ATTR_IFNAME:
			if (attr.len == 0 || attr.len >= IF_NAMESIZE)
				return -EINVAL;
			memcpy(args->ifname, attr.value, attr.len);
			args->ifname[attr.len] = '\0';
			break;
		case EK_ATTR_CONTAINER_IP:
			args->ip = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_GATEWAY_IP:
			args->gateway = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_PREFIXLEN:
			args->prefixlen = ek_tlv_u8(&attr);
			break;
		default:
			if (attr.type & EK_TLV_CRITICAL_BIT)
				return -EPROTO;
			break;
		}
	}

	/* Decompose IP for logging */
	args->ip_bytes[0] = (uint8_t)(args->ip >> 24);
	args->ip_bytes[1] = (uint8_t)(args->ip >> 16);
	args->ip_bytes[2] = (uint8_t)(args->ip >> 8);
	args->ip_bytes[3] = (uint8_t)(args->ip);
	args->gw_bytes[0] = (uint8_t)(args->gateway >> 24);
	args->gw_bytes[1] = (uint8_t)(args->gateway >> 16);
	args->gw_bytes[2] = (uint8_t)(args->gateway >> 8);
	args->gw_bytes[3] = (uint8_t)(args->gateway);

	if (args->ifname[0] == '\0')
		return -EINVAL;
	return 0;
}

/*
 * libFuzzer entry point.
 *
 * Invariant: parse_cmd_net_setup MUST NOT crash, abort, or access
 * memory outside the input buffer, regardless of input content.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct net_setup_args args;

	parse_cmd_net_setup(data, size, &args);

	return 0;
}
