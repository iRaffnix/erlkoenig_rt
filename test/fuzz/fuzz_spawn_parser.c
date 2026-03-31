/*
 * fuzz_spawn_parser.c - libFuzzer target for parse_cmd_spawn.
 *
 * Feeds random bytes to the SPAWN command parser and verifies
 * it never crashes, never aborts, always returns a clean error code.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *     -I include -D_GNU_SOURCE \
 *     test/fuzz/fuzz_spawn_parser.c -o fuzz_spawn
 *
 * Run:
 *   ./fuzz_spawn -max_len=65536 -timeout=5
 *
 * The parser must be extracted from erlkoenig_rt.c into a
 * standalone compilation unit. For now, we include the source
 * directly (the parser is a static function).
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Pull in the buffer helpers and types needed by the parser */
#include "erlkoenig_buf.h"
#include "erlkoenig_ns.h"
#include "erlkoenig_log.h"

/*
 * Forward-declare parse_cmd_spawn. Since it's static in erlkoenig_rt.c,
 * we need to either:
 *   a) Move it to a separate .c file (proper solution, future)
 *   b) Include the relevant section (hack, but works for fuzzing)
 *
 * For now, we replicate the parser here as a standalone function.
 * This will be replaced when parse_cmd_spawn moves to protocol_parse.c
 * (RT-004 full refactor).
 */

/* Minimal strbuf_copy needed by the parser */
static char *strbuf_copy(struct erlkoenig_spawn_opts *opts,
			  const uint8_t *data, uint16_t len)
{
	if (opts->strbuf_used + len + 1 > sizeof(opts->strbuf))
		return NULL;
	char *dst = opts->strbuf + opts->strbuf_used;
	memcpy(dst, data, len);
	dst[len] = '\0';
	opts->strbuf_used += len + 1;
	return dst;
}

static int parse_cmd_spawn(const uint8_t *payload, size_t len,
			    struct erlkoenig_spawn_opts *opts)
{
	struct erlkoenig_buf b;
	const uint8_t *path_data;
	uint16_t path_len;

	*opts = (struct erlkoenig_spawn_opts){0};
	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	if (buf_read_str16(&b, &path_data, &path_len))
		return -22; /* EINVAL */
	if (path_len == 0 || path_len >= ERLKOENIG_MAX_PATH)
		return -36; /* ENAMETOOLONG */

	memcpy(opts->binary_path, path_data, path_len);
	opts->binary_path[path_len] = '\0';

	opts->argv[0] = (char *)"/app";
	opts->argc = 1;

	uint8_t num_args;
	if (buf_read_u8(&b, &num_args))
		return -22;
	for (uint8_t i = 0; i < num_args; i++) {
		const uint8_t *arg_data;
		uint16_t arg_len;
		if (buf_read_str16(&b, &arg_data, &arg_len))
			return -22;
		if (opts->argc >= ERLKOENIG_MAX_ARGS + 1)
			return -7; /* E2BIG */
		opts->argv[opts->argc] = strbuf_copy(opts, arg_data, arg_len);
		if (!opts->argv[opts->argc])
			return -12; /* ENOMEM */
		opts->argc++;
	}
	opts->argv[opts->argc] = NULL;

	uint8_t num_env;
	if (buf_read_u8(&b, &num_env))
		return -22;
	opts->envp[0] = (char *)"HOME=/tmp";
	opts->envp[1] = (char *)"PATH=/";
	opts->envc = 2;

	for (uint8_t i = 0; i < num_env; i++) {
		const uint8_t *key_data, *val_data;
		uint8_t key_len;
		uint16_t val_len;
		if (buf_read_str8(&b, &key_data, &key_len))
			return -22;
		if (buf_read_str16(&b, &val_data, &val_len))
			return -22;
		if (opts->envc >= ERLKOENIG_MAX_ENV)
			return -7;
		size_t entry_len = (size_t)key_len + 1 + val_len;
		if (opts->strbuf_used + entry_len + 1 > sizeof(opts->strbuf))
			return -12;
		char *dst = opts->strbuf + opts->strbuf_used;
		memcpy(dst, key_data, key_len);
		dst[key_len] = '=';
		memcpy(dst + key_len + 1, val_data, val_len);
		dst[entry_len] = '\0';
		opts->strbuf_used += entry_len + 1;
		opts->envp[opts->envc++] = dst;
	}
	opts->envp[opts->envc] = NULL;

	if (buf_read_u32(&b, &opts->uid))
		opts->uid = 65534;
	if (buf_read_u32(&b, &opts->gid))
		opts->gid = 65534;
	if (buf_read_u8(&b, &opts->seccomp_profile))
		opts->seccomp_profile = 0;
	if (buf_read_u32(&b, &opts->rootfs_size_mb))
		opts->rootfs_size_mb = 0;
	if (buf_read_u64(&b, &opts->caps_keep))
		opts->caps_keep = 0;
	if (buf_read_u32(&b, &opts->dns_ip))
		opts->dns_ip = 0;
	if (buf_read_u32(&b, &opts->flags))
		opts->flags = 0;

	opts->num_volumes = 0;
	{
		uint8_t num_volumes;
		if (!buf_read_u8(&b, &num_volumes)) {
			if (num_volumes > ERLKOENIG_MAX_VOLUMES)
				return -22;
			for (uint8_t i = 0; i < num_volumes; i++) {
				const uint8_t *src_data, *dst_data;
				uint16_t src_len, dst_len;
				uint32_t vol_opts;
				if (buf_read_str16(&b, &src_data, &src_len))
					return -22;
				if (buf_read_str16(&b, &dst_data, &dst_len))
					return -22;
				if (buf_read_u32(&b, &vol_opts))
					return -22;
				if (src_len >= ERLKOENIG_MAX_PATH - 1)
					return -36;
				if (dst_len >= ERLKOENIG_MAX_PATH - 1)
					return -36;
				memcpy(opts->volumes[i].source, src_data, src_len);
				opts->volumes[i].source[src_len] = '\0';
				memcpy(opts->volumes[i].dest, dst_data, dst_len);
				opts->volumes[i].dest[dst_len] = '\0';
				opts->volumes[i].opts = vol_opts;
			}
			opts->num_volumes = num_volumes;
		}
	}

	return 0;
}

/*
 * libFuzzer entry point.
 *
 * Invariant: parse_cmd_spawn MUST NOT crash, abort, or access
 * memory outside the input buffer, regardless of input content.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct erlkoenig_spawn_opts opts;

	parse_cmd_spawn(data, size, &opts);

	return 0;
}
