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
 * ek_protocol.c - TLV command-payload parsers (extracted from
 * erlkoenig_rt.c so libFuzzer can link against the real code).
 *
 * See ek_protocol.h for contract.
 */

#include "ek_protocol.h"

#include <errno.h>
#include <string.h>

#include "erlkoenig_buf.h"
#include "erlkoenig_proto.h"
#include "erlkoenig_tlv.h"

/*
 * strbuf_copy - Copy a string into opts->strbuf, NUL-terminated.
 * Returns pointer to the copy, or NULL if the strbuf is full.
 */
static char *strbuf_copy(struct erlkoenig_spawn_opts *opts, const uint8_t *data,
			 size_t len)
{
	if (opts->strbuf_used + len + 1 > sizeof(opts->strbuf))
		return NULL;

	char *dst = opts->strbuf + opts->strbuf_used;
	memcpy(dst, data, len);
	dst[len] = '\0';
	opts->strbuf_used += len + 1;
	return dst;
}

int ek_parse_cmd_spawn(const uint8_t *payload, size_t len,
		       struct erlkoenig_spawn_opts *opts)
{
	struct erlkoenig_buf b;
	struct ek_tlv attr;

	*opts = (struct erlkoenig_spawn_opts){0};
	opts->uid = 65534;
	opts->gid = 65534;
	opts->argv[0] = (char *)"/app";
	opts->argc = 1;
	opts->envp[0] = (char *)"HOME=/tmp";
	opts->envp[1] = (char *)"PATH=/";
	opts->envc = 2;

	erlkoenig_buf_init(&b, (uint8_t *)payload, len);

	while (ek_tlv_next(&b, &attr) == 0) {
		switch (attr.type) {
		case EK_ATTR_PATH:
			if (attr.len == 0 || attr.len >= ERLKOENIG_MAX_PATH)
				return -ENAMETOOLONG;
			memcpy(opts->binary_path, attr.value, attr.len);
			opts->binary_path[attr.len] = '\0';
			break;
		case EK_ATTR_UID:
			opts->uid = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_GID:
			opts->gid = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_CAPS:
			opts->caps_keep = ek_tlv_u64(&attr);
			break;
		case EK_ATTR_ARG:
			if (opts->argc >= ERLKOENIG_MAX_ARGS + 1)
				return -E2BIG;
			opts->argv[opts->argc] =
			    strbuf_copy(opts, attr.value, attr.len);
			if (!opts->argv[opts->argc])
				return -ENOMEM;
			opts->argc++;
			break;
		case EK_ATTR_FLAGS:
			opts->flags = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_ENV: {
			if (opts->envc >= ERLKOENIG_MAX_ENV)
				return -E2BIG;
			const uint8_t *sep = memchr(attr.value, '\0', attr.len);
			if (!sep)
				return -EINVAL;
			size_t klen = (size_t)(sep - attr.value);
			size_t vlen = attr.len - klen - 1;
			size_t elen = klen + 1 + vlen;
			if (opts->strbuf_used + elen + 1 > sizeof(opts->strbuf))
				return -ENOMEM;
			char *dst = opts->strbuf + opts->strbuf_used;
			memcpy(dst, attr.value, klen);
			dst[klen] = '=';
			memcpy(dst + klen + 1, sep + 1, vlen);
			dst[elen] = '\0';
			opts->strbuf_used += elen + 1;
			opts->envp[opts->envc++] = dst;
			break;
		}
		case EK_ATTR_ROOTFS_MB:
			opts->rootfs_size_mb = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_SECCOMP:
			opts->seccomp_profile = ek_tlv_u8(&attr);
			break;
		case EK_ATTR_DNS_IP:
			opts->dns_ip = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_VOLUME: {
			if (opts->num_volumes >= ERLKOENIG_MAX_VOLUMES)
				return -E2BIG;
			/*
			 * Wire: host\0 cont\0 flags:u32 clear:u32 prop:u8
			 *       rec:u8 data_len:u16 data:data_len
			 * See EK_VOLUME_TLV_MIN in erlkoenig_proto.h.
			 */
			if (attr.len < EK_VOLUME_TLV_MIN)
				return -EINVAL;
			const uint8_t *sep1 =
			    memchr(attr.value, '\0', attr.len);
			if (!sep1)
				return -EINVAL;
			size_t slen = (size_t)(sep1 - attr.value);
			size_t after_src = slen + 1;
			if (after_src >= attr.len)
				return -EINVAL;
			const uint8_t *sep2 = memchr(
			    attr.value + after_src, '\0', attr.len - after_src);
			if (!sep2)
				return -EINVAL;
			size_t dlen = (size_t)(sep2 - (attr.value + after_src));
			size_t after_dst = after_src + dlen + 1;
			/* Fixed header after the two NUL-terminated paths:
			 * 4+4+1+1+2 = 12 bytes, then variable data. */
			if (attr.len - after_dst < 12)
				return -EINVAL;
			if (slen >= ERLKOENIG_MAX_PATH - 1 ||
			    dlen >= ERLKOENIG_MAX_PATH - 1)
				return -ENAMETOOLONG;
			const uint8_t *hdr = attr.value + after_dst;
			uint32_t flags =
			    (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
			    (uint32_t)hdr[2] << 8 | (uint32_t)hdr[3];
			uint32_t clear =
			    (uint32_t)hdr[4] << 24 | (uint32_t)hdr[5] << 16 |
			    (uint32_t)hdr[6] << 8 | (uint32_t)hdr[7];
			uint8_t prop = hdr[8];
			uint8_t rec = hdr[9];
			uint16_t data_len =
			    (uint16_t)hdr[10] << 8 | (uint16_t)hdr[11];
			if ((size_t)data_len != attr.len - after_dst - 12)
				return -EINVAL;
			if (data_len >= ERLKOENIG_MAX_MOUNT_DATA)
				return -ENAMETOOLONG;
			if (prop > EK_PROP_UNBINDABLE)
				return -EINVAL;
			uint8_t vi = opts->num_volumes;
			memcpy(opts->volumes[vi].source, attr.value, slen);
			opts->volumes[vi].source[slen] = '\0';
			memcpy(opts->volumes[vi].dest, attr.value + after_src,
			       dlen);
			opts->volumes[vi].dest[dlen] = '\0';
			opts->volumes[vi].flags = flags;
			opts->volumes[vi].clear = clear;
			opts->volumes[vi].propagation = prop;
			opts->volumes[vi].recursive = rec;
			if (data_len > 0)
				memcpy(opts->volumes[vi].data, hdr + 12,
				       data_len);
			opts->volumes[vi].data[data_len] = '\0';
			opts->num_volumes++;
			break;
		}
		case EK_ATTR_MEMORY_MAX:
			opts->memory_max = ek_tlv_u64(&attr);
			break;
		case EK_ATTR_PIDS_MAX:
			opts->pids_max = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_CPU_WEIGHT:
			opts->cpu_weight = ek_tlv_u32(&attr);
			break;
		case EK_ATTR_IMAGE_PATH:
			if (attr.len == 0 || attr.len >= ERLKOENIG_MAX_PATH)
				return -ENAMETOOLONG;
			memcpy(opts->image_path, attr.value, attr.len);
			opts->image_path[attr.len] = '\0';
			break;
		default:
			if (attr.type & EK_TLV_CRITICAL_BIT)
				return -EPROTO;
			break;
		}
	}

	opts->argv[opts->argc] = NULL;
	opts->envp[opts->envc] = NULL;

	if (opts->binary_path[0] == '\0')
		return -EINVAL;
	return 0;
}

int ek_parse_cmd_kill(const uint8_t *payload, size_t len, uint8_t *signal_out)
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

int ek_parse_cmd_net_setup(const uint8_t *payload, size_t len,
			   struct ek_net_setup_args *args)
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

int ek_parse_cmd_resize(const uint8_t *payload, size_t len, uint16_t *rows,
			uint16_t *cols)
{
	struct erlkoenig_buf b;
	struct ek_tlv attr;

	*rows = 0;
	*cols = 0;
	erlkoenig_buf_init(&b, (uint8_t *)payload, len);
	while (ek_tlv_next(&b, &attr) == 0) {
		switch (attr.type) {
		case EK_ATTR_ROWS:
			*rows = ek_tlv_u16(&attr);
			break;
		case EK_ATTR_COLS:
			*cols = ek_tlv_u16(&attr);
			break;
		default:
			if (attr.type & EK_TLV_CRITICAL_BIT)
				return -EPROTO;
			break;
		}
	}
	if (*rows == 0 || *cols == 0)
		return -EINVAL;
	return 0;
}
