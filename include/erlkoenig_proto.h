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
 * erlkoenig_proto.h - Erlkoenig wire protocol definitions.
 *
 * Message tags and names for the binary protocol between
 * the Erlang control plane and the C runtime.
 *
 * See proto/erlkoenig.protocol for the full specification.
 */

#ifndef ERLKOENIG_PROTO_H
#define ERLKOENIG_PROTO_H

#include "erlkoenig_buf.h"

/* -- Compiler attributes ------------------------------------------ */

#define EK_NODISCARD __attribute__((warn_unused_result))

/* -- Compile-time protocol invariants ----------------------------- */

_Static_assert(sizeof(uint8_t) == 1, "protocol assumes 1-byte uint8");
_Static_assert(sizeof(uint16_t) == 2, "protocol assumes 2-byte uint16");
_Static_assert(sizeof(uint32_t) == 4, "protocol assumes 4-byte uint32");
_Static_assert(sizeof(uint64_t) == 8, "protocol assumes 8-byte uint64");

/* -- Protocol version --------------------------------------------- */

/*
 * Protocol version 1: TLV-based wire format.
 * Messages: <<Tag:8, Ver:8, [TLV Attributes...]>>
 * Streaming (STDIN/STDOUT/STDERR): raw bytes, no TLV.
 * No legacy formats, no fallbacks.
 */
#define ERLKOENIG_PROTOCOL_VERSION 1

/* -- SPAWN TLV attribute types ------------------------------------ */
#define EK_ATTR_PATH	   1  /* bytes, required */
#define EK_ATTR_UID	   2  /* uint32, required */
#define EK_ATTR_GID	   3  /* uint32, required */
#define EK_ATTR_CAPS	   4  /* uint64, optional */
#define EK_ATTR_ARG	   5  /* bytes, repeated */
#define EK_ATTR_FLAGS	   6  /* uint32, optional */
#define EK_ATTR_ENV	   7  /* bytes "key\0val", repeated */
#define EK_ATTR_ROOTFS_MB  8  /* uint32, optional */
#define EK_ATTR_SECCOMP	   9  /* uint8, optional */
#define EK_ATTR_DNS_IP	   10 /* uint32, optional */
#define EK_ATTR_VOLUME	   11 /* bytes, repeated */
#define EK_ATTR_MEMORY_MAX 12 /* uint64, optional */
#define EK_ATTR_PIDS_MAX   13 /* uint32, optional */
#define EK_ATTR_CPU_WEIGHT 14 /* uint32, optional */
#define EK_ATTR_IMAGE_PATH 15 /* bytes, optional — EROFS image path */

/* KILL attribute */
#define EK_ATTR_SIGNAL 1 /* uint8, required */

/* NET_SETUP attributes */
#define EK_ATTR_IFNAME	     1 /* bytes, required */
#define EK_ATTR_CONTAINER_IP 2 /* uint32, required */
#define EK_ATTR_GATEWAY_IP   3 /* uint32, required */
#define EK_ATTR_PREFIXLEN    4 /* uint8, optional */

/* WRITE_FILE attributes */
#define EK_ATTR_FILE_PATH 1 /* bytes, required */
#define EK_ATTR_CONTENT	  2 /* bytes, required */
#define EK_ATTR_FILE_MODE 3 /* uint32, optional */

/* RESIZE attributes */
#define EK_ATTR_ROWS 1 /* uint16, required */
#define EK_ATTR_COLS 2 /* uint16, required */

/* DEVICE_FILTER / METRICS_START attributes */
#define EK_ATTR_CGROUP_PATH 1 /* bytes, required */
#define EK_ATTR_DEV_RULE    2 /* bytes, repeated */

/* Reply attributes (per-reply type numbers) */
#define EK_ATTR_DATA	    1 /* bytes (OK) */
#define EK_ATTR_CODE	    1 /* int32 (ERROR) */
#define EK_ATTR_MESSAGE	    2 /* bytes (ERROR) */
#define EK_ATTR_PID	    1 /* uint32 (CONTAINER_PID, STATUS) */
#define EK_ATTR_NETNS_PATH  2 /* bytes (CONTAINER_PID) */
#define EK_ATTR_EXIT_CODE   1 /* int32 (EXITED) */
#define EK_ATTR_TERM_SIGNAL 2 /* uint8 (EXITED) */
#define EK_ATTR_STATE	    1 /* uint8 (STATUS) */
#define EK_ATTR_UPTIME_MS   3 /* uint64 (STATUS) */
#define EK_ATTR_EVENT_DATA  1 /* bytes (METRICS_EVENT) */

/* -- Reply tags (C -> Erlang, 0x01-0x0F) -------------------------- */

#define ERLKOENIG_TAG_REPLY_OK		  0x01
#define ERLKOENIG_TAG_REPLY_ERROR	  0x02
#define ERLKOENIG_TAG_REPLY_CONTAINER_PID 0x03
#define ERLKOENIG_TAG_REPLY_READY	  0x04
#define ERLKOENIG_TAG_REPLY_EXITED	  0x05
#define ERLKOENIG_TAG_REPLY_STATUS	  0x06
#define ERLKOENIG_TAG_REPLY_STDOUT	  0x07
#define ERLKOENIG_TAG_REPLY_STDERR	  0x08
#define ERLKOENIG_TAG_REPLY_METRICS_EVENT 0x09

/* -- Container command tags (Erlang -> C, 0x10-0x1F) -------------- */

#define ERLKOENIG_TAG_CMD_SPAWN		0x10
#define ERLKOENIG_TAG_CMD_GO		0x11
#define ERLKOENIG_TAG_CMD_KILL		0x12
#define ERLKOENIG_TAG_CMD_CGROUP_SET	0x13
#define ERLKOENIG_TAG_CMD_QUERY_STATUS	0x14
#define ERLKOENIG_TAG_CMD_NET_SETUP	0x15
#define ERLKOENIG_TAG_CMD_WRITE_FILE	0x16
#define ERLKOENIG_TAG_CMD_STDIN		0x17
#define ERLKOENIG_TAG_CMD_RESIZE	0x18
#define ERLKOENIG_TAG_CMD_DEVICE_FILTER 0x19
#define ERLKOENIG_TAG_CMD_METRICS_START 0x1A
#define ERLKOENIG_TAG_CMD_METRICS_STOP	0x1B
#define ERLKOENIG_TAG_CMD_NFT_SETUP	0x1C
#define ERLKOENIG_TAG_CMD_NFT_LIST	0x1D

/* -- Spawn flags -------------------------------------------------- */

#define ERLKOENIG_SPAWN_FLAG_PTY 0x01

/* -- Tag name lookup ---------------------------------------------- */

static inline const char *erlkoenig_tag_name(uint8_t tag)
{
	switch (tag) {
	case 0x01:
		return "REPLY_OK";
	case 0x02:
		return "REPLY_ERROR";
	case 0x03:
		return "REPLY_CONTAINER_PID";
	case 0x04:
		return "REPLY_READY";
	case 0x05:
		return "REPLY_EXITED";
	case 0x06:
		return "REPLY_STATUS";
	case 0x07:
		return "REPLY_STDOUT";
	case 0x08:
		return "REPLY_STDERR";
	case 0x09:
		return "REPLY_METRICS_EVENT";
	case 0x10:
		return "CMD_SPAWN";
	case 0x11:
		return "CMD_GO";
	case 0x12:
		return "CMD_KILL";
	case 0x13:
		return "CMD_CGROUP_SET";
	case 0x14:
		return "CMD_QUERY_STATUS";
	case 0x15:
		return "CMD_NET_SETUP";
	case 0x16:
		return "CMD_WRITE_FILE";
	case 0x17:
		return "CMD_STDIN";
	case 0x18:
		return "CMD_RESIZE";
	case 0x19:
		return "CMD_DEVICE_FILTER";
	case 0x1A:
		return "CMD_METRICS_START";
	case 0x1B:
		return "CMD_METRICS_STOP";
	case 0x1C:
		return "CMD_NFT_SETUP";
	case 0x1D:
		return "CMD_NFT_LIST";
	default:
		return "UNKNOWN";
	}
}

#endif /* ERLKOENIG_PROTO_H */
