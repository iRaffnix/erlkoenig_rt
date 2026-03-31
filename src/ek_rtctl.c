/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * ek_rtctl — Minimal CLI client for erlkoenig_rt wire protocol.
 *
 * Replaces the Go CLI (ek_ctl) with a small C binary that speaks
 * the same {packet,4} + TLV protocol over Unix socket.
 *
 * Build:  musl-gcc -static -O2 -o ek_rtctl ek_rtctl.c -Iinclude
 * Usage:
 *   ek_rtctl <socket> spawn --path /app --image /tmp/app.erofs [opts]
 *   ek_rtctl <socket> go
 *   ek_rtctl <socket> status
 *   ek_rtctl <socket> kill [signal]
 *   ek_rtctl <socket> watch
 */

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "erlkoenig_buf.h"
#include "erlkoenig_tlv.h"
#include "erlkoenig_proto.h"

/* --- I/O --- */

static int ek_connect(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "connect(%s): %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}

	/* Handshake: send protocol version, receive server version */
	uint8_t ver = ERLKOENIG_PROTOCOL_VERSION;
	uint32_t hshdr = htonl(1);

	if (write(fd, &hshdr, 4) != 4 || write(fd, &ver, 1) != 1) {
		fprintf(stderr, "handshake send failed\n");
		close(fd);
		return -1;
	}

	uint8_t rbuf[16];
	uint32_t rhdr;

	if (read(fd, &rhdr, 4) != 4) {
		fprintf(stderr, "handshake recv failed\n");
		close(fd);
		return -1;
	}
	uint32_t rlen = ntohl(rhdr);

	if (rlen > sizeof(rbuf) || rlen < 1) {
		fprintf(stderr, "handshake: bad length %u\n", rlen);
		close(fd);
		return -1;
	}
	if (read(fd, rbuf, rlen) != (ssize_t)rlen) {
		fprintf(stderr, "handshake: short read\n");
		close(fd);
		return -1;
	}
	if (rbuf[0] != ERLKOENIG_PROTOCOL_VERSION) {
		fprintf(stderr, "handshake: server version %u, expected %u\n",
			rbuf[0], ERLKOENIG_PROTOCOL_VERSION);
		close(fd);
		return -1;
	}

	return fd;
}

static int send_frame(int fd, const uint8_t *payload, size_t len)
{
	uint32_t hdr = htonl((uint32_t)len);
	ssize_t w;

	w = write(fd, &hdr, 4);
	if (w != 4)
		return -1;
	if (len > 0) {
		w = write(fd, payload, len);
		if (w != (ssize_t)len)
			return -1;
	}
	return 0;
}

static ssize_t recv_frame(int fd, uint8_t *buf, size_t bufsz)
{
	uint32_t hdr;
	size_t got = 0;

	while (got < 4) {
		ssize_t r = read(fd, ((uint8_t *)&hdr) + got, 4 - got);
		if (r <= 0)
			return -1;
		got += (size_t)r;
	}

	uint32_t plen = ntohl(hdr);

	if (plen > bufsz)
		return -1;

	got = 0;
	while (got < plen) {
		ssize_t r = read(fd, buf + got, plen - got);
		if (r <= 0)
			return -1;
		got += (size_t)r;
	}
	return (ssize_t)plen;
}

static int send_msg(int fd, uint8_t tag, const uint8_t *attrs, size_t len)
{
	uint8_t frame[4096];
	struct erlkoenig_buf b;

	erlkoenig_buf_init(&b, frame, sizeof(frame));
	buf_write_u8(&b, tag);
	buf_write_u8(&b, ERLKOENIG_PROTOCOL_VERSION);
	if (len > 0 && attrs)
		buf_write_bytes(&b, attrs, len);

	return send_frame(fd, frame, b.pos);
}

/* --- reply printing --- */

static void print_reply(const uint8_t *buf, ssize_t n)
{
	if (n < 2)
		return;

	uint8_t tag = buf[0];

	printf("%s", erlkoenig_tag_name(tag));

	struct erlkoenig_buf ab;

	erlkoenig_buf_init(&ab, (uint8_t *)(uintptr_t)(buf + 2),
			   (size_t)(n - 2));

	struct ek_tlv a;

	switch (tag) {
	case ERLKOENIG_TAG_REPLY_OK:
		printf("\n");
		break;
	case ERLKOENIG_TAG_REPLY_ERROR:
		while (ek_tlv_next(&ab, &a) == 0) {
			if (a.type == EK_ATTR_CODE)
				printf(" code=%d", ek_tlv_i32(&a));
			else if (a.type == EK_ATTR_MESSAGE)
				printf(" msg=%.*s", a.len, a.value);
		}
		printf("\n");
		break;
	case ERLKOENIG_TAG_REPLY_CONTAINER_PID:
		while (ek_tlv_next(&ab, &a) == 0) {
			if (a.type == EK_ATTR_PID)
				printf(" PID=%u", ek_tlv_u32(&a));
			else if (a.type == EK_ATTR_NETNS_PATH)
				printf(" netns=%.*s", a.len, a.value);
		}
		printf("\n");
		break;
	case ERLKOENIG_TAG_REPLY_READY:
		printf("\n");
		break;
	case ERLKOENIG_TAG_REPLY_EXITED:
		while (ek_tlv_next(&ab, &a) == 0) {
			if (a.type == EK_ATTR_EXIT_CODE)
				printf(" exit=%d", ek_tlv_i32(&a));
			else if (a.type == EK_ATTR_TERM_SIGNAL)
				printf(" signal=%u", ek_tlv_u8(&a));
		}
		printf("\n");
		break;
	case ERLKOENIG_TAG_REPLY_STATUS:
		while (ek_tlv_next(&ab, &a) == 0) {
			if (a.type == EK_ATTR_STATE)
				printf(" state=%u", ek_tlv_u8(&a));
			else if (a.type == EK_ATTR_PID)
				printf(" pid=%u", ek_tlv_u32(&a));
			else if (a.type == EK_ATTR_UPTIME_MS)
				printf(" uptime=%llums",
				       (unsigned long long)ek_tlv_u64(&a));
		}
		printf("\n");
		break;
	case ERLKOENIG_TAG_REPLY_STDOUT:
		if (n > 2)
			fwrite(buf + 2, 1, (size_t)(n - 2), stdout);
		break;
	case ERLKOENIG_TAG_REPLY_STDERR:
		if (n > 2)
			fwrite(buf + 2, 1, (size_t)(n - 2), stderr);
		break;
	default:
		printf(" (tag=0x%02x, %zd bytes)\n", tag, n - 2);
		break;
	}
}

/* --- commands --- */

static uint64_t parse_memory(const char *s)
{
	char *end;
	unsigned long long v = strtoull(s, &end, 10);

	switch (*end) {
	case 'G':
	case 'g':
		v *= 1024 * 1024 * 1024;
		break;
	case 'M':
	case 'm':
		v *= 1024 * 1024;
		break;
	case 'K':
	case 'k':
		v *= 1024;
		break;
	}
	return (uint64_t)v;
}

static int cmd_spawn(int fd, int argc, char **argv)
{
	uint8_t attrs[4096];
	struct erlkoenig_buf ab;

	erlkoenig_buf_init(&ab, attrs, sizeof(attrs));

	/* Defaults */
	ek_tlv_put_u32(&ab, EK_ATTR_UID, 65534); /* nobody */
	ek_tlv_put_u32(&ab, EK_ATTR_GID, 65534);

	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
			ek_tlv_put_str(&ab, EK_ATTR_PATH, argv[++i]);
		} else if (strcmp(argv[i], "--image") == 0 && i + 1 < argc) {
			ek_tlv_put_str(&ab, EK_ATTR_IMAGE_PATH, argv[++i]);
		} else if (strcmp(argv[i], "--uid") == 0 && i + 1 < argc) {
			/* Already written defaults, just overwrite — TLV
			 * last-value-wins for non-repeated attrs */
			ek_tlv_put_u32(&ab, EK_ATTR_UID,
				       (uint32_t)strtoul(argv[++i], NULL, 10));
		} else if (strcmp(argv[i], "--gid") == 0 && i + 1 < argc) {
			ek_tlv_put_u32(&ab, EK_ATTR_GID,
				       (uint32_t)strtoul(argv[++i], NULL, 10));
		} else if (strcmp(argv[i], "--memory") == 0 && i + 1 < argc) {
			ek_tlv_put_u64(&ab, EK_ATTR_MEMORY_MAX,
				       parse_memory(argv[++i]));
		} else if (strcmp(argv[i], "--pids") == 0 && i + 1 < argc) {
			ek_tlv_put_u32(&ab, EK_ATTR_PIDS_MAX,
				       (uint32_t)strtoul(argv[++i], NULL, 10));
		} else if (strcmp(argv[i], "--seccomp") == 0 && i + 1 < argc) {
			ek_tlv_put_u8(&ab, EK_ATTR_SECCOMP,
				      (uint8_t)strtoul(argv[++i], NULL, 10));
		} else if (strcmp(argv[i], "--arg") == 0 && i + 1 < argc) {
			ek_tlv_put_str(&ab, EK_ATTR_ARG, argv[++i]);
		} else if (strcmp(argv[i], "--env") == 0 && i + 1 < argc) {
			/* env format: KEY=VALUE → "KEY\0VALUE" */
			char *kv = argv[++i];
			char *eq = strchr(kv, '=');

			if (eq) {
				*eq = '\0';
				size_t klen = strlen(kv);
				size_t vlen = strlen(eq + 1);
				uint8_t envbuf[512];

				memcpy(envbuf, kv, klen);
				envbuf[klen] = '\0';
				memcpy(envbuf + klen + 1, eq + 1, vlen);
				ek_tlv_put(&ab, EK_ATTR_ENV, envbuf,
					   (uint16_t)(klen + 1 + vlen));
				*eq = '='; /* restore */
			}
		} else if (strcmp(argv[i], "--pty") == 0) {
			ek_tlv_put_u32(&ab, EK_ATTR_FLAGS,
				       ERLKOENIG_SPAWN_FLAG_PTY);
		} else if (strcmp(argv[i], "--cpu-weight") == 0 &&
			   i + 1 < argc) {
			ek_tlv_put_u32(&ab, EK_ATTR_CPU_WEIGHT,
				       (uint32_t)strtoul(argv[++i], NULL, 10));
		}
	}

	if (send_msg(fd, ERLKOENIG_TAG_CMD_SPAWN, attrs, ab.pos) < 0)
		return 1;

	uint8_t reply[4096];
	ssize_t n = recv_frame(fd, reply, sizeof(reply));

	if (n < 2)
		return 1;

	print_reply(reply, n);

	return (reply[0] == ERLKOENIG_TAG_REPLY_CONTAINER_PID) ? 0 : 1;
}

static int cmd_simple(int fd, uint8_t tag)
{
	if (send_msg(fd, tag, NULL, 0) < 0)
		return 1;

	uint8_t reply[4096];
	ssize_t n = recv_frame(fd, reply, sizeof(reply));

	if (n < 2)
		return 1;

	print_reply(reply, n);
	return (reply[0] == ERLKOENIG_TAG_REPLY_OK ||
		reply[0] == ERLKOENIG_TAG_REPLY_STATUS ||
		reply[0] == ERLKOENIG_TAG_REPLY_READY)
		       ? 0
		       : 1;
}

static int cmd_kill(int fd, uint8_t sig)
{
	uint8_t attrs[8];
	struct erlkoenig_buf ab;

	erlkoenig_buf_init(&ab, attrs, sizeof(attrs));
	ek_tlv_put_u8(&ab, EK_ATTR_SIGNAL, sig);

	if (send_msg(fd, ERLKOENIG_TAG_CMD_KILL, attrs, ab.pos) < 0)
		return 1;

	uint8_t reply[4096];
	ssize_t n = recv_frame(fd, reply, sizeof(reply));

	if (n < 2)
		return 1;

	print_reply(reply, n);
	return 0;
}

static volatile int g_watching = 1;

static void watch_signal(int sig)
{
	(void)sig;
	g_watching = 0;
}

static int cmd_watch(int fd)
{
	signal(SIGINT, watch_signal);
	signal(SIGTERM, watch_signal);

	uint8_t reply[65536];

	while (g_watching) {
		ssize_t n = recv_frame(fd, reply, sizeof(reply));

		if (n < 2)
			break;

		print_reply(reply, n);

		/* Stop on EXITED */
		if (reply[0] == ERLKOENIG_TAG_REPLY_EXITED)
			break;
	}
	return 0;
}

/* --- main --- */

static void usage(void)
{
	fprintf(stderr,
		"Usage: ek_rtctl <socket> <command> [options]\n"
		"\n"
		"Commands:\n"
		"  spawn --path PATH --image IMG [--memory N] [--pids N] "
		"[--env K=V] [--arg A]\n"
		"  go\n"
		"  status\n"
		"  kill [signal]\n"
		"  watch\n");
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		usage();
		return 1;
	}

	const char *sock = argv[1];
	const char *cmd = argv[2];

	int fd = ek_connect(sock);

	if (fd < 0)
		return 1;

	int rc;

	if (strcmp(cmd, "spawn") == 0) {
		rc = cmd_spawn(fd, argc - 3, argv + 3);
	} else if (strcmp(cmd, "go") == 0) {
		rc = cmd_simple(fd, ERLKOENIG_TAG_CMD_GO);
	} else if (strcmp(cmd, "status") == 0) {
		rc = cmd_simple(fd, ERLKOENIG_TAG_CMD_QUERY_STATUS);
	} else if (strcmp(cmd, "kill") == 0) {
		uint8_t sig = 15; /* SIGTERM */
		if (argc > 3)
			sig = (uint8_t)strtoul(argv[3], NULL, 10);
		rc = cmd_kill(fd, sig);
	} else if (strcmp(cmd, "watch") == 0) {
		rc = cmd_watch(fd);
	} else {
		fprintf(stderr, "unknown command: %s\n", cmd);
		usage();
		rc = 1;
	}

	close(fd);
	return rc;
}
