/*
 * run_probe_one.c — single-connection harness for one boundary probe.
 *
 * Holds one connection to erlkoenig_rt for the entire spawn → go →
 * watch lifecycle, eliminating the disconnect-race window where a
 * REPLY_EXITED could be buffered (rt.c:1550–1559) and never delivered
 * because cmd_watch() doesn't ask for STATUS.
 *
 * Output (machine-parseable, single line):
 *   spawn_pid=<PID> exit_code=<INT> term_signal=<UINT> stderr=<base64>
 *
 * Exit codes:
 *   0  normal — exit_code/term_signal set as the container reported
 *   2  internal error (connect/spawn/go failed before container ran)
 *   3  watch timeout (container never delivered REPLY_EXITED)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "erlkoenig_buf.h"
#include "erlkoenig_proto.h"
#include "erlkoenig_tlv.h"

static int connect_socket(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "connect(%s): %s\n", path, strerror(errno));
		close(fd);
		return -1;
	}
	uint8_t ver = ERLKOENIG_PROTOCOL_VERSION;
	uint32_t hshdr = htonl(1);
	if (write(fd, &hshdr, 4) != 4 || write(fd, &ver, 1) != 1) {
		close(fd);
		return -1;
	}
	uint32_t rhdr;
	if (read(fd, &rhdr, 4) != 4) {
		close(fd);
		return -1;
	}
	uint32_t rlen = ntohl(rhdr);
	uint8_t rbuf[16];
	if (rlen > sizeof(rbuf) || read(fd, rbuf, rlen) != (ssize_t)rlen ||
	    rbuf[0] != ERLKOENIG_PROTOCOL_VERSION) {
		close(fd);
		return -1;
	}
	return fd;
}

static int send_frame(int fd, const uint8_t *p, size_t n)
{
	uint32_t hdr = htonl((uint32_t)n);
	if (write(fd, &hdr, 4) != 4)
		return -1;
	if (n > 0 && write(fd, p, n) != (ssize_t)n)
		return -1;
	return 0;
}

/* Read one frame with a deadline (ms since epoch). Returns -2 on timeout. */
static ssize_t recv_frame_deadline(int fd, uint8_t *buf, size_t bufsz,
				   long deadline_ms)
{
	uint8_t hdrbuf[4];
	size_t got = 0;
	while (got < 4) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long now_ms = (long)now.tv_sec * 1000L + now.tv_nsec / 1000000L;
		long remaining = deadline_ms - now_ms;
		if (remaining <= 0)
			return -2;
		struct pollfd p = {.fd = fd, .events = POLLIN};
		int pr = poll(&p, 1, (int)remaining);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (pr == 0)
			return -2;
		ssize_t r = read(fd, hdrbuf + got, 4 - got);
		if (r <= 0)
			return -1;
		got += (size_t)r;
	}
	uint32_t plen = ntohl(*(uint32_t *)hdrbuf);
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

static long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int send_spawn(int fd, const char *binary_path, uint8_t profile)
{
	uint8_t attrs[1024];
	struct erlkoenig_buf ab;
	erlkoenig_buf_init(&ab, attrs, sizeof(attrs));
	ek_tlv_put_u32(&ab, EK_ATTR_UID, 0);
	ek_tlv_put_u32(&ab, EK_ATTR_GID, 0);
	ek_tlv_put_str(&ab, EK_ATTR_PATH, binary_path);
	ek_tlv_put_u8(&ab, EK_ATTR_SECCOMP, profile);

	uint8_t frame[1100];
	struct erlkoenig_buf fb;
	erlkoenig_buf_init(&fb, frame, sizeof(frame));
	buf_write_u8(&fb, ERLKOENIG_TAG_CMD_SPAWN);
	buf_write_u8(&fb, ERLKOENIG_PROTOCOL_VERSION);
	buf_write_bytes(&fb, attrs, ab.pos);
	return send_frame(fd, frame, fb.pos);
}

static int send_go(int fd)
{
	uint8_t frame[2] = {ERLKOENIG_TAG_CMD_GO, ERLKOENIG_PROTOCOL_VERSION};
	return send_frame(fd, frame, 2);
}

static void usage(const char *a0)
{
	fprintf(stderr,
		"Usage: %s --socket SOCK --probe PATH "
		"--profile {1|2|3} [--timeout-ms MS]\n",
		a0);
}

int main(int argc, char **argv)
{
	const char *sock = NULL, *probe = NULL;
	int profile = 1;
	long timeout_ms = 15000;

	static const struct option opts[] = {
	    {"socket", required_argument, NULL, 's'},
	    {"probe", required_argument, NULL, 'p'},
	    {"profile", required_argument, NULL, 'P'},
	    {"timeout-ms", required_argument, NULL, 't'},
	    {NULL, 0, NULL, 0},
	};
	int c;
	while ((c = getopt_long(argc, argv, "s:p:P:t:", opts, NULL)) != -1) {
		switch (c) {
		case 's': sock = optarg; break;
		case 'p': probe = optarg; break;
		case 'P': profile = atoi(optarg); break;
		case 't': timeout_ms = atol(optarg); break;
		default:  usage(argv[0]); return 2;
		}
	}
	if (!sock || !probe) {
		usage(argv[0]);
		return 2;
	}

	int fd = connect_socket(sock);
	if (fd < 0) {
		fprintf(stderr, "ERROR: cannot connect to %s\n", sock);
		return 2;
	}

	long deadline = now_ms() + timeout_ms;

	/* SPAWN */
	if (send_spawn(fd, probe, (uint8_t)profile) < 0) {
		fprintf(stderr, "ERROR: send SPAWN failed\n");
		return 2;
	}
	uint8_t reply[65536];
	ssize_t n = recv_frame_deadline(fd, reply, sizeof(reply), deadline);
	if (n < 2) {
		fprintf(stderr, "ERROR: no SPAWN reply (n=%zd)\n", n);
		return 2;
	}
	if (reply[0] != ERLKOENIG_TAG_REPLY_CONTAINER_PID) {
		struct erlkoenig_buf rb;
		erlkoenig_buf_init(&rb, (uint8_t *)(reply + 2),
				   (size_t)(n - 2));
		struct ek_tlv a;
		int32_t code = 0;
		const char *msg = "?";
		size_t msglen = 1;
		while (ek_tlv_next(&rb, &a) == 0) {
			if (a.type == EK_ATTR_CODE)
				code = ek_tlv_i32(&a);
			else if (a.type == EK_ATTR_MESSAGE) {
				msg = (const char *)a.value;
				msglen = a.len;
			}
		}
		fprintf(stderr, "ERROR: SPAWN rejected: code=%d msg=%.*s\n",
			code, (int)msglen, msg);
		return 2;
	}

	uint32_t spawn_pid = 0;
	{
		struct erlkoenig_buf rb;
		erlkoenig_buf_init(&rb, (uint8_t *)(reply + 2),
				   (size_t)(n - 2));
		struct ek_tlv a;
		while (ek_tlv_next(&rb, &a) == 0)
			if (a.type == EK_ATTR_PID)
				spawn_pid = ek_tlv_u32(&a);
	}

	/* GO */
	if (send_go(fd) < 0) {
		fprintf(stderr, "ERROR: send GO failed\n");
		return 2;
	}
	n = recv_frame_deadline(fd, reply, sizeof(reply), deadline);
	if (n < 2 || reply[0] != ERLKOENIG_TAG_REPLY_OK) {
		fprintf(stderr, "ERROR: GO did not return REPLY_OK (n=%zd)\n",
			n);
		return 2;
	}

	/* Watch loop — same connection, so REPLY_EXITED is delivered live. */
	int got_exited = 0;
	int32_t exit_code = -999;
	uint8_t term_signal = 0;
	char stderr_buf[8192];
	size_t stderr_len = 0;

	while (!got_exited) {
		n = recv_frame_deadline(fd, reply, sizeof(reply), deadline);
		if (n == -2) {
			fprintf(stderr,
				"ERROR: watch timeout — no REPLY_EXITED\n");
			close(fd);
			return 3;
		}
		if (n < 2) {
			fprintf(stderr, "ERROR: socket closed unexpectedly\n");
			close(fd);
			return 2;
		}
		switch (reply[0]) {
		case ERLKOENIG_TAG_REPLY_STDERR:
			if (n > 2) {
				size_t take = (size_t)(n - 2);
				if (take + stderr_len >= sizeof(stderr_buf))
					take = sizeof(stderr_buf) - 1
					       - stderr_len;
				memcpy(stderr_buf + stderr_len, reply + 2,
				       take);
				stderr_len += take;
				stderr_buf[stderr_len] = '\0';
			}
			break;
		case ERLKOENIG_TAG_REPLY_STDOUT:
			/* container stdout is ignored for boundary probes */
			break;
		case ERLKOENIG_TAG_REPLY_EXITED: {
			struct erlkoenig_buf rb;
			erlkoenig_buf_init(&rb, (uint8_t *)(reply + 2),
					   (size_t)(n - 2));
			struct ek_tlv a;
			while (ek_tlv_next(&rb, &a) == 0) {
				if (a.type == EK_ATTR_EXIT_CODE)
					exit_code = ek_tlv_i32(&a);
				else if (a.type == EK_ATTR_TERM_SIGNAL)
					term_signal = ek_tlv_u8(&a);
			}
			got_exited = 1;
			break;
		}
		default:
			/* ignore other tags (status etc) */
			break;
		}
	}

	close(fd);

	/* Print result on stdout, in a parseable shape. stderr text goes on
	 * the stderr stream so the harness can surface FINDING/OK/SKIP. */
	printf("spawn_pid=%u exit_code=%d term_signal=%u\n", spawn_pid,
	       exit_code, term_signal);
	if (stderr_len > 0)
		fwrite(stderr_buf, 1, stderr_len, stderr);
	return 0;
}
