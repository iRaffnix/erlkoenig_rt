/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * gateway.c — Function-as-a-Service gateway for erlkoenig.
 *
 * HTTP server that spawns an isolated container per request.
 * Each container connects to PostgreSQL, computes a risk score,
 * and returns JSON. The container is destroyed after each request.
 *
 * Cold start: ~15ms. Full isolation per request. Real DB queries.
 *
 * Usage:
 *   gateway --image /tmp/risk_scorer.erofs [--port 8080]
 *
 * Endpoints:
 *   GET /score?customer=42&amount=1500&country=RU
 *   GET /health
 *   GET /stats
 *
 * Build: cmake --build build (or: make)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "erlkoenig_buf.h"
#include "erlkoenig_tlv.h"
#include "erlkoenig_proto.h"
#include "erlkoenig_netcfg.h"

/* --- config --- */

#define MAX_SLOTS      64
#define LISTEN_PORT    8080
#define VETH_SUBNET    "10.1"
#define RECV_TIMEOUT_S 10

static const char *g_runtime_path = "/usr/lib/erlkoenig/erlkoenig_rt";
static const char *g_image_path = "/tmp/risk_scorer.erofs";
static volatile int g_running = 1;

static atomic_uint g_total_requests;
static atomic_uint g_total_errors;
static atomic_uint g_active;
static atomic_uint g_next_slot;
static atomic_int g_slot_busy[MAX_SLOTS];

static int acquire_slot(void)
{
	for (int tries = 0; tries < MAX_SLOTS * 4; tries++) {
		int s = (int)(atomic_fetch_add(&g_next_slot, 1) % MAX_SLOTS);
		int expected = 0;

		if (atomic_compare_exchange_strong(&g_slot_busy[s], &expected,
						   1))
			return s;
	}
	return -1;
}

static void release_slot(int slot)
{
	atomic_store(&g_slot_busy[slot], 0);
}

/* --- timing --- */

static uint64_t now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

/* --- TLV client --- */

static int tlv_connect(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;

	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	/* Receive timeout */
	struct timeval tv = {.tv_sec = RECV_TIMEOUT_S};

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* Handshake */
	uint8_t ver = ERLKOENIG_PROTOCOL_VERSION;
	uint32_t hdr = htonl(1);

	if (write(fd, &hdr, 4) != 4 || write(fd, &ver, 1) != 1) {
		close(fd);
		return -1;
	}

	uint8_t rbuf[16];
	uint32_t rhdr;

	if (read(fd, &rhdr, 4) != 4) {
		close(fd);
		return -1;
	}
	uint32_t rlen = ntohl(rhdr);

	if (rlen > sizeof(rbuf) || rlen < 1) {
		close(fd);
		return -1;
	}
	if (read(fd, rbuf, rlen) != (ssize_t)rlen) {
		close(fd);
		return -1;
	}

	return fd;
}

static int tlv_send(int fd, uint8_t tag, const uint8_t *attrs, size_t len)
{
	uint8_t frame[4096];
	size_t msg_len = 2 + len;
	uint32_t pkt_len = htonl((uint32_t)msg_len);

	if (msg_len > sizeof(frame) - 4)
		return -1;

	memcpy(frame, &pkt_len, 4);
	frame[4] = tag;
	frame[5] = ERLKOENIG_PROTOCOL_VERSION;
	if (len > 0 && attrs)
		memcpy(frame + 6, attrs, len);

	size_t total = 4 + msg_len;
	size_t sent = 0;

	while (sent < total) {
		ssize_t w = write(fd, frame + sent, total - sent);

		if (w <= 0)
			return -1;
		sent += (size_t)w;
	}
	return 0;
}

static ssize_t tlv_recv(int fd, uint8_t *buf, size_t bufsz)
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

/* --- network setup (netlink, no shell) --- */

static int setup_veth(int slot, uint32_t ct_pid)
{
	char veth[16];
	uint32_t host_ip;
	int ret;

	snprintf(veth, sizeof(veth), "vek%u", ct_pid);

	/* Host IP: VETH_SUBNET.slot.1 → e.g. 10.1.3.1 */
	host_ip = (10U << 24) | (1U << 16) | ((uint32_t)slot << 8) | 1U;

	/* Phase 1: create veth, move peer, configure host side */
	ret = erlkoenig_netcfg_veth_create((pid_t)ct_pid, veth, "eth0", host_ip,
					   24);
	if (ret)
		return ret;

	/* Phase 2: configure container side (IP, UP, route) */
	{
		uint32_t ct_ip =
		    (10U << 24) | (1U << 16) | ((uint32_t)slot << 8) | 2U;
		uint32_t gw_ip = host_ip;

		ret = erlkoenig_netcfg_setup((pid_t)ct_pid, "eth0", ct_ip, 24,
					     gw_ip);
	}

	if (ret)
		erlkoenig_netcfg_veth_destroy(veth);

	return ret;
}

static void teardown_veth(uint32_t ct_pid)
{
	char veth[16];

	snprintf(veth, sizeof(veth), "vek%u", ct_pid);
	erlkoenig_netcfg_veth_destroy(veth);
}

/* --- container lifecycle --- */

static int run_container(int slot, int customer_id, double amount,
			 const char *country, char *result, size_t result_sz,
			 uint64_t *spawn_us, uint64_t *total_us)
{
	uint64_t t0 = now_us();
	char sock_path[64];

	snprintf(sock_path, sizeof(sock_path), "/tmp/ek-gw-%d.sock", slot);

	/* 1. Start runtime */
	unlink(sock_path);
	pid_t rt_pid = fork();

	if (rt_pid == 0) {
		int devnull = open("/dev/null", O_RDWR);

		if (devnull >= 0) {
			dup2(devnull, 1);
			dup2(devnull, 2);
			close(devnull);
		}
		execl(g_runtime_path, "erlkoenig_rt", "--socket", sock_path,
		      NULL);
		_exit(127);
	}
	if (rt_pid < 0)
		return -1;

	/* Wait for socket (max 500ms) */
	for (int tries = 0; tries < 500; tries++) {
		if (access(sock_path, F_OK) == 0)
			break;
		usleep(1000);
	}

	int rt_fd = tlv_connect(sock_path);

	if (rt_fd < 0)
		goto fail_kill;

	/* 2. Spawn */
	uint8_t attrs[2048];
	struct erlkoenig_buf ab;

	erlkoenig_buf_init(&ab, attrs, sizeof(attrs));
	ek_tlv_put_str(&ab, EK_ATTR_PATH, "/app");
	ek_tlv_put_str(&ab, EK_ATTR_IMAGE_PATH, g_image_path);
	ek_tlv_put_u32(&ab, EK_ATTR_UID, 65534);
	ek_tlv_put_u32(&ab, EK_ATTR_GID, 65534);
	ek_tlv_put_u64(&ab, EK_ATTR_MEMORY_MAX, 64 * 1024 * 1024);
	ek_tlv_put_u32(&ab, EK_ATTR_PIDS_MAX, 10);

	char arg1[16], arg2[32];

	snprintf(arg1, sizeof(arg1), "%d", customer_id);
	snprintf(arg2, sizeof(arg2), "%.2f", amount);
	ek_tlv_put_str(&ab, EK_ATTR_ARG, arg1);
	ek_tlv_put_str(&ab, EK_ATTR_ARG, arg2);
	ek_tlv_put_str(&ab, EK_ATTR_ARG, country);

	/* PG_HOST = host-side veth IP */
	char pg_host[32];

	snprintf(pg_host, sizeof(pg_host), "%s.%d.1", VETH_SUBNET, slot);

	char envbuf[128];
	size_t klen = 7;
	size_t vlen = strlen(pg_host);

	memcpy(envbuf, "PG_HOST", klen);
	envbuf[klen] = '\0';
	memcpy(envbuf + klen + 1, pg_host, vlen);
	ek_tlv_put(&ab, EK_ATTR_ENV, envbuf, (uint16_t)(klen + 1 + vlen));

	if (tlv_send(rt_fd, ERLKOENIG_TAG_CMD_SPAWN, attrs, ab.pos) < 0)
		goto fail_close;

	uint8_t reply[8192];
	ssize_t n = tlv_recv(rt_fd, reply, sizeof(reply));

	if (n < 2 || reply[0] != ERLKOENIG_TAG_REPLY_CONTAINER_PID)
		goto fail_close;

	uint32_t ct_pid = 0;
	struct erlkoenig_buf rb;

	erlkoenig_buf_init(&rb, reply + 2, (size_t)(n - 2));

	struct ek_tlv a;

	while (ek_tlv_next(&rb, &a) == 0) {
		if (a.type == EK_ATTR_PID)
			ct_pid = ek_tlv_u32(&a);
	}
	if (ct_pid == 0)
		goto fail_close;

	uint64_t t_spawned = now_us();

	*spawn_us = t_spawned - t0;

	/* 3. Network */
	if (setup_veth(slot, ct_pid) < 0)
		goto fail_close;

	/* 4. Go */
	if (tlv_send(rt_fd, ERLKOENIG_TAG_CMD_GO, NULL, 0) < 0)
		goto fail_cleanup;

	/* 5. Read replies until EXITED */
	atomic_fetch_add(&g_active, 1);
	result[0] = '\0';
	size_t rpos = 0;

	for (int msgs = 0; msgs < 50; msgs++) {
		n = tlv_recv(rt_fd, reply, sizeof(reply));
		if (n < 2)
			break;

		uint8_t tag = reply[0];

		if (tag == ERLKOENIG_TAG_REPLY_STDOUT && n > 2) {
			size_t dlen = (size_t)(n - 2);

			if (rpos + dlen < result_sz - 1) {
				memcpy(result + rpos, reply + 2, dlen);
				rpos += dlen;
			}
		} else if (tag == ERLKOENIG_TAG_REPLY_EXITED) {
			break;
		}
		/* REPLY_OK, REPLY_READY, REPLY_STDERR — continue */
	}
	result[rpos] = '\0';
	atomic_fetch_sub(&g_active, 1);

	/* 6. Cleanup */
	close(rt_fd);
	teardown_veth(ct_pid);
	kill(rt_pid, SIGTERM);
	waitpid(rt_pid, NULL, 0);
	unlink(sock_path);

	*total_us = now_us() - t0;
	return (rpos > 0) ? 0 : -1;

fail_cleanup:
	teardown_veth(ct_pid);
fail_close:
	close(rt_fd);
fail_kill:
	kill(rt_pid, SIGKILL);
	waitpid(rt_pid, NULL, 0);
	unlink(sock_path);
	*total_us = now_us() - t0;
	return -1;
}

/* --- HTTP --- */

static void parse_query(const char *uri, int *customer, double *amount,
			char *country, size_t country_sz)
{
	*customer = 1;
	*amount = 100.0;
	strncpy(country, "DE", country_sz);

	const char *q = strchr(uri, '?');

	if (!q)
		return;
	q++;

	char buf[512];

	strncpy(buf, q, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	char *tok = strtok(buf, "&");

	while (tok) {
		char *eq = strchr(tok, '=');

		if (eq) {
			*eq = '\0';
			if (strcmp(tok, "customer") == 0)
				*customer = atoi(eq + 1);
			else if (strcmp(tok, "amount") == 0)
				*amount = atof(eq + 1);
			else if (strcmp(tok, "country") == 0)
				strncpy(country, eq + 1, country_sz - 1);
		}
		tok = strtok(NULL, "&");
	}
}

static void handle_http(int cfd)
{
	char req[2048];
	ssize_t n = read(cfd, req, sizeof(req) - 1);

	if (n <= 0) {
		close(cfd);
		return;
	}
	req[n] = '\0';

	char method[8] = "", uri[256] = "";

	sscanf(req, "%7s %255s", method, uri);

	char resp[8192];
	int resp_len;

	if (strcmp(method, "GET") == 0 && strncmp(uri, "/score", 6) == 0) {
		int customer;
		double amount;
		char country[8];

		parse_query(uri, &customer, &amount, country, sizeof(country));

		int slot = acquire_slot();
		char result[4096];
		uint64_t spawn_t = 0, total_t = 0;

		atomic_fetch_add(&g_total_requests, 1);

		if (slot < 0) {
			resp_len =
			    snprintf(resp, sizeof(resp),
				     "HTTP/1.1 503 Service Unavailable\r\n"
				     "Content-Type: application/json\r\n\r\n"
				     "{\"error\":\"no_slots_available\"}");
			(void)write(cfd, resp, (size_t)resp_len);
			close(cfd);
			atomic_fetch_add(&g_total_errors, 1);
			return;
		}

		int rc = run_container(slot, customer, amount, country, result,
				       sizeof(result), &spawn_t, &total_t);
		release_slot(slot);

		if (rc == 0 && result[0]) {
			/* Inject timing into JSON */
			size_t rlen = strlen(result);

			while (rlen > 0 && (result[rlen - 1] == '\n' ||
					    result[rlen - 1] == ' '))
				rlen--;
			if (rlen > 0 && result[rlen - 1] == '}')
				rlen--;
			result[rlen] = '\0';

			char body[4096];
			int blen = snprintf(body, sizeof(body),
					    "%s,\"spawn_ms\":%.1f,"
					    "\"total_ms\":%.1f}\n",
					    result, spawn_t / 1000.0,
					    total_t / 1000.0);

			resp_len = snprintf(resp, sizeof(resp),
					    "HTTP/1.1 200 OK\r\n"
					    "Content-Type: application/json\r\n"
					    "Content-Length: %d\r\n"
					    "Connection: close\r\n\r\n%s",
					    blen, body);
		} else {
			atomic_fetch_add(&g_total_errors, 1);
			char body[128];
			int blen = snprintf(body, sizeof(body),
					    "{\"error\":\"container_failed\","
					    "\"total_ms\":%.1f}\n",
					    total_t / 1000.0);
			resp_len = snprintf(resp, sizeof(resp),
					    "HTTP/1.1 500\r\n"
					    "Content-Type: application/json\r\n"
					    "Content-Length: %d\r\n"
					    "Connection: close\r\n\r\n%s",
					    blen, body);
		}

	} else if (strcmp(uri, "/health") == 0) {
		const char *body = "{\"status\":\"ok\"}\n";

		resp_len = snprintf(resp, sizeof(resp),
				    "HTTP/1.1 200 OK\r\n"
				    "Content-Type: application/json\r\n"
				    "Content-Length: %zu\r\n"
				    "Connection: close\r\n\r\n%s",
				    strlen(body), body);

	} else if (strcmp(uri, "/stats") == 0) {
		char body[256];
		int blen = snprintf(body, sizeof(body),
				    "{\"requests\":%u,\"errors\":%u,"
				    "\"active\":%u}\n",
				    atomic_load(&g_total_requests),
				    atomic_load(&g_total_errors),
				    atomic_load(&g_active));

		resp_len = snprintf(resp, sizeof(resp),
				    "HTTP/1.1 200 OK\r\n"
				    "Content-Type: application/json\r\n"
				    "Content-Length: %d\r\n"
				    "Connection: close\r\n\r\n%s",
				    blen, body);
	} else {
		const char *body = "{\"error\":\"not_found\"}\n";

		resp_len = snprintf(resp, sizeof(resp),
				    "HTTP/1.1 404\r\n"
				    "Content-Length: %zu\r\n"
				    "Connection: close\r\n\r\n%s",
				    strlen(body), body);
	}

	write(cfd, resp, (size_t)resp_len);
	close(cfd);
}

static void *worker(void *arg)
{
	int cfd = *(int *)arg;

	free(arg);
	handle_http(cfd);
	return NULL;
}

/* --- main --- */

static void handle_signal(int sig)
{
	(void)sig;
	g_running = 0;
}

int main(int argc, char **argv)
{
	int port = LISTEN_PORT;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--image") == 0 && i + 1 < argc)
			g_image_path = argv[++i];
		else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
			port = atoi(argv[++i]);
		else if (strcmp(argv[i], "--runtime") == 0 && i + 1 < argc)
			g_runtime_path = argv[++i];
		else if (strcmp(argv[i], "--help") == 0) {
			printf("Usage: gateway [--image PATH] "
			       "[--port N] [--runtime PATH]\n");
			return 0;
		}
	}

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);
	signal(SIGPIPE, SIG_IGN);
	/* NO SIGCHLD SIG_IGN — we need waitpid() to work */

	/* Sysctl — write directly to /proc */
	{
		static const char *const sysctls[] = {
		    "/proc/sys/net/ipv4/ip_forward",
		    "/proc/sys/net/ipv4/conf/all/rp_filter",
		    "/proc/sys/net/ipv4/conf/default/rp_filter",
		};
		for (size_t i = 0; i < sizeof(sysctls) / sizeof(sysctls[0]);
		     i++) {
			int sfd = open(sysctls[i], O_WRONLY);
			if (sfd >= 0) {
				(void)write(sfd, i == 0 ? "1\n" : "0\n", 2);
				close(sfd);
			}
		}
	}
	/* Firewall rules for veth forwarding */
	(void)system("nft add table inet erlkoenig 2>/dev/null;"
		     "nft add chain inet erlkoenig forward "
		     "'{ type filter hook forward priority 0; policy accept; "
		     "}' 2>/dev/null;"
		     "nft add rule inet erlkoenig forward "
		     "iifname \"vek*\" accept 2>/dev/null;"
		     "nft add rule inet erlkoenig forward "
		     "oifname \"vek*\" accept 2>/dev/null");

	int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int one = 1;

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in addr = {
	    .sin_family = AF_INET,
	    .sin_port = htons((uint16_t)port),
	    .sin_addr.s_addr = INADDR_ANY,
	};

	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}
	listen(lfd, 128);

	fprintf(stderr,
		"gateway: http://0.0.0.0:%d\n"
		"gateway: GET /score?customer=N&amount=N&country=XX\n"
		"gateway: GET /health | /stats\n"
		"gateway: runtime=%s image=%s\n",
		port, g_runtime_path, g_image_path);

	while (g_running) {
		int cfd = accept(lfd, NULL, NULL);

		if (cfd < 0)
			continue;

		int *pfd = malloc(sizeof(int));

		if (!pfd) {
			close(cfd);
			continue;
		}
		*pfd = cfd;

		pthread_t t;

		if (pthread_create(&t, NULL, worker, pfd) == 0) {
			pthread_detach(t);
		} else {
			close(cfd);
			free(pfd);
		}
	}

	close(lfd);
	return 0;
}
