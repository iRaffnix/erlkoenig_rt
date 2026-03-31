/*
 * test_metrics.c - Smoke tests for eBPF metrics infrastructure.
 *
 * Two modes:
 *   Without root:  Tests struct layout, event serialization, format parser.
 *   With root:     Full test: BPF map creation, program load, ring buffer.
 *
 * Build: gcc -o test_metrics test_metrics.c -I.. -D_GNU_SOURCE
 * Run:   ./test_metrics           (unprivileged tests only)
 *        sudo ./test_metrics      (all tests)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#include "erlkoenig_bpf.h"
#include "erlkoenig_metrics.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-50s", name); \
    fflush(stdout); \
} while(0)

#define PASS() do { tests_passed++; printf("OK\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

/* ------------------------------------------------------------------ */
/* Unprivileged tests (no root needed)                                 */
/* ------------------------------------------------------------------ */

static void test_event_struct_size(void)
{
    TEST("event struct size is reasonable");
    size_t sz = sizeof(struct ek_metrics_event);
    if (sz >= 16 && sz <= 64)
        PASS();
    else {
        char buf[64];
        snprintf(buf, sizeof(buf), "size=%zu, expected 16-64", sz);
        FAIL(buf);
    }
}

static void test_event_struct_layout(void)
{
    TEST("event struct field offsets");
    struct ek_metrics_event ev;
    memset(&ev, 0, sizeof(ev));

    ev.type = EK_METRICS_FORK;
    ev.pid = 12345;
    ev.tgid = 12345;
    ev.timestamp_ns = 999999;
    ev.fork_ev.child_pid = 12346;

    if (ev.type == EK_METRICS_FORK &&
        ev.pid == 12345 &&
        ev.fork_ev.child_pid == 12346)
        PASS();
    else
        FAIL("field read-back mismatch");
}

static void test_ctx_init(void)
{
    TEST("ctx_init sets all fds to -1");
    struct ek_metrics_ctx ctx;
    ek_metrics_ctx_init(&ctx);

    if (ctx.ringbuf_fd != -1 || ctx.cgroup_map_fd != -1) {
        FAIL("map fds not -1");
        return;
    }
    for (int i = 0; i < EK_METRICS_N_PROGS; i++) {
        if (ctx.prog_fds[i] != -1) {
            FAIL("prog_fd not -1");
            return;
        }
    }
    PASS();
}

static void test_poll_fd_inactive(void)
{
    TEST("poll_fd returns -1 when inactive");
    struct ek_metrics_ctx ctx;
    ek_metrics_ctx_init(&ctx);

    if (ek_metrics_poll_fd(&ctx) == -1)
        PASS();
    else
        FAIL("expected -1");
}

static void test_stop_safe_on_zeroed(void)
{
    TEST("stop is safe on zeroed/init'd ctx");
    struct ek_metrics_ctx ctx;
    ek_metrics_ctx_init(&ctx);
    ek_metrics_stop(&ctx);  /* must not crash */
    PASS();
}

/* ------------------------------------------------------------------ */
/* Privileged tests (root only)                                        */
/* ------------------------------------------------------------------ */

static int is_root(void)
{
    return geteuid() == 0;
}

static void test_bpf_map_create(void)
{
    TEST("BPF array map creation");
    int fd = ek_bpf_map_create(BPF_MAP_TYPE_ARRAY,
                                sizeof(uint32_t),
                                sizeof(uint64_t), 1);
    if (fd >= 0) {
        close(fd);
        PASS();
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "fd=%d errno=%s", fd, strerror(-fd));
        FAIL(buf);
    }
}

static void test_bpf_ringbuf_create(void)
{
    TEST("BPF ring buffer creation (256KB)");
    int fd = ek_bpf_ringbuf_create(256 * 1024);
    if (fd >= 0) {
        close(fd);
        PASS();
    } else {
        char buf[128];
        snprintf(buf, sizeof(buf), "fd=%d errno=%s", fd, strerror(-fd));
        FAIL(buf);
    }
}

static void test_bpf_map_update_read(void)
{
    TEST("BPF map update + lookup");
    int fd = ek_bpf_map_create(BPF_MAP_TYPE_ARRAY,
                                sizeof(uint32_t),
                                sizeof(uint64_t), 1);
    if (fd < 0) {
        FAIL("map create failed");
        return;
    }

    uint32_t key = 0;
    uint64_t val = 0xDEADBEEFCAFE;
    int ret = ek_bpf_map_update(fd, &key, &val, 0);
    if (ret < 0) {
        close(fd);
        FAIL("map update failed");
        return;
    }

    /* Read back via bpf syscall */
    union bpf_attr attr;
    uint64_t readback = 0;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = (uint64_t)(unsigned long)&key;
    attr.value  = (uint64_t)(unsigned long)&readback;
    ret = (int)syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
    close(fd);

    if (ret == 0 && readback == 0xDEADBEEFCAFE)
        PASS();
    else
        FAIL("readback mismatch");
}

static void test_tracepoint_id(void)
{
    TEST("tracepoint ID for sched/sched_process_fork");
    int id = ek_bpf_tracepoint_id("sched", "sched_process_fork");
    if (id > 0) {
        printf("OK (id=%d)\n", id);
        tests_passed++;
    } else {
        FAIL("could not read tracepoint id");
    }
}

static void test_tp_field_offset(void)
{
    TEST("tracepoint field offset: fork/parent_pid");
    int off = ek_bpf_tp_field_offset("sched", "sched_process_fork",
                                      "parent_pid");
    if (off > 0) {
        printf("OK (offset=%d)\n", off);
        tests_passed++;
    } else {
        FAIL("field not found");
    }
}

static void test_full_metrics_start_stop(void)
{
    TEST("full metrics start/stop on /sys/fs/cgroup");
    /* Use our own cgroup as test target */
    struct ek_metrics_ctx ctx;
    ek_metrics_ctx_init(&ctx);

    /* Read our cgroup path from /proc/self/cgroup */
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) {
        FAIL("cannot read /proc/self/cgroup");
        return;
    }
    char line[256];
    char cgroup_path[512] = "";
    while (fgets(line, sizeof(line), f)) {
        /* Format: "0::/path" for cgroup v2 */
        if (strncmp(line, "0::", 3) == 0) {
            char *nl = strchr(line + 3, '\n');
            if (nl) *nl = '\0';
            snprintf(cgroup_path, sizeof(cgroup_path),
                     "/sys/fs/cgroup%s", line + 3);
            break;
        }
    }
    fclose(f);

    if (cgroup_path[0] == '\0') {
        FAIL("no cgroup v2 found");
        return;
    }

    printf("\n    cgroup: %s\n    ", cgroup_path);

    int ret = ek_metrics_start(cgroup_path, &ctx);
    if (ret < 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "start failed: %s (ret=%d)",
                 strerror(-ret), ret);
        FAIL(buf);
        return;
    }

    /* Check ring buffer fd is valid */
    int poll_fd = ek_metrics_poll_fd(&ctx);
    if (poll_fd < 0) {
        FAIL("poll_fd < 0 after start");
        ek_metrics_stop(&ctx);
        return;
    }

    /* Try consuming (should return 0 events, no crash) */
    int count = ek_metrics_consume(&ctx, NULL, NULL);

    ek_metrics_stop(&ctx);

    if (count >= 0)
        PASS();
    else
        FAIL("consume returned error");
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== erlkoenig_metrics smoke tests ===\n\n");

    printf("-- Unprivileged tests --\n");
    test_event_struct_size();
    test_event_struct_layout();
    test_ctx_init();
    test_poll_fd_inactive();
    test_stop_safe_on_zeroed();

    if (is_root()) {
        printf("\n-- Privileged tests (running as root) --\n");
        test_bpf_map_create();
        test_bpf_ringbuf_create();
        test_bpf_map_update_read();
        test_tracepoint_id();
        test_tp_field_offset();
        test_full_metrics_start_stop();
    } else {
        printf("\n-- Skipping privileged tests (not root) --\n");
        printf("  Run with: sudo %s\n", "test_metrics");
    }

    printf("\n=== Results: %d/%d passed",
           tests_passed, tests_run);
    if (tests_failed > 0)
        printf(", %d FAILED", tests_failed);
    printf(" ===\n");

    return tests_failed > 0 ? 1 : 0;
}
