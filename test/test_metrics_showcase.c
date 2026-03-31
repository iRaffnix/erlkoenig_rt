/*
 * test_metrics_showcase.c - Full eBPF metrics showcase.
 *
 * Demonstrates the complete metrics pipeline:
 *   Kernel tracepoints → BPF programs → Ring buffer → Userspace events
 *
 * Attaches to the current cgroup, then runs several workloads
 * to generate fork/exec/exit events. Shows real-time event streaming
 * and aggregation.
 *
 * Run: sudo ./test_metrics_showcase
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <poll.h>
#include <time.h>

#include "erlkoenig_bpf.h"
#include "erlkoenig_metrics.h"

/* Counters */
static int n_fork = 0, n_exec = 0, n_exit = 0, n_oom = 0;

static void print_event(const struct ek_metrics_event *ev, void *userdata)
{
    (void)userdata;
    const char *type_str;
    char detail[128] = "";

    switch (ev->type) {
    case EK_METRICS_FORK:
        type_str = "FORK";
        n_fork++;
        snprintf(detail, sizeof(detail), "child_pid=%u", ev->fork_ev.child_pid);
        break;
    case EK_METRICS_EXEC:
        type_str = "EXEC";
        n_exec++;
        snprintf(detail, sizeof(detail), "comm=%.16s", ev->exec_ev.comm);
        break;
    case EK_METRICS_EXIT:
        type_str = "EXIT";
        n_exit++;
        snprintf(detail, sizeof(detail), "exit_code=%d", ev->exit_ev.exit_code);
        break;
    case EK_METRICS_OOM:
        type_str = "OOM!";
        n_oom++;
        snprintf(detail, sizeof(detail), "victim=%u", ev->oom_ev.victim_pid);
        break;
    default:
        type_str = "????";
        break;
    }

    /* Timestamp relative to first event */
    static uint64_t first_ts = 0;
    if (first_ts == 0) first_ts = ev->timestamp_ns;
    double ms = (double)(ev->timestamp_ns - first_ts) / 1e6;

    printf("  [%8.2f ms] %-5s  pid=%-7u %s\n",
           ms, type_str, ev->pid, detail);
}

static void drain_events(struct ek_metrics_ctx *ctx)
{
    struct pollfd pfd = {
        .fd = ek_metrics_poll_fd(ctx),
        .events = POLLIN,
    };
    for (int i = 0; i < 10; i++) {
        if (poll(&pfd, 1, 50) > 0 && (pfd.revents & POLLIN))
            ek_metrics_consume(ctx, print_event, NULL);
    }
}

static void run_workload(const char *desc, const char *cmd)
{
    printf("\n--- %s: %s ---\n", desc, cmd);
    fflush(stdout);
    int status = system(cmd);
    (void)status;
}

int main(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Must run as root\n");
        return 1;
    }

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║     Erlkoenig eBPF Tracepoint Metrics Showcase  ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    /* Read cgroup */
    FILE *f = fopen("/proc/self/cgroup", "r");
    char line[256], cgroup[512] = "";
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) == 0) {
            char *nl = strchr(line + 3, '\n');
            if (nl) *nl = '\0';
            snprintf(cgroup, sizeof(cgroup), "/sys/fs/cgroup%s", line + 3);
            break;
        }
    }
    fclose(f);

    struct ek_metrics_ctx ctx;
    ek_metrics_ctx_init(&ctx);
    int ret = ek_metrics_start(cgroup, &ctx);
    if (ret < 0) {
        fprintf(stderr, "Failed to start metrics: %s\n", strerror(-ret));
        return 1;
    }

    printf("Cgroup:     %s\n", cgroup);
    printf("Ringbuf FD: %d (256 KB)\n", ctx.ringbuf_fd);
    printf("CPUs:       %d\n\n", ctx.n_cpus);

    printf("=== Tracepoints attached, generating workloads ===\n");

    /* Workload 1: Simple fork+exec */
    run_workload("1", "/bin/true");
    drain_events(&ctx);

    /* Workload 2: Multiple children */
    run_workload("2", "for i in 1 2 3; do /bin/echo -n ''; done");
    drain_events(&ctx);

    /* Workload 3: Pipeline (fork + exec chain) */
    run_workload("3", "echo hello | cat | wc -c");
    drain_events(&ctx);

    /* Workload 4: Subshell fork bomb (limited) */
    run_workload("4", "for i in $(seq 1 5); do (exit 0); done");
    drain_events(&ctx);

    /* Summary */
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║  Summary                                        ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║  Fork events:  %-5d                             ║\n", n_fork);
    printf("║  Exec events:  %-5d                             ║\n", n_exec);
    printf("║  Exit events:  %-5d                             ║\n", n_exit);
    printf("║  OOM  events:  %-5d                             ║\n", n_oom);
    printf("║  Total:        %-5d                             ║\n",
           n_fork + n_exec + n_exit + n_oom);
    printf("╚══════════════════════════════════════════════════╝\n");

    ek_metrics_stop(&ctx);

    printf("\nAll BPF resources cleaned up (kernel auto-freed FDs).\n");
    return (n_fork > 0 && n_exec > 0 && n_exit > 0) ? 0 : 1;
}
