/*
 * test_metrics_live.c - Live test: fork a process and see eBPF events.
 *
 * Must run as root. Attaches to own cgroup, forks a child,
 * and checks that fork/exec/exit events arrive in the ring buffer.
 *
 * Build: gcc -o test_metrics_live test_metrics_live.c ../erlkoenig_metrics.c \
 *        -I.. -D_GNU_SOURCE -Wall -Wno-unused-parameter -O0 -g
 * Run:   sudo ./test_metrics_live
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <poll.h>

#include "erlkoenig_bpf.h"
#include "erlkoenig_metrics.h"

static int fork_seen = 0;
static int exec_seen = 0;
static int exit_seen = 0;

static void event_handler(const struct ek_metrics_event *ev, void *userdata)
{
    (void)userdata;
    const char *type_name = "?";
    switch (ev->type) {
    case EK_METRICS_FORK:
        type_name = "FORK";
        fork_seen++;
        break;
    case EK_METRICS_EXEC:
        type_name = "EXEC";
        exec_seen++;
        break;
    case EK_METRICS_EXIT:
        type_name = "EXIT";
        exit_seen++;
        break;
    case EK_METRICS_OOM:
        type_name = "OOM";
        break;
    }
    printf("  EVENT: %-5s pid=%u tgid=%u ts=%lu",
           type_name, ev->pid, ev->tgid,
           (unsigned long)ev->timestamp_ns);
    if (ev->type == EK_METRICS_FORK)
        printf(" child_pid=%u", ev->fork_ev.child_pid);
    if (ev->type == EK_METRICS_EXEC)
        printf(" comm=%.16s", ev->exec_ev.comm);
    printf("\n");
}

int main(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Must run as root\n");
        return 1;
    }

    printf("=== eBPF metrics live test ===\n\n");

    /* Read our cgroup path */
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) {
        perror("fopen /proc/self/cgroup");
        return 1;
    }
    char line[256], cgroup_path[512] = "";
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) == 0) {
            char *nl = strchr(line + 3, '\n');
            if (nl) *nl = '\0';
            snprintf(cgroup_path, sizeof(cgroup_path),
                     "/sys/fs/cgroup%s", line + 3);
            break;
        }
    }
    fclose(f);

    printf("Cgroup: %s\n\n", cgroup_path);

    /* Start metrics */
    struct ek_metrics_ctx ctx;
    ek_metrics_ctx_init(&ctx);

    int ret = ek_metrics_start(cgroup_path, &ctx);
    if (ret < 0) {
        fprintf(stderr, "ek_metrics_start failed: %s\n", strerror(-ret));
        return 1;
    }
    printf("Metrics started (ringbuf_fd=%d)\n\n", ctx.ringbuf_fd);

    /* Fork a child that exec's /bin/true */
    printf("Forking child (exec /bin/true)...\n");
    pid_t child = fork();
    if (child == 0) {
        execl("/bin/true", "true", NULL);
        _exit(127);
    }
    if (child < 0) {
        perror("fork");
        ek_metrics_stop(&ctx);
        return 1;
    }

    printf("Child PID: %d\n", child);

    /* Wait for child */
    int status;
    waitpid(child, &status, 0);
    printf("Child exited (status=%d)\n\n", WEXITSTATUS(status));

    /* Give BPF a moment to deliver events, then poll + consume */
    printf("Consuming ring buffer events:\n");
    struct pollfd pfd = {
        .fd = ek_metrics_poll_fd(&ctx),
        .events = POLLIN,
    };

    /* Poll a few times to collect all events */
    for (int attempt = 0; attempt < 5; attempt++) {
        int pret = poll(&pfd, 1, 100);  /* 100ms timeout */
        if (pret > 0 && (pfd.revents & POLLIN)) {
            ek_metrics_consume(&ctx, event_handler, NULL);
        }
    }

    printf("\n--- Results ---\n");
    printf("Fork events: %d\n", fork_seen);
    printf("Exec events: %d\n", exec_seen);
    printf("Exit events: %d\n", exit_seen);

    ek_metrics_stop(&ctx);

    int ok = (fork_seen >= 1);
    printf("\n%s (fork_seen=%d)\n", ok ? "PASS" : "FAIL", fork_seen);
    return ok ? 0 : 1;
}
