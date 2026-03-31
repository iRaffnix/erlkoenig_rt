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
 * erlkoenig_metrics.h - eBPF tracepoint metrics for containers.
 *
 * Attaches BPF programs to stable kernel tracepoints to collect
 * per-container process lifecycle events:
 *
 *   sched/sched_process_fork  — child process creation
 *   sched/sched_process_exec  — binary execution (execve)
 *   sched/sched_process_exit  — process termination
 *   oom/mark_victim           — OOM killer victim selection
 *
 * Events are filtered by cgroup ID (one ring buffer per container)
 * and consumed via mmap in the ppoll() event loop.
 *
 * All BPF programs are hand-assembled (no libbpf dependency).
 * Requires kernel >= 5.8 (BPF ring buffer support).
 */

#ifndef ERLKOENIG_METRICS_H
#define ERLKOENIG_METRICS_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Event types                                                         */
/* ------------------------------------------------------------------ */

#define EK_METRICS_FORK 1
#define EK_METRICS_EXEC 2
#define EK_METRICS_EXIT 3
#define EK_METRICS_OOM	5

/* ------------------------------------------------------------------ */
/* Event structure (matches ring buffer layout and wire format)        */
/* ------------------------------------------------------------------ */

struct ek_metrics_event {
	uint8_t type; /* EK_METRICS_* */
	uint8_t _pad[3];
	uint32_t pid;	       /* process ID */
	uint32_t tgid;	       /* thread group ID */
	uint64_t timestamp_ns; /* ktime_get_ns() */
	union {
		struct {
			uint32_t child_pid;
		} fork_ev;
		struct {
			char comm[16];
		} exec_ev;
		struct {
			int32_t exit_code;
		} exit_ev;
		struct {
			uint32_t victim_pid;
		} oom_ev;
	};
};

/* ------------------------------------------------------------------ */
/* Tracepoint programs                                                 */
/* ------------------------------------------------------------------ */

#define EK_METRICS_PROG_FORK 0
#define EK_METRICS_PROG_EXEC 1
#define EK_METRICS_PROG_EXIT 2
#define EK_METRICS_PROG_OOM  3
#define EK_METRICS_N_PROGS   4

/* Maximum perf event fds (one per CPU per program) */
#define EK_METRICS_MAX_CPUS 128

/* ------------------------------------------------------------------ */
/* Metrics context (one per container)                                 */
/* ------------------------------------------------------------------ */

struct ek_metrics_ctx {
	/* BPF maps */
	int ringbuf_fd;	   /* BPF_MAP_TYPE_RINGBUF */
	int cgroup_map_fd; /* BPF_MAP_TYPE_ARRAY (1 elem) */

	/* Loaded BPF programs */
	int prog_fds[EK_METRICS_N_PROGS];

	/* Perf event fds for tracepoint attachment (per program, per CPU) */
	int perf_fds[EK_METRICS_N_PROGS][EK_METRICS_MAX_CPUS];
	int n_cpus;

	/* Ring buffer consumer (two separate mmaps) */
	void *ring_mmap;	   /* consumer page (read-write) */
	size_t ring_mmap_size;	   /* consumer page size */
	void *ring_producer;	   /* producer + data pages (read-only) */
	size_t ring_producer_size; /* producer mmap size */
	size_t ring_data_size;	   /* data area size */
};

/* Ring buffer size: 256 KB (power of 2, page-aligned) */
#define EK_METRICS_RINGBUF_SIZE (256 * 1024)

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * Start metrics collection for a container.
 *
 * Resolves the cgroup ID, creates BPF maps, loads tracepoint programs,
 * attaches to all online CPUs, and sets up the ring buffer consumer.
 *
 * @param cgroup_path  Absolute path to the container's cgroup directory
 * @param ctx          Output: metrics context (zeroed on entry)
 * @return             0 on success, -errno on failure
 *
 * On failure, all partially created resources are cleaned up.
 * Individual tracepoint failures are non-fatal: if OOM tracepoint
 * is unavailable, fork/exec/exit still work.
 */
int ek_metrics_start(const char *cgroup_path, struct ek_metrics_ctx *ctx);

/*
 * Stop metrics collection and release all resources.
 *
 * Detaches BPF programs, closes perf events, unmaps ring buffer,
 * closes map fds. Safe to call on a zeroed or partially initialized ctx.
 */
void ek_metrics_stop(struct ek_metrics_ctx *ctx);

/*
 * Return the fd to poll for ring buffer readability.
 *
 * Add this fd to ppoll() with POLLIN. When readable, call
 * ek_metrics_consume() to drain events.
 *
 * @return ring buffer fd, or -1 if metrics not active
 */
int ek_metrics_poll_fd(const struct ek_metrics_ctx *ctx);

/*
 * Consume available events from the ring buffer.
 *
 * Reads all pending events and calls the callback for each one.
 * Non-blocking: returns immediately if no events available.
 *
 * @param ctx       Metrics context
 * @param callback  Called for each event (must not block)
 * @param userdata  Opaque pointer passed to callback
 * @return          Number of events consumed, or -1 on error
 */
typedef void (*ek_metrics_callback_t)(const struct ek_metrics_event *ev,
				      void *userdata);

int ek_metrics_consume(struct ek_metrics_ctx *ctx,
		       ek_metrics_callback_t callback, void *userdata);

/*
 * Initialize a metrics context to safe defaults.
 * Must be called before ek_metrics_start().
 */
void ek_metrics_ctx_init(struct ek_metrics_ctx *ctx);

#endif /* ERLKOENIG_METRICS_H */
