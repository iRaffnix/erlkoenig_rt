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
 * erlkoenig_metrics.c - eBPF tracepoint metrics implementation.
 *
 * Hand-assembled BPF programs attached to stable kernel tracepoints.
 * Each program filters by cgroup ID and writes events to a shared
 * ring buffer consumed by the ppoll() event loop in erlkoenig_rt.
 *
 * Ring buffer consumer implements the lock-free protocol from
 * kernel/bpf/ringbuf.c without libbpf dependency.
 */

#include "erlkoenig_metrics.h"
#include "erlkoenig_bpf.h"
#include "erlkoenig_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/bpf.h>

/* ------------------------------------------------------------------ */
/* Ring buffer constants (from kernel/bpf/ringbuf.c)                   */
/* ------------------------------------------------------------------ */

#define BPF_RINGBUF_BUSY_BIT	(1U << 31)
#define BPF_RINGBUF_DISCARD_BIT (1U << 30)
#define BPF_RINGBUF_HDR_SZ	8

/* Ring buffer shared page layout:
 * - Page 0: consumer page (consumer_pos at offset 0)
 * - Page 1: producer page (producer_pos at offset 0)
 * - Pages 2..N+1: data pages
 * - Pages N+2..2N+1: data pages again (wrap-around mapping)
 */

/* ------------------------------------------------------------------ */
/* Cgroup ID resolution                                                */
/* ------------------------------------------------------------------ */

/*
 * Get the cgroup ID for a cgroup directory path.
 * The cgroup ID is the inode number on cgroupfs, which is what
 * bpf_get_current_cgroup_id() returns in the kernel.
 */
static int get_cgroup_id(const char *cgroup_path, uint64_t *cgroup_id)
{
	struct stat st;

	if (stat(cgroup_path, &st) < 0) {
		LOG_ERR("metrics: stat(%s): %s", cgroup_path, strerror(errno));
		return -errno;
	}

	*cgroup_id = (uint64_t)st.st_ino;
	LOG_DBG("metrics: cgroup_id for %s = %lu", cgroup_path,
		(unsigned long)*cgroup_id);
	return 0;
}

/* ------------------------------------------------------------------ */
/* BPF program generation: common preamble                             */
/* ------------------------------------------------------------------ */

/*
 * Maximum instructions per tracepoint program.
 * Largest program (exec with comm copy) needs ~45 instructions.
 */
#define MAX_TP_INSNS 64

/*
 * Jump fixup indices returned by emit_cgroup_filter().
 * Caller must fix up these jump offsets to point to the exit block.
 */
struct cgroup_filter_jumps {
	int jmp_null; /* JEQ r0,0 (map lookup returned NULL) */
	int jmp_neq;  /* JNE r7,r1 (cgroup mismatch) */
};

/*
 * Emit the cgroup filter preamble.
 * After this sequence:
 *   r6 = saved ctx pointer
 *   r7 = current cgroup id
 *   Execution continues only if cgroup matches.
 *
 * Returns new pc, or -1 on overflow.
 * jumps: filled with instruction indices that need fixup.
 */
static int emit_cgroup_filter(struct bpf_insn *prog, int pc, int max_insns,
			      int cgroup_map_fd,
			      struct cgroup_filter_jumps *jumps)
{
	if (pc + 13 > max_insns)
		return -1;

	/* r6 = r1 (save ctx) */
	prog[pc++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);

	/* r0 = bpf_get_current_cgroup_id() */
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_get_current_cgroup_id);

	/* r7 = r0 (save cgroup id) */
	prog[pc++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);

	/* *(u32 *)(fp - 4) = 0 (map key on stack) */
	prog[pc++] = BPF_ST_MEM(BPF_W, BPF_REG_FP, -4, 0);

	/* r1 = cgroup_map_fd (2 insns) */
	prog[pc++] = BPF_LD_MAP_FD_1(BPF_REG_1, cgroup_map_fd);
	prog[pc++] = BPF_LD_MAP_FD_2();

	/* r2 = fp - 4 (&key) */
	prog[pc++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP);
	prog[pc++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);

	/* r0 = bpf_map_lookup_elem(r1, r2) */
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_map_lookup_elem);

	/* if r0 == 0 goto exit (placeholder offset, fixed up later) */
	prog[pc++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
	jumps->jmp_null = pc - 1;

	/* r1 = *(u64 *)(r0 + 0) (target cgroup id from map) */
	prog[pc++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0);

	/* if r7 != r1 goto exit (placeholder offset) */
	prog[pc++] = BPF_JMP_REG(BPF_JNE, BPF_REG_7, BPF_REG_1, 0);
	jumps->jmp_neq = pc - 1;

	return pc;
}

/*
 * Fix up cgroup filter jump offsets to point to exit_pc.
 * jmp1_pc and jmp2_pc are the pc values of the two JMP instructions.
 */
/*
 * Fix up all placeholder jumps to point to exit_pc.
 * Called after emit_submit_and_exit() to resolve forward references.
 */
static void fixup_jumps_to_exit(struct bpf_insn *prog, int exit_pc,
				const struct cgroup_filter_jumps *cg,
				int jmp_ringbuf_full)
{
	prog[cg->jmp_null].off = (__s16)(exit_pc - cg->jmp_null - 1);
	prog[cg->jmp_neq].off = (__s16)(exit_pc - cg->jmp_neq - 1);
	prog[jmp_ringbuf_full].off = (__s16)(exit_pc - jmp_ringbuf_full - 1);
}

/* ------------------------------------------------------------------ */
/* BPF program generation: ringbuf reserve + submit                    */
/* ------------------------------------------------------------------ */

/*
 * Emit ring buffer reserve. After this:
 *   r8 = reserved slot pointer (or exit if full)
 *
 * Returns new pc. jmp_full_pc is the index of the JEQ that needs
 * fixup to point to exit.
 */
static int emit_ringbuf_reserve(struct bpf_insn *prog, int pc, int max_insns,
				int ringbuf_fd, uint32_t event_size,
				int *jmp_full_pc)
{
	if (pc + 7 > max_insns)
		return -1;

	/* r1 = ringbuf_fd (2 insns) */
	prog[pc++] = BPF_LD_MAP_FD_1(BPF_REG_1, ringbuf_fd);
	prog[pc++] = BPF_LD_MAP_FD_2();

	/* r2 = event_size */
	prog[pc++] = BPF_MOV64_IMM(BPF_REG_2, (int32_t)event_size);

	/* r3 = 0 (flags) */
	prog[pc++] = BPF_MOV64_IMM(BPF_REG_3, 0);

	/* r0 = bpf_ringbuf_reserve(r1, r2, r3) */
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_ringbuf_reserve);

	/* if r0 == 0 goto exit (placeholder) */
	prog[pc++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
	*jmp_full_pc = pc - 1;

	/* r8 = r0 (save slot pointer) */
	prog[pc++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);

	return pc;
}

/*
 * Emit ring buffer submit + exit block.
 * Returns new pc (this is the final pc, the exit block).
 */
static int emit_submit_and_exit(struct bpf_insn *prog, int pc, int max_insns)
{
	if (pc + 5 > max_insns)
		return -1;

	/* bpf_ringbuf_submit(r8, 0) */
	prog[pc++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
	prog[pc++] = BPF_MOV64_IMM(BPF_REG_2, 0);
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_ringbuf_submit);

	/* exit: r0 = 0; return */
	int exit_pc = pc;
	prog[pc++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	prog[pc++] = BPF_EXIT_INSN();

	(void)exit_pc;
	return pc;
}

/* ------------------------------------------------------------------ */
/* BPF program: sched_process_fork                                     */
/* ------------------------------------------------------------------ */

static int generate_fork_program(struct bpf_insn *prog, int max_insns,
				 int cgroup_map_fd, int ringbuf_fd,
				 int parent_pid_off, int child_pid_off)
{
	struct cgroup_filter_jumps cg;
	int jmp_full, pc = 0;

	pc = emit_cgroup_filter(prog, pc, max_insns, cgroup_map_fd, &cg);
	if (pc < 0)
		return -1;

	pc = emit_ringbuf_reserve(prog, pc, max_insns, ringbuf_fd,
				  (uint32_t)sizeof(struct ek_metrics_event),
				  &jmp_full);
	if (pc < 0)
		return -1;

	if (pc + 10 > max_insns)
		return -1;

	prog[pc++] = BPF_ST_MEM(
	    BPF_B, BPF_REG_8, (int16_t)offsetof(struct ek_metrics_event, type),
	    EK_METRICS_FORK);
	prog[pc++] =
	    BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, (int16_t)parent_pid_off);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_1,
			(int16_t)offsetof(struct ek_metrics_event, pid));
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid);
	prog[pc++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_0,
			(int16_t)offsetof(struct ek_metrics_event, tgid));
	prog[pc++] =
	    BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, (int16_t)child_pid_off);
	prog[pc++] = BPF_STX_MEM(
	    BPF_W, BPF_REG_8, BPF_REG_1,
	    (int16_t)offsetof(struct ek_metrics_event, fork_ev.child_pid));
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_ktime_get_ns);
	prog[pc++] = BPF_STX_MEM(
	    BPF_DW, BPF_REG_8, BPF_REG_0,
	    (int16_t)offsetof(struct ek_metrics_event, timestamp_ns));

	pc = emit_submit_and_exit(prog, pc, max_insns);
	if (pc < 0)
		return -1;

	fixup_jumps_to_exit(prog, pc - 2, &cg, jmp_full);
	return pc;
}

/* ------------------------------------------------------------------ */
/* BPF program: sched_process_exec                                     */
/* ------------------------------------------------------------------ */

static int generate_exec_program(struct bpf_insn *prog, int max_insns,
				 int cgroup_map_fd, int ringbuf_fd, int pid_off)
{
	struct cgroup_filter_jumps cg;
	int jmp_full, pc = 0;

	pc = emit_cgroup_filter(prog, pc, max_insns, cgroup_map_fd, &cg);
	if (pc < 0)
		return -1;

	pc = emit_ringbuf_reserve(prog, pc, max_insns, ringbuf_fd,
				  (uint32_t)sizeof(struct ek_metrics_event),
				  &jmp_full);
	if (pc < 0)
		return -1;

	if (pc + 12 > max_insns)
		return -1;

	prog[pc++] = BPF_ST_MEM(
	    BPF_B, BPF_REG_8, (int16_t)offsetof(struct ek_metrics_event, type),
	    EK_METRICS_EXEC);
	prog[pc++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, (int16_t)pid_off);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_1,
			(int16_t)offsetof(struct ek_metrics_event, pid));
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid);
	prog[pc++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_0,
			(int16_t)offsetof(struct ek_metrics_event, tgid));
	/* bpf_get_current_comm() fills comm[16] directly in ringbuf slot */
	prog[pc++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
	prog[pc++] = BPF_ALU64_IMM(
	    BPF_ADD, BPF_REG_1,
	    (int32_t)offsetof(struct ek_metrics_event, exec_ev.comm));
	prog[pc++] = BPF_MOV64_IMM(BPF_REG_2, 16);
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_get_current_comm);
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_ktime_get_ns);
	prog[pc++] = BPF_STX_MEM(
	    BPF_DW, BPF_REG_8, BPF_REG_0,
	    (int16_t)offsetof(struct ek_metrics_event, timestamp_ns));

	pc = emit_submit_and_exit(prog, pc, max_insns);
	if (pc < 0)
		return -1;

	fixup_jumps_to_exit(prog, pc - 2, &cg, jmp_full);
	return pc;
}

/* ------------------------------------------------------------------ */
/* BPF program: sched_process_exit                                     */
/* ------------------------------------------------------------------ */

static int generate_exit_program(struct bpf_insn *prog, int max_insns,
				 int cgroup_map_fd, int ringbuf_fd, int pid_off)
{
	struct cgroup_filter_jumps cg;
	int jmp_full, pc = 0;

	(void)
	    pid_off; /* exit code not in tracepoint ctx; waitpid provides it */

	pc = emit_cgroup_filter(prog, pc, max_insns, cgroup_map_fd, &cg);
	if (pc < 0)
		return -1;

	pc = emit_ringbuf_reserve(prog, pc, max_insns, ringbuf_fd,
				  (uint32_t)sizeof(struct ek_metrics_event),
				  &jmp_full);
	if (pc < 0)
		return -1;

	if (pc + 8 > max_insns)
		return -1;

	prog[pc++] = BPF_ST_MEM(
	    BPF_B, BPF_REG_8, (int16_t)offsetof(struct ek_metrics_event, type),
	    EK_METRICS_EXIT);
	/* Use bpf_get_current_pid_tgid() — more reliable than tracepoint ctx
	 * for identifying the dying process from any CPU */
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_0,
			(int16_t)offsetof(struct ek_metrics_event, pid));
	prog[pc++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_0,
			(int16_t)offsetof(struct ek_metrics_event, tgid));
	prog[pc++] = BPF_ST_MEM(
	    BPF_W, BPF_REG_8,
	    (int16_t)offsetof(struct ek_metrics_event, exit_ev.exit_code), 0);
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_ktime_get_ns);
	prog[pc++] = BPF_STX_MEM(
	    BPF_DW, BPF_REG_8, BPF_REG_0,
	    (int16_t)offsetof(struct ek_metrics_event, timestamp_ns));

	pc = emit_submit_and_exit(prog, pc, max_insns);
	if (pc < 0)
		return -1;

	fixup_jumps_to_exit(prog, pc - 2, &cg, jmp_full);
	return pc;
}

/* ------------------------------------------------------------------ */
/* BPF program: oom/mark_victim                                        */
/* ------------------------------------------------------------------ */

static int generate_oom_program(struct bpf_insn *prog, int max_insns,
				int cgroup_map_fd, int ringbuf_fd, int pid_off)
{
	struct cgroup_filter_jumps cg;
	int jmp_full, pc = 0;

	pc = emit_cgroup_filter(prog, pc, max_insns, cgroup_map_fd, &cg);
	if (pc < 0)
		return -1;

	pc = emit_ringbuf_reserve(prog, pc, max_insns, ringbuf_fd,
				  (uint32_t)sizeof(struct ek_metrics_event),
				  &jmp_full);
	if (pc < 0)
		return -1;

	if (pc + 9 > max_insns)
		return -1;

	prog[pc++] = BPF_ST_MEM(
	    BPF_B, BPF_REG_8, (int16_t)offsetof(struct ek_metrics_event, type),
	    EK_METRICS_OOM);
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_get_current_pid_tgid);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_0,
			(int16_t)offsetof(struct ek_metrics_event, pid));
	prog[pc++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32);
	prog[pc++] =
	    BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_0,
			(int16_t)offsetof(struct ek_metrics_event, tgid));
	prog[pc++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, (int16_t)pid_off);
	prog[pc++] = BPF_STX_MEM(
	    BPF_W, BPF_REG_8, BPF_REG_1,
	    (int16_t)offsetof(struct ek_metrics_event, oom_ev.victim_pid));
	prog[pc++] = BPF_CALL_HELPER(BPF_FUNC_ktime_get_ns);
	prog[pc++] = BPF_STX_MEM(
	    BPF_DW, BPF_REG_8, BPF_REG_0,
	    (int16_t)offsetof(struct ek_metrics_event, timestamp_ns));

	pc = emit_submit_and_exit(prog, pc, max_insns);
	if (pc < 0)
		return -1;

	fixup_jumps_to_exit(prog, pc - 2, &cg, jmp_full);
	return pc;
}

/* ------------------------------------------------------------------ */
/* Ring buffer consumer (no libbpf)                                    */
/* ------------------------------------------------------------------ */

/*
 * Set up ring buffer mmap consumer.
 *
 * The kernel requires two separate mmap calls (like libbpf's ringbuf.c):
 *   1. Consumer page (offset 0, 1 page): PROT_READ | PROT_WRITE
 *      Contains consumer_pos which we advance after reading.
 *   2. Producer + data pages (offset 1 page): PROT_READ only
 *      Contains producer_pos + 2x data area (wrap-around mapping).
 */
static int ringbuf_mmap_setup(struct ek_metrics_ctx *ctx)
{
	size_t page_size = (size_t)getpagesize();

	/* Step 1: mmap consumer page (read-write) */
	void *consumer = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, ctx->ringbuf_fd, 0);
	if (consumer == MAP_FAILED) {
		LOG_ERR("metrics: ringbuf consumer mmap failed: %s",
			strerror(errno));
		return -errno;
	}

	/* Step 2: mmap producer + data pages (read-only) */
	size_t producer_size = page_size + 2 * EK_METRICS_RINGBUF_SIZE;
	void *producer = mmap(NULL, producer_size, PROT_READ, MAP_SHARED,
			      ctx->ringbuf_fd, (off_t)page_size);
	if (producer == MAP_FAILED) {
		int saved = errno;
		LOG_ERR("metrics: ringbuf producer mmap failed: %s",
			strerror(saved));
		munmap(consumer, page_size);
		return -saved;
	}

	ctx->ring_mmap = consumer;
	ctx->ring_mmap_size = page_size; /* consumer page size */
	ctx->ring_data_size = EK_METRICS_RINGBUF_SIZE;
	ctx->ring_producer = producer;
	ctx->ring_producer_size = producer_size;

	return 0;
}

int ek_metrics_consume(struct ek_metrics_ctx *ctx,
		       ek_metrics_callback_t callback, void *userdata)
{
	if (!ctx->ring_mmap || !ctx->ring_producer)
		return -1;

	/* Consumer position: first 8 bytes of consumer page (ring_mmap) */
	unsigned long *consumer_pos_ptr = (unsigned long *)ctx->ring_mmap;

	/* Producer position: first 8 bytes of producer page (ring_producer) */
	unsigned long *producer_pos_ptr = (unsigned long *)ctx->ring_producer;

	/* Data starts after the producer page header */
	size_t page_size = (size_t)getpagesize();
	uint8_t *data_base = (uint8_t *)ctx->ring_producer + page_size;

	unsigned long cons_pos = atomic_load_explicit(
	    (_Atomic unsigned long *)consumer_pos_ptr, memory_order_acquire);

	unsigned long prod_pos = atomic_load_explicit(
	    (_Atomic unsigned long *)producer_pos_ptr, memory_order_acquire);

	int count = 0;

	while (cons_pos < prod_pos) {
		/* Record header at data offset (masked to ring size) */
		size_t offset = (size_t)(cons_pos % ctx->ring_data_size);
		uint32_t *hdr = (uint32_t *)(data_base + offset);
		uint32_t len = atomic_load_explicit((_Atomic uint32_t *)hdr,
						    memory_order_acquire);

		/* Check busy bit — record still being written */
		if (len & BPF_RINGBUF_BUSY_BIT)
			break;

		uint32_t record_len =
		    len & ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);

		/* Data follows the 8-byte header */
		uint8_t *record_data = data_base + offset + BPF_RINGBUF_HDR_SZ;

		/* Deliver event (skip discarded records) */
		if (!(len & BPF_RINGBUF_DISCARD_BIT) &&
		    record_len >= sizeof(struct ek_metrics_event)) {
			const struct ek_metrics_event *ev =
			    (const struct ek_metrics_event *)record_data;
			callback(ev, userdata);
			count++;
		}

		/* Advance consumer: header + data, rounded up to 8 */
		uint32_t total = BPF_RINGBUF_HDR_SZ + record_len;
		total = (total + 7) & ~7U;
		cons_pos += total;
	}

	/* Update consumer position */
	atomic_store_explicit((_Atomic unsigned long *)consumer_pos_ptr,
			      cons_pos, memory_order_release);

	return count;
}

/* ------------------------------------------------------------------ */
/* Tracepoint attachment                                               */
/* ------------------------------------------------------------------ */

struct tp_info {
	const char *group;
	const char *name;
	int prog_idx;
};

static const struct tp_info tracepoints[EK_METRICS_N_PROGS] = {
    [EK_METRICS_PROG_FORK] = {"sched", "sched_process_fork",
			      EK_METRICS_PROG_FORK},
    [EK_METRICS_PROG_EXEC] = {"sched", "sched_process_exec",
			      EK_METRICS_PROG_EXEC},
    [EK_METRICS_PROG_EXIT] = {"sched", "sched_process_exit",
			      EK_METRICS_PROG_EXIT},
    [EK_METRICS_PROG_OOM] = {"oom", "mark_victim", EK_METRICS_PROG_OOM},
};

static int attach_program(struct ek_metrics_ctx *ctx, int prog_idx)
{
	const struct tp_info *tp = &tracepoints[prog_idx];
	int tp_id;
	int attached = 0;

	tp_id = ek_bpf_tracepoint_id(tp->group, tp->name);
	if (tp_id < 0) {
		LOG_WARN("metrics: tracepoint %s/%s not available", tp->group,
			 tp->name);
		return tp_id;
	}

	for (int cpu = 0; cpu < ctx->n_cpus; cpu++) {
		int perf_fd = ek_bpf_attach_tracepoint_cpu(
		    ctx->prog_fds[prog_idx], tp_id, cpu);
		if (perf_fd < 0) {
			/* CPU might be offline — non-fatal */
			LOG_DBG("metrics: attach %s/%s cpu %d: %s", tp->group,
				tp->name, cpu, strerror(-perf_fd));
			ctx->perf_fds[prog_idx][cpu] = -1;
			continue;
		}
		ctx->perf_fds[prog_idx][cpu] = perf_fd;
		attached++;
	}

	if (attached == 0) {
		LOG_WARN("metrics: %s/%s: no CPUs attached", tp->group,
			 tp->name);
		return -ENODEV;
	}

	LOG_INFO("metrics: attached %s/%s on %d/%d CPUs", tp->group, tp->name,
		 attached, ctx->n_cpus);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void ek_metrics_ctx_init(struct ek_metrics_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->ringbuf_fd = -1;
	ctx->cgroup_map_fd = -1;
	ctx->ring_mmap = NULL;
	ctx->ring_producer = NULL;

	for (int i = 0; i < EK_METRICS_N_PROGS; i++) {
		ctx->prog_fds[i] = -1;
		for (int j = 0; j < EK_METRICS_MAX_CPUS; j++)
			ctx->perf_fds[i][j] = -1;
	}
}

int ek_metrics_poll_fd(const struct ek_metrics_ctx *ctx)
{
	return ctx->ringbuf_fd;
}

void ek_metrics_stop(struct ek_metrics_ctx *ctx)
{
	/* Close perf event fds (detaches BPF programs) */
	for (int i = 0; i < EK_METRICS_N_PROGS; i++) {
		for (int j = 0; j < EK_METRICS_MAX_CPUS; j++) {
			if (ctx->perf_fds[i][j] >= 0) {
				close(ctx->perf_fds[i][j]);
				ctx->perf_fds[i][j] = -1;
			}
		}
	}

	/* Close BPF program fds */
	for (int i = 0; i < EK_METRICS_N_PROGS; i++) {
		if (ctx->prog_fds[i] >= 0) {
			close(ctx->prog_fds[i]);
			ctx->prog_fds[i] = -1;
		}
	}

	/* Unmap ring buffer (two separate mmaps) */
	if (ctx->ring_producer) {
		munmap(ctx->ring_producer, ctx->ring_producer_size);
		ctx->ring_producer = NULL;
	}
	if (ctx->ring_mmap) {
		munmap(ctx->ring_mmap, ctx->ring_mmap_size);
		ctx->ring_mmap = NULL;
	}

	/* Close map fds */
	if (ctx->ringbuf_fd >= 0) {
		close(ctx->ringbuf_fd);
		ctx->ringbuf_fd = -1;
	}
	if (ctx->cgroup_map_fd >= 0) {
		close(ctx->cgroup_map_fd);
		ctx->cgroup_map_fd = -1;
	}
}

int ek_metrics_start(const char *cgroup_path, struct ek_metrics_ctx *ctx)
{
	struct bpf_insn prog[MAX_TP_INSNS];
	char log_buf[4096];
	uint64_t cgroup_id;
	uint32_t key = 0;
	int ret, insn_cnt;
	int programs_loaded = 0;

	/* Resolve cgroup ID */
	ret = get_cgroup_id(cgroup_path, &cgroup_id);
	if (ret < 0)
		goto fail;

	/* Detect online CPUs */
	ctx->n_cpus = ek_bpf_online_cpus();
	if (ctx->n_cpus < 0 || ctx->n_cpus > EK_METRICS_MAX_CPUS) {
		LOG_ERR("metrics: invalid CPU count: %d", ctx->n_cpus);
		ret = -EINVAL;
		goto fail;
	}

	/* Create cgroup ID map (ARRAY, 1 element, value = u64) */
	ctx->cgroup_map_fd = ek_bpf_map_create(
	    BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t), 1);
	if (ctx->cgroup_map_fd < 0) {
		LOG_ERR("metrics: cgroup map create: %s",
			strerror(-ctx->cgroup_map_fd));
		ret = ctx->cgroup_map_fd;
		goto fail;
	}

	/* Store target cgroup ID in map */
	ret = ek_bpf_map_update(ctx->cgroup_map_fd, &key, &cgroup_id, 0);
	if (ret < 0) {
		LOG_ERR("metrics: cgroup map update: %s", strerror(-ret));
		goto fail;
	}

	/* Create ring buffer map */
	ctx->ringbuf_fd = ek_bpf_ringbuf_create(EK_METRICS_RINGBUF_SIZE);
	if (ctx->ringbuf_fd < 0) {
		LOG_ERR("metrics: ringbuf create: %s",
			strerror(-ctx->ringbuf_fd));
		ret = ctx->ringbuf_fd;
		goto fail;
	}

	/* Set up mmap consumer */
	ret = ringbuf_mmap_setup(ctx);
	if (ret < 0)
		goto fail;

	/* --- Generate and load BPF programs --- */

	/* Fork program */
	{
		int ppid_off = ek_bpf_tp_field_offset(
		    "sched", "sched_process_fork", "parent_pid");
		int cpid_off = ek_bpf_tp_field_offset(
		    "sched", "sched_process_fork", "child_pid");
		if (ppid_off >= 0 && cpid_off >= 0) {
			insn_cnt = generate_fork_program(
			    prog, MAX_TP_INSNS, ctx->cgroup_map_fd,
			    ctx->ringbuf_fd, ppid_off, cpid_off);
			if (insn_cnt > 0) {
				ctx->prog_fds[EK_METRICS_PROG_FORK] =
				    ek_bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT,
						     prog, insn_cnt, "ek_fork",
						     log_buf, sizeof(log_buf));
				if (ctx->prog_fds[EK_METRICS_PROG_FORK] >= 0)
					programs_loaded++;
				else
					LOG_WARN(
					    "metrics: fork prog load: %s",
					    strerror(
						-ctx->prog_fds
						     [EK_METRICS_PROG_FORK]));
			}
		} else {
			LOG_WARN("metrics: fork tracepoint format unavailable");
		}
	}

	/* Exec program */
	{
		int pid_off = ek_bpf_tp_field_offset(
		    "sched", "sched_process_exec", "pid");
		if (pid_off >= 0) {
			insn_cnt = generate_exec_program(
			    prog, MAX_TP_INSNS, ctx->cgroup_map_fd,
			    ctx->ringbuf_fd, pid_off);
			if (insn_cnt > 0) {
				ctx->prog_fds[EK_METRICS_PROG_EXEC] =
				    ek_bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT,
						     prog, insn_cnt, "ek_exec",
						     log_buf, sizeof(log_buf));
				if (ctx->prog_fds[EK_METRICS_PROG_EXEC] >= 0)
					programs_loaded++;
				else
					LOG_WARN(
					    "metrics: exec prog load: %s",
					    strerror(
						-ctx->prog_fds
						     [EK_METRICS_PROG_EXEC]));
			}
		}
	}

	/* Exit program (pid_off only used for cgroup check, exit code
	 * comes from waitpid on Erlang side — not from tracepoint ctx) */
	{
		int pid_off = ek_bpf_tp_field_offset(
		    "sched", "sched_process_exit", "pid");
		if (pid_off >= 0) {
			insn_cnt = generate_exit_program(
			    prog, MAX_TP_INSNS, ctx->cgroup_map_fd,
			    ctx->ringbuf_fd, pid_off);
			if (insn_cnt > 0) {
				ctx->prog_fds[EK_METRICS_PROG_EXIT] =
				    ek_bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT,
						     prog, insn_cnt, "ek_exit",
						     log_buf, sizeof(log_buf));
				if (ctx->prog_fds[EK_METRICS_PROG_EXIT] >= 0)
					programs_loaded++;
				else
					LOG_WARN(
					    "metrics: exit prog load: %s",
					    strerror(
						-ctx->prog_fds
						     [EK_METRICS_PROG_EXIT]));
			}
		}
	}

	/* OOM program */
	{
		int pid_off =
		    ek_bpf_tp_field_offset("oom", "mark_victim", "pid");
		if (pid_off >= 0) {
			insn_cnt = generate_oom_program(
			    prog, MAX_TP_INSNS, ctx->cgroup_map_fd,
			    ctx->ringbuf_fd, pid_off);
			if (insn_cnt > 0) {
				ctx->prog_fds[EK_METRICS_PROG_OOM] =
				    ek_bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT,
						     prog, insn_cnt, "ek_oom",
						     log_buf, sizeof(log_buf));
				if (ctx->prog_fds[EK_METRICS_PROG_OOM] >= 0)
					programs_loaded++;
				else
					LOG_WARN(
					    "metrics: oom prog load: %s",
					    strerror(
						-ctx->prog_fds
						     [EK_METRICS_PROG_OOM]));
			}
		}
	}

	if (programs_loaded == 0) {
		LOG_ERR("metrics: no BPF programs loaded");
		ret = -ENOTSUP;
		goto fail;
	}

	/* Attach loaded programs to tracepoints */
	for (int i = 0; i < EK_METRICS_N_PROGS; i++) {
		if (ctx->prog_fds[i] >= 0)
			attach_program(ctx, i);
	}

	LOG_INFO("metrics: started for %s (cgroup_id=%lu, %d programs)",
		 cgroup_path, (unsigned long)cgroup_id, programs_loaded);
	return 0;

fail:
	ek_metrics_stop(ctx);
	return ret;
}
