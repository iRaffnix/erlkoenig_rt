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
 * erlkoenig_bpf.h - Shared eBPF infrastructure.
 *
 * BPF instruction macros, syscall wrappers, and helpers used by
 * both the cgroup device filter and tracepoint metrics programs.
 *
 * All BPF programs are hand-assembled as struct bpf_insn arrays
 * (no libbpf dependency). This follows the crun/runc approach
 * and keeps the static musl build clean.
 */

#ifndef ERLKOENIG_BPF_H
#define ERLKOENIG_BPF_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

/* ------------------------------------------------------------------ */
/* BPF register numbers                                                */
/* ------------------------------------------------------------------ */

#define BPF_REG_0  0  /* return value / helper result */
#define BPF_REG_1  1  /* arg1 / ctx pointer */
#define BPF_REG_2  2  /* arg2 */
#define BPF_REG_3  3  /* arg3 */
#define BPF_REG_4  4  /* arg4 */
#define BPF_REG_5  5  /* arg5 */
#define BPF_REG_6  6  /* callee-saved */
#define BPF_REG_7  7  /* callee-saved */
#define BPF_REG_8  8  /* callee-saved */
#define BPF_REG_9  9  /* callee-saved */
#define BPF_REG_FP 10 /* frame pointer (read-only) */

/* ------------------------------------------------------------------ */
/* BPF instruction macros                                              */
/* ------------------------------------------------------------------ */

/* ALU32 with immediate: dst OP= imm */
#define BPF_ALU32_IMM(OP, DST, IMM)                                            \
	((struct bpf_insn){                                                    \
	    .code = BPF_ALU | BPF_OP(OP) | BPF_K,                              \
	    .dst_reg = (DST),                                                  \
	    .src_reg = 0,                                                      \
	    .off = 0,                                                          \
	    .imm = (IMM),                                                      \
	})

/* ALU64 with immediate: dst OP= imm (64-bit) */
#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
	((struct bpf_insn){                                                    \
	    .code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                            \
	    .dst_reg = (DST),                                                  \
	    .src_reg = 0,                                                      \
	    .off = 0,                                                          \
	    .imm = (IMM),                                                      \
	})

/* ALU64 register-register: dst OP= src */
#define BPF_ALU64_REG(OP, DST, SRC)                                            \
	((struct bpf_insn){                                                    \
	    .code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                            \
	    .dst_reg = (DST),                                                  \
	    .src_reg = (SRC),                                                  \
	    .off = 0,                                                          \
	    .imm = 0,                                                          \
	})

/* Load from memory: dst = *(size *)(src + off) */
#define BPF_LDX_MEM(SZ, DST, SRC, OFF)                                         \
	((struct bpf_insn){                                                    \
	    .code = BPF_LDX | BPF_SIZE(SZ) | BPF_MEM,                          \
	    .dst_reg = (DST),                                                  \
	    .src_reg = (SRC),                                                  \
	    .off = (OFF),                                                      \
	    .imm = 0,                                                          \
	})

/* Store register to memory: *(size *)(dst + off) = src */
#define BPF_STX_MEM(SZ, DST, SRC, OFF)                                         \
	((struct bpf_insn){                                                    \
	    .code = BPF_STX | BPF_SIZE(SZ) | BPF_MEM,                          \
	    .dst_reg = (DST),                                                  \
	    .src_reg = (SRC),                                                  \
	    .off = (OFF),                                                      \
	    .imm = 0,                                                          \
	})

/* Store immediate to memory: *(size *)(dst + off) = imm */
#define BPF_ST_MEM(SZ, DST, OFF, IMM)                                          \
	((struct bpf_insn){                                                    \
	    .code = BPF_ST | BPF_SIZE(SZ) | BPF_MEM,                           \
	    .dst_reg = (DST),                                                  \
	    .src_reg = 0,                                                      \
	    .off = (OFF),                                                      \
	    .imm = (IMM),                                                      \
	})

/* Move immediate into register: dst = imm (64-bit) */
#define BPF_MOV64_IMM(DST, IMM)                                                \
	((struct bpf_insn){                                                    \
	    .code = BPF_ALU64 | BPF_OP(BPF_MOV) | BPF_K,                       \
	    .dst_reg = (DST),                                                  \
	    .src_reg = 0,                                                      \
	    .off = 0,                                                          \
	    .imm = (IMM),                                                      \
	})

/* Move register: dst = src (64-bit) */
#define BPF_MOV64_REG(DST, SRC)                                                \
	((struct bpf_insn){                                                    \
	    .code = BPF_ALU64 | BPF_OP(BPF_MOV) | BPF_X,                       \
	    .dst_reg = (DST),                                                  \
	    .src_reg = (SRC),                                                  \
	    .off = 0,                                                          \
	    .imm = 0,                                                          \
	})

/* Conditional jump (reg vs imm): if (dst OP imm) goto PC+off */
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
	((struct bpf_insn){                                                    \
	    .code = BPF_JMP | BPF_OP(OP) | BPF_K,                              \
	    .dst_reg = (DST),                                                  \
	    .src_reg = 0,                                                      \
	    .off = (__s16)(OFF),                                               \
	    .imm = (IMM),                                                      \
	})

/* Conditional jump (reg vs reg): if (dst OP src) goto PC+off */
#define BPF_JMP_REG(OP, DST, SRC, OFF)                                         \
	((struct bpf_insn){                                                    \
	    .code = BPF_JMP | BPF_OP(OP) | BPF_X,                              \
	    .dst_reg = (DST),                                                  \
	    .src_reg = (SRC),                                                  \
	    .off = (__s16)(OFF),                                               \
	    .imm = 0,                                                          \
	})

/* Program exit: return R0 */
#define BPF_EXIT_INSN()                                                        \
	((struct bpf_insn){                                                    \
	    .code = BPF_JMP | BPF_OP(BPF_EXIT),                                \
	    .dst_reg = 0,                                                      \
	    .src_reg = 0,                                                      \
	    .off = 0,                                                          \
	    .imm = 0,                                                          \
	})

/* Call BPF helper function by ID */
#define BPF_CALL_HELPER(FUNC_ID)                                               \
	((struct bpf_insn){                                                    \
	    .code = BPF_JMP | BPF_OP(BPF_CALL),                                \
	    .dst_reg = 0,                                                      \
	    .src_reg = 0,                                                      \
	    .off = 0,                                                          \
	    .imm = (FUNC_ID),                                                  \
	})

/*
 * Load 64-bit map fd pseudo-instruction.
 * This is a 2-instruction sequence: the kernel replaces the fd
 * with the internal map pointer at program load time.
 *
 * Usage: prog[pc] = BPF_LD_MAP_FD_1(reg, fd);
 *        prog[pc+1] = BPF_LD_MAP_FD_2();
 *        pc += 2;
 */
#define BPF_LD_MAP_FD_1(DST, FD)                                               \
	((struct bpf_insn){                                                    \
	    .code = BPF_LD | BPF_DW | BPF_IMM,                                 \
	    .dst_reg = (DST),                                                  \
	    .src_reg = BPF_PSEUDO_MAP_FD,                                      \
	    .off = 0,                                                          \
	    .imm = (FD),                                                       \
	})

#define BPF_LD_MAP_FD_2()                                                      \
	((struct bpf_insn){                                                    \
	    .code = 0,                                                         \
	    .dst_reg = 0,                                                      \
	    .src_reg = 0,                                                      \
	    .off = 0,                                                          \
	    .imm = 0,                                                          \
	})

/* ------------------------------------------------------------------ */
/* BPF helper function IDs (stable kernel ABI)                         */
/* ------------------------------------------------------------------ */

#define BPF_FUNC_map_lookup_elem       1   /* since 3.18 */
#define BPF_FUNC_map_update_elem       2   /* since 3.18 */
#define BPF_FUNC_ktime_get_ns	       5   /* since 4.1  */
#define BPF_FUNC_get_current_pid_tgid  14  /* since 4.2  */
#define BPF_FUNC_get_current_cgroup_id 80  /* since 4.18 */
#define BPF_FUNC_ringbuf_reserve       131 /* since 5.8  */
#define BPF_FUNC_ringbuf_submit	       132 /* since 5.8  */
#define BPF_FUNC_ringbuf_output	       130 /* since 5.8  */
#define BPF_FUNC_probe_read_kernel     113 /* since 5.5  */
#define BPF_FUNC_get_current_comm      16  /* since 4.2  */

/* ------------------------------------------------------------------ */
/* BPF syscall wrapper                                                 */
/* ------------------------------------------------------------------ */

static inline int ek_bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr,
			     unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

/*
 * Ensure RLIMIT_MEMLOCK is high enough for BPF.
 * Without this, BPF_PROG_LOAD fails with EPERM/ENOSPC
 * on systems with low default memlock limits.
 */
static inline void ek_bpf_raise_memlock(void)
{
	struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
	(void)setrlimit(RLIMIT_MEMLOCK, &rl);
}

/* ------------------------------------------------------------------ */
/* BPF map helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * Create a BPF map. Returns fd on success, -errno on failure.
 */
static inline int ek_bpf_map_create(enum bpf_map_type type, uint32_t key_size,
				    uint32_t value_size, uint32_t max_entries)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	int fd = ek_bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0)
		return -errno;
	return fd;
}

/*
 * Create a BPF ring buffer map. Returns fd on success, -errno on failure.
 * size must be a power of 2 and page-aligned.
 */
static inline int ek_bpf_ringbuf_create(uint32_t size)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_RINGBUF;
	attr.max_entries = size;

	int fd = ek_bpf_sys(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0)
		return -errno;
	return fd;
}

/*
 * Update a map element. Returns 0 on success, -errno on failure.
 */
static inline int ek_bpf_map_update(int map_fd, const void *key,
				    const void *value, uint64_t flags)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(unsigned long)key;
	attr.value = (uint64_t)(unsigned long)value;
	attr.flags = flags;

	if (ek_bpf_sys(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
		return -errno;
	return 0;
}

/* ------------------------------------------------------------------ */
/* BPF program load                                                    */
/* ------------------------------------------------------------------ */

/*
 * Load a BPF program. Returns fd on success, -errno on failure.
 * prog_type: BPF_PROG_TYPE_CGROUP_DEVICE, BPF_PROG_TYPE_TRACEPOINT, etc.
 */
static inline int ek_bpf_prog_load(enum bpf_prog_type prog_type,
				   struct bpf_insn *insns, int insn_cnt,
				   const char *name, char *log_buf,
				   size_t log_size)
{
	union bpf_attr attr;
	int fd;

	ek_bpf_raise_memlock();

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = prog_type;
	attr.insns = (uint64_t)(unsigned long)insns;
	attr.insn_cnt = (uint32_t)insn_cnt;
	attr.license = (uint64_t)(unsigned long)"GPL";
	attr.log_level = 0;
	attr.log_buf = (uint64_t)(unsigned long)log_buf;
	attr.log_size = (uint32_t)log_size;

	if (name) {
		size_t nlen = strlen(name);
		if (nlen > sizeof(attr.prog_name) - 1)
			nlen = sizeof(attr.prog_name) - 1;
		memcpy(attr.prog_name, name, nlen);
	}

	fd = ek_bpf_sys(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0) {
		/* Retry with verifier log for debugging */
		attr.log_level = 1;
		fd = ek_bpf_sys(BPF_PROG_LOAD, &attr, sizeof(attr));
		if (fd < 0) {
			int saved = errno;
			if (log_buf && log_buf[0])
				fprintf(stderr,
					"bpf: prog_load(%s) failed: %s\n"
					"  verifier: %s\n",
					name ? name : "?", strerror(saved),
					log_buf);
			else
				fprintf(stderr,
					"bpf: prog_load(%s) failed: %s\n",
					name ? name : "?", strerror(saved));
			return -saved;
		}
	}
	return fd;
}

/* ------------------------------------------------------------------ */
/* Tracepoint attachment via perf_event_open                           */
/* ------------------------------------------------------------------ */

#include <linux/perf_event.h>
#include <sys/ioctl.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

/*
 * Read tracepoint ID from tracefs.
 * Tries /sys/kernel/tracing first, then /sys/kernel/debug/tracing.
 * Returns ID on success, -errno on failure.
 */
static inline int ek_bpf_tracepoint_id(const char *group, const char *name)
{
	char path[256];
	char buf[32];
	int fd, ret;

	static const char *bases[] = {
	    "/sys/kernel/tracing/events",
	    "/sys/kernel/debug/tracing/events",
	};

	for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
		ret = snprintf(path, sizeof(path), "%s/%s/%s/id", bases[i],
			       group, name);
		if (ret < 0 || (size_t)ret >= sizeof(path))
			continue;

		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			ssize_t n = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			if (n > 0) {
				buf[n] = '\0';
				char *endptr;
				long val = strtol(buf, &endptr, 10);
				if (endptr == buf || val <= 0 || val > INT_MAX)
					continue;
				return (int)val;
			}
		}
	}

	fprintf(stderr, "bpf: cannot read tracepoint id for %s/%s\n", group,
		name);
	return -ENOENT;
}

/*
 * Attach a BPF program to a tracepoint on a specific CPU.
 * Returns perf_event fd on success, -errno on failure.
 */
static inline int ek_bpf_attach_tracepoint_cpu(int prog_fd, int tracepoint_id,
					       int cpu)
{
	struct perf_event_attr pe;
	int perf_fd;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_TRACEPOINT;
	pe.size = sizeof(pe);
	pe.config = (uint64_t)(unsigned int)tracepoint_id;
	pe.sample_period = 1;
	pe.sample_type = PERF_SAMPLE_RAW;
	pe.wakeup_events = 1;

	perf_fd = (int)syscall(__NR_perf_event_open, &pe, -1 /* all pids */,
			       cpu, -1 /* group */, PERF_FLAG_FD_CLOEXEC);
	if (perf_fd < 0)
		return -errno;

	if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
		int saved = errno;
		close(perf_fd);
		return -saved;
	}

	if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		int saved = errno;
		close(perf_fd);
		return -saved;
	}

	return perf_fd;
}

/*
 * Get number of online CPUs.
 * Reads /sys/devices/system/cpu/online and counts CPUs.
 * Returns count, or -1 on failure.
 */
static inline int ek_bpf_online_cpus(void)
{
	int n = (int)sysconf(_SC_NPROCESSORS_ONLN);
	return n > 0 ? n : -1;
}

/* ------------------------------------------------------------------ */
/* Tracepoint format parser                                            */
/* ------------------------------------------------------------------ */

/*
 * Parse a tracepoint format file to find the offset of a named field.
 * Returns offset on success, -1 if not found.
 *
 * Format lines look like:
 *   \tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
 */
static inline int ek_bpf_tp_field_offset(const char *group, const char *tp_name,
					 const char *field_name)
{
	char path[256];
	char line[512];
	int ret, offset = -1;
	FILE *f = NULL;

	static const char *bases[] = {
	    "/sys/kernel/tracing/events",
	    "/sys/kernel/debug/tracing/events",
	};

	for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
		ret = snprintf(path, sizeof(path), "%s/%s/%s/format", bases[i],
			       group, tp_name);
		if (ret < 0 || (size_t)ret >= sizeof(path))
			continue;

		f = fopen(path, "re");
		if (f)
			break;
	}

	if (!f) {
		fprintf(stderr, "bpf: cannot open format for %s/%s\n", group,
			tp_name);
		return -1;
	}

	size_t flen = strlen(field_name);
	while (fgets(line, (int)sizeof(line), f)) {
		/*
		 * Look for "field:TYPE FIELD_NAME;" then "offset:N;"
		 *
		 * Format line example:
		 *   \tfield:pid_t parent_pid;\toffset:24;\tsize:4;
		 *
		 * Skip common_* fields to avoid matching e.g. "common_pid"
		 * when looking for "pid".
		 */
		char *field = strstr(line, "field:");
		if (!field)
			continue;

		/* Skip common_* header fields */
		if (strstr(field, "common_"))
			continue;

		/* Find the field name: scan all occurrences in the line.
		 * Match requires:
		 * - preceded by space, tab, or * (not part of another word)
		 * - followed by ; or [ or tab (end of field name) */
		char *search = field;
		int found = 0;
		char *line_end = line + strlen(line);
		while ((search = strstr(search, field_name)) != NULL) {
			/* Bounds check: field_name must fit within line */
			if (search + flen > line_end)
				break;
			char before = (search > field) ? search[-1] : '\0';
			char after = search[flen];

			if ((before == ' ' || before == '\t' ||
			     before == '*') &&
			    (after == ';' || after == '[' || after == '\t')) {
				found = 1;
				break;
			}
			search += flen;
		}
		if (!found)
			continue;

		/* Find offset:N — use strtol for safety */
		char *off_str = strstr(line, "offset:");
		if (!off_str)
			continue;

		{
			char *endptr;
			long val = strtol(off_str + 7, &endptr, 10);
			if (endptr == off_str + 7 || val < 0 ||
			    val > INT16_MAX) {
				fprintf(stderr,
					"bpf: field '%s' offset out of range: "
					"%ld\n",
					field_name, val);
				continue;
			}
			offset = (int)val;
		}
		break;
	}

	fclose(f);

	if (offset < 0)
		fprintf(stderr, "bpf: field '%s' not found in %s/%s/format\n",
			field_name, group, tp_name);

	return offset;
}

#endif /* ERLKOENIG_BPF_H */
