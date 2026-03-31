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
 * erlkoenig_devfilter.c - eBPF cgroup device filter.
 *
 * Implements device access control for cgroup v2 using
 * BPF_PROG_TYPE_CGROUP_DEVICE. Follows the crun/runc approach
 * of generating BPF bytecode as struct bpf_insn arrays.
 *
 * The kernel's device cgroup hook calls our BPF program on every
 * open/mknod/read/write to a device node. The program receives
 * a bpf_cgroup_dev_ctx:
 *
 *   struct bpf_cgroup_dev_ctx {
 *       u32 access_type;   // lower 16 = type, upper 16 = access
 *       u32 major;
 *       u32 minor;
 *   };
 *
 * Return 1 = allow, 0 = deny (EPERM).
 */

#include "erlkoenig_devfilter.h"
#include "erlkoenig_bpf.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* BPF program generation                                             */
/* ------------------------------------------------------------------ */

/*
 * Maximum BPF instructions:
 *   4 preamble + (5 per rule max) * N_RULES + 2 default deny
 * With 11 default rules: 4 + 55 + 2 = 61, round up generously.
 */
#define MAX_BPF_INSNS 128

/*
 * Count how many jump instructions a rule needs.
 * Each non-wildcard field adds one JNE instruction.
 * Plus 2 for MOV+EXIT (allow return).
 */
static int rule_insn_count(const struct ek_dev_rule *r)
{
	int n = 2; /* MOV R0,1 + EXIT */
	if (r->type != 0)
		n++;
	if (r->access != 0 && r->access != EK_DEV_ACC_RWM)
		n++;
	if (r->major != EK_DEV_WILDCARD)
		n++;
	if (r->minor != EK_DEV_WILDCARD)
		n++;
	return n;
}

/*
 * Generate BPF program for device allowlist.
 *
 * Program structure:
 *   1. Preamble: load ctx fields into R2-R5
 *   2. Per rule: conditional jumps + allow return
 *   3. Default: deny (return 0)
 *
 * Returns number of instructions written, or -1 on overflow.
 */
static int generate_device_filter(struct bpf_insn *prog, size_t max_insns,
				  const struct ek_dev_rule *rules,
				  size_t n_rules)
{
	size_t pc = 0;

	/* --- Preamble: unpack bpf_cgroup_dev_ctx into registers --- */

	/* R2 = ctx->access_type */
	prog[pc++] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0);
	/* R3 = R2 (copy before masking) */
	prog[pc++] = (struct bpf_insn){
	    .code = BPF_ALU64 | BPF_OP(BPF_MOV) | BPF_X,
	    .dst_reg = BPF_REG_3,
	    .src_reg = BPF_REG_2,
	    .off = 0,
	    .imm = 0,
	};
	/* R2 &= 0xFFFF (device type = lower 16 bits) */
	prog[pc++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_2, 0xFFFF);
	/* R3 >>= 16 (access flags = upper 16 bits) */
	prog[pc++] = BPF_ALU32_IMM(BPF_RSH, BPF_REG_3, 16);
	/* R4 = ctx->major (offset 4) */
	prog[pc++] = BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, 4);
	/* R5 = ctx->minor (offset 8) */
	prog[pc++] = BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_1, 8);

	/* --- Per-rule filter blocks --- */
	for (size_t i = 0; i < n_rules; i++) {
		const struct ek_dev_rule *r = &rules[i];
		int skip = rule_insn_count(r) - 1;
		/* skip = number of insns to jump over on mismatch
		 * (all remaining insns in this rule block) */

		if (r->type != 0) {
			if (pc >= max_insns)
				return -1;
			prog[pc++] =
			    BPF_JMP_IMM(BPF_JNE, BPF_REG_2, r->type, skip);
			skip--;
		}
		if (r->access != 0) {
			/*
			 * Access is a bitmask (r=2, w=4, m=1).
			 * We check: does the requested access have any
			 * bits outside the allowed mask?
			 *   (requested & ~allowed) != 0  →  skip (deny)
			 *
			 * In BPF: compute R3 & ~allowed. If nonzero, skip.
			 * But we can't do NOT in BPF easily. Instead:
			 * if access == RWM (7), skip the check (allow all).
			 * Otherwise, mask the requested access against the
			 * complement and check if any forbidden bits remain.
			 *
			 * Simplest correct approach for our use case:
			 * all our default rules use RWM, so access check
			 * is skipped. For custom rules with partial access,
			 * we use JSET to check forbidden bits.
			 */
			if (r->access != EK_DEV_ACC_RWM) {
				/* Check: (requested & ~allowed) != 0 → skip
				 * BPF_JSET jumps if (dst & imm) != 0 */
				uint32_t forbidden =
				    (~r->access) & EK_DEV_ACC_RWM;
				if (pc >= max_insns)
					return -1;
				prog[pc++] =
				    BPF_JMP_IMM(BPF_JSET, BPF_REG_3,
						(int32_t)forbidden, skip);
				skip--;
			} else {
				/* RWM = allow everything, no check needed.
				 * Adjust skip counts for remaining checks. */
			}
		}
		if (r->major != EK_DEV_WILDCARD) {
			if (pc >= max_insns)
				return -1;
			prog[pc++] =
			    BPF_JMP_IMM(BPF_JNE, BPF_REG_4, r->major, skip);
			skip--;
		}
		if (r->minor != EK_DEV_WILDCARD) {
			if (pc >= max_insns)
				return -1;
			prog[pc++] =
			    BPF_JMP_IMM(BPF_JNE, BPF_REG_5, r->minor, skip);
			skip--;
		}

		/* All checks passed → allow */
		if (pc >= max_insns)
			return -1;
		prog[pc++] = BPF_MOV64_IMM(BPF_REG_0, 1);
		if (pc >= max_insns)
			return -1;
		prog[pc++] = BPF_EXIT_INSN();
	}

	/* --- Default: deny --- */
	if (pc >= max_insns)
		return -1;
	prog[pc++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	if (pc >= max_insns)
		return -1;
	prog[pc++] = BPF_EXIT_INSN();

	return (int)pc;
}

/* ------------------------------------------------------------------ */
/* BPF syscall wrappers (now in erlkoenig_bpf.h)                      */
/* Cgroup-device-specific attach wrapper                               */
/* ------------------------------------------------------------------ */

static int bpf_prog_load_cgroup_device(struct bpf_insn *insns, int insn_cnt)
{
	char log_buf[4096];
	return ek_bpf_prog_load(BPF_PROG_TYPE_CGROUP_DEVICE, insns, insn_cnt,
				"ek_devfilter", log_buf, sizeof(log_buf));
}

static int bpf_prog_attach(int prog_fd, int cgroup_fd)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.attach_type = BPF_CGROUP_DEVICE;
	attr.target_fd = (uint32_t)cgroup_fd;
	attr.attach_bpf_fd = (uint32_t)prog_fd;
	attr.attach_flags = BPF_F_ALLOW_MULTI;

	if (ek_bpf_sys(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
		fprintf(stderr, "devfilter: BPF_PROG_ATTACH failed: %s\n",
			strerror(errno));
		return -errno;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int ek_devfilter_attach(const char *cgroup_path,
			const struct ek_dev_rule *rules, size_t n_rules)
{
	struct bpf_insn prog[MAX_BPF_INSNS];
	int insn_cnt, prog_fd, cgroup_fd, ret;

	/* Generate BPF program */
	insn_cnt = generate_device_filter(prog, MAX_BPF_INSNS, rules, n_rules);
	if (insn_cnt < 0) {
		fprintf(stderr, "devfilter: too many BPF instructions\n");
		return -E2BIG;
	}

	/* Load program into kernel */
	prog_fd = bpf_prog_load_cgroup_device(prog, insn_cnt);
	if (prog_fd < 0)
		return prog_fd;

	/* Open cgroup directory */
	cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0) {
		ret = -errno;
		fprintf(stderr, "devfilter: open(%s): %s\n", cgroup_path,
			strerror(errno));
		close(prog_fd);
		return ret;
	}

	/* Attach to cgroup */
	ret = bpf_prog_attach(prog_fd, cgroup_fd);

	close(cgroup_fd);
	close(prog_fd);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Default OCI-compatible device allowlist                            */
/* ------------------------------------------------------------------ */

/*
 * These match the runc/OCI default allowed devices:
 *
 *   /dev/null     c 1:3   rwm
 *   /dev/zero     c 1:5   rwm
 *   /dev/full     c 1:7   rwm
 *   /dev/random   c 1:8   rwm
 *   /dev/urandom  c 1:9   rwm
 *   /dev/tty      c 5:0   rwm
 *   /dev/ptmx     c 5:2   rwm
 *   /dev/pts/N    c 136:* rwm
 */
const struct ek_dev_rule ek_default_dev_rules[] = {
    /* /dev/null */
    {.type = EK_DEV_CHAR, .major = 1, .minor = 3, .access = EK_DEV_ACC_RWM},
    /* /dev/zero */
    {.type = EK_DEV_CHAR, .major = 1, .minor = 5, .access = EK_DEV_ACC_RWM},
    /* /dev/full */
    {.type = EK_DEV_CHAR, .major = 1, .minor = 7, .access = EK_DEV_ACC_RWM},
    /* /dev/random */
    {.type = EK_DEV_CHAR, .major = 1, .minor = 8, .access = EK_DEV_ACC_RWM},
    /* /dev/urandom */
    {.type = EK_DEV_CHAR, .major = 1, .minor = 9, .access = EK_DEV_ACC_RWM},
    /* /dev/tty */
    {.type = EK_DEV_CHAR, .major = 5, .minor = 0, .access = EK_DEV_ACC_RWM},
    /* /dev/ptmx */
    {.type = EK_DEV_CHAR, .major = 5, .minor = 2, .access = EK_DEV_ACC_RWM},
    /* /dev/pts/N (all PTY slaves) */
    {.type = EK_DEV_CHAR,
     .major = 136,
     .minor = EK_DEV_WILDCARD,
     .access = EK_DEV_ACC_RWM},
};

const size_t ek_default_dev_rules_count =
    sizeof(ek_default_dev_rules) / sizeof(ek_default_dev_rules[0]);
