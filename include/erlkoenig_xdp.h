/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * erlkoenig_xdp.h — XDP packet steering for container networking.
 *
 * BPF instruction array + helper macros for the XDP steering program.
 * Same technique as erlkoenig_seccomp.h: raw BPF instructions in a
 * C array, loaded via bpf() syscall at runtime. No libbpf, no ELF.
 *
 * The program:
 *   1. Reads the destination IPv4 address from the packet
 *   2. Looks it up in a BPF hash map (IP → veth ifindex)
 *   3. If found: bpf_redirect(ifindex) → XDP_REDIRECT
 *   4. If not found: XDP_PASS (normal kernel stack)
 */

#ifndef ERLKOENIG_XDP_H
#define ERLKOENIG_XDP_H

#include <linux/bpf.h>
#include <stdint.h>

/*
 * BPF instruction macros — not always in kernel headers.
 * These produce struct bpf_insn values for the instruction array.
 */

/* ALU/ALU64 with immediate */
#define BPF_I(CODE, DST, SRC, OFF, IMM)                                        \
	((struct bpf_insn){.code = (CODE),                                     \
			   .dst_reg = (DST),                                   \
			   .src_reg = (SRC),                                   \
			   .off = (OFF),                                       \
			   .imm = (IMM)})

/* 64-bit register move: dst = src */
#define INSN_MOV64_REG(DST, SRC)                                               \
	BPF_I(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)

/* 64-bit immediate move: dst = imm */
#define INSN_MOV64_IMM(DST, IMM)                                               \
	BPF_I(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, (int)(IMM))

/* 64-bit add immediate: dst += imm */
#define INSN_ALU64_IMM(OP, DST, IMM)                                           \
	BPF_I(BPF_ALU64 | (OP) | BPF_K, DST, 0, 0, (int)(IMM))

/* Memory load: dst = *(size *)(src + off) */
#define INSN_LDX_MEM(SIZE, DST, SRC, OFF)                                      \
	BPF_I(BPF_LDX | (SIZE) | BPF_MEM, DST, SRC, (short)(OFF), 0)

/* Memory store: *(size *)(dst + off) = src */
#define INSN_STX_MEM(SIZE, DST, SRC, OFF)                                      \
	BPF_I(BPF_STX | (SIZE) | BPF_MEM, DST, SRC, (short)(OFF), 0)

/* Store immediate: *(size *)(dst + off) = imm */
#define INSN_ST_MEM(SIZE, DST, OFF, IMM)                                       \
	BPF_I(BPF_ST | (SIZE) | BPF_MEM, DST, 0, (short)(OFF), (int)(IMM))

/* Conditional jump: if (dst OP src) goto +off */
#define INSN_JMP_REG(OP, DST, SRC, OFF)                                        \
	BPF_I(BPF_JMP | (OP) | BPF_X, DST, SRC, (short)(OFF), 0)

/* Conditional jump: if (dst OP imm) goto +off */
#define INSN_JMP_IMM(OP, DST, IMM, OFF)                                        \
	BPF_I(BPF_JMP | (OP) | BPF_K, DST, 0, (short)(OFF), (int)(IMM))

/* Helper function call: r0 = helper(r1, r2, r3, r4, r5) */
#define INSN_CALL(HELPER) BPF_I(BPF_JMP | BPF_CALL, 0, 0, 0, (int)(HELPER))

/* Program exit: return r0 */
#define INSN_EXIT() BPF_I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

/*
 * Load map FD into register — takes TWO instruction slots.
 * The imm field is patched at load time with the actual map FD.
 * BPF_PSEUDO_MAP_FD (1) tells the verifier this is a map reference.
 */
#define INSN_LD_MAP_FD(DST, FD)                                                \
	BPF_I(BPF_LD | BPF_DW | BPF_IMM, DST, 1 /* BPF_PSEUDO_MAP_FD */, 0,    \
	      (int)(FD)),                                                      \
	    BPF_I(0, 0, 0, 0, (int)((uint64_t)(FD) >> 32))

/* 64-bit ALU with register: dst OP= src */
#define INSN_ALU64_REG(OP, DST, SRC)                                           \
	BPF_I(BPF_ALU64 | (OP) | BPF_X, DST, SRC, 0, 0)

/* 32-bit ALU with register: dst OP= src (zero-extends result to 64-bit) */
#define INSN_ALU_REG(OP, DST, SRC) BPF_I(BPF_ALU | (OP) | BPF_X, DST, SRC, 0, 0)

/* BPF ALU ops we need beyond BPF_ADD/BPF_MOV */
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif
#ifndef BPF_MOD
#define BPF_MOD 0x90
#endif

/* BPF helper IDs we use */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_redirect	 23

/* BPF registers */
#define R0  0
#define R1  1
#define R2  2
#define R3  3
#define R4  4
#define R5  5
#define R6  6
#define R7  7
#define R8  8
#define R9  9
#define R10 10

/* Ethernet / IPv4 constants */
#define ETH_HLEN     14
#define IP_PROTO_OFF (ETH_HLEN + 9)  /* Offset of protocol in IPv4 header */
#define IP_SRC_OFF   (ETH_HLEN + 12) /* Offset of src IP in IPv4 packet */
#define IP_DST_OFF   (ETH_HLEN + 16) /* Offset of dst IP in IPv4 packet */
#define IP_HDR_MIN   (ETH_HLEN + 20) /* Minimum: eth + IPv4 header */
#define L4_SPORT_OFF (ETH_HLEN + 20) /* TCP/UDP src port (assumes IHL=5) */
#define L4_DPORT_OFF (ETH_HLEN + 22) /* TCP/UDP dst port (assumes IHL=5) */
#define L4_HDR_MIN   (ETH_HLEN + 24) /* eth + ip20 + 4 bytes for ports */

/*
 * Ethertype in NATIVE byte order for BPF_LDX_MEM comparison.
 * eBPF BPF_LDX_MEM(BPF_H) does a raw memory load — unlike classic BPF's
 * BPF_LD_ABS it does NOT convert from network to host byte order.
 * On little-endian x86_64: wire bytes {0x08, 0x00} → host u16 = 0x0008.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ETH_P_IP_NBO 0x0008 /* 0x0800 byte-swapped for LE */
#else
#define ETH_P_IP_NBO 0x0800
#endif

/*
 * BPF map key/value structures for L4 DSR service steering.
 *
 * Service map: {vip, port, proto} → {svc_id, backend_count}
 * Backend map: {svc_id, slot}     → {ifindex}
 * Route map:   {dst_ip}           → {ifindex}  (existing L3 steering)
 */
struct xdp_svc_key {
	uint32_t vip;  /* VIP in network byte order */
	uint16_t port; /* destination port, NBO */
	uint8_t proto; /* IPPROTO_TCP(6) / IPPROTO_UDP(17) */
	uint8_t _pad;
}; /* 8 bytes, naturally aligned */

struct xdp_svc_val {
	uint32_t svc_id;	/* service identifier (auto-assigned) */
	uint32_t backend_count; /* number of active backends */
}; /* 8 bytes */

struct xdp_backend_key {
	uint32_t svc_id; /* matches xdp_svc_val.svc_id */
	uint32_t slot;	 /* 0 .. backend_count-1 */
}; /* 8 bytes */

struct xdp_backend_val {
	uint32_t ifindex; /* veth interface index */
}; /* 4 bytes */

/*
 * XDP steering program — L4 DSR with L3 fallback.
 *
 * For each incoming IPv4 packet:
 *
 *   1. If TCP/UDP: lookup {dst_ip, dst_port, proto} in service_map
 *      → If found: select backend via flow hash, redirect (DSR)
 *   2. Fallback: lookup dst_ip in route_map (existing L3 steering)
 *      → If found: redirect
 *   3. Otherwise: XDP_PASS (normal kernel stack)
 *
 * DSR model: the VIP is NOT rewritten. The packet is redirected to
 * the backend's veth interface with the original dst_ip (= VIP)
 * intact. The backend carries the VIP on its loopback and responds
 * directly to the client.
 *
 * Flow consistency: backend = hash(src_ip, dst_ip, src_port, dst_port) % count
 * Deterministic per 4-tuple, no per-connection state.
 *
 * Register usage:
 *   r6  = saved ctx pointer (callee-saved)
 *   r7  = data pointer (callee-saved)
 *   r8  = data_end pointer (callee-saved)
 *   r9  = scratch (callee-saved, survives helper calls)
 *   r0  = return value / helper result
 *   r1-r5 = helper arguments (caller-saved)
 *   r10 = stack frame pointer
 *
 * Stack layout:
 *   r10 - 4:   dst_ip (u32)              — route_map key
 *   r10 - 16:  svc_key (8 bytes)         — {vip, port, proto, pad}
 *   r10 - 24:  backend_key (8 bytes)     — {svc_id, slot}
 */
static struct bpf_insn xdp_steering_prog[] = {
    /* --- Prologue --- */

    /* [0] Save ctx in r6 */
    INSN_MOV64_REG(R6, R1),

    /* [1] r7 = ctx->data */
    INSN_LDX_MEM(BPF_W, R7, R6, 0),

    /* [2] r8 = ctx->data_end */
    INSN_LDX_MEM(BPF_W, R8, R6, 4),

    /* --- Bounds check: need at least eth(14) + ip(20) = 34 bytes --- */

    /* [3] r9 = data + 34 */
    INSN_MOV64_REG(R9, R7),
    /* [4] */
    INSN_ALU64_IMM(BPF_ADD, R9, IP_HDR_MIN),

    /* [5] if data + 34 > data_end: goto PASS */
    INSN_JMP_REG(BPF_JGT, R9, R8, 54), /* → [60] PASS */

    /* --- Check ethertype == IPv4 --- */

    /* [6] r2 = *(u16 *)(data + 12) */
    INSN_LDX_MEM(BPF_H, R2, R7, 12),

    /* [7] if ethertype != IPv4: goto PASS */
    INSN_JMP_IMM(BPF_JNE, R2, ETH_P_IP_NBO, 52), /* → [60] PASS */

    /* --- Read dst_ip, store for route_map fallback --- */

    /* [8] r2 = *(u32 *)(data + 30) — dst_ip, NBO */
    INSN_LDX_MEM(BPF_W, R2, R7, IP_DST_OFF),

    /* [9] stack[-4] = dst_ip */
    INSN_STX_MEM(BPF_W, R10, R2, -4),

    /* --- L4 service lookup (TCP/UDP only) --- */

    /* [10] r3 = *(u8 *)(data + 23) — IP protocol */
    INSN_LDX_MEM(BPF_B, R3, R7, IP_PROTO_OFF),

    /* [11] if proto == TCP(6): skip to L4 path */
    INSN_JMP_IMM(BPF_JEQ, R3, 6, 1), /* → [13] */

    /* [12] if proto != UDP(17): skip L4, goto ROUTE_LOOKUP */
    INSN_JMP_IMM(BPF_JNE, R3, 17, 37), /* → [50] ROUTE */

    /* --- Extended bounds check for L4 ports --- */

    /* [13] r9 = data + 38 (eth14 + ip20 + ports4) */
    INSN_MOV64_REG(R9, R7),
    /* [14] */
    INSN_ALU64_IMM(BPF_ADD, R9, L4_HDR_MIN),

    /* [15] if data + 38 > data_end: goto ROUTE_LOOKUP */
    INSN_JMP_REG(BPF_JGT, R9, R8, 34), /* → [50] ROUTE */

    /* --- Read dst_port --- */

    /* [16] r4 = *(u16 *)(data + 36) — dst_port, NBO */
    INSN_LDX_MEM(BPF_H, R4, R7, L4_DPORT_OFF),

    /* --- Build service key on stack: {vip:u32, port:u16, proto:u8, pad:u8} ---
     */

    /* [17] stack[-16] = dst_ip (vip) */
    INSN_STX_MEM(BPF_W, R10, R2, -16),

    /* [18] stack[-12] = dst_port */
    INSN_STX_MEM(BPF_H, R10, R4, -12),

    /* [19] stack[-10] = proto */
    INSN_STX_MEM(BPF_B, R10, R3, -10),

    /* [20] stack[-9] = 0 (padding) */
    INSN_ST_MEM(BPF_B, R10, -9, 0),

    /* --- Service map lookup --- */

    /* [21-22] r1 = service_map FD (patched at load time) */
    INSN_LD_MAP_FD(R1, 0),

    /* [23] r2 = &svc_key (r10 - 16) */
    INSN_MOV64_REG(R2, R10),
    /* [24] */
    INSN_ALU64_IMM(BPF_ADD, R2, -16),

    /* [25] r0 = bpf_map_lookup_elem(service_map, &svc_key) */
    INSN_CALL(BPF_FUNC_map_lookup_elem),

    /* [26] if not found: goto ROUTE_LOOKUP */
    INSN_JMP_IMM(BPF_JEQ, R0, 0, 23), /* → [50] ROUTE */

    /* --- Read service value: {svc_id, backend_count} --- */

    /* [27] r4 = svc_id */
    INSN_LDX_MEM(BPF_W, R4, R0, 0),

    /* [28] r3 = backend_count */
    INSN_LDX_MEM(BPF_W, R3, R0, 4),

    /* [29] if backend_count == 0: goto ROUTE_LOOKUP */
    INSN_JMP_IMM(BPF_JEQ, R3, 0, 20), /* → [50] ROUTE */

    /* --- Flow hash: src_ip ^ dst_ip ^ src_port ^ dst_port --- */

    /* [30] r1 = src_ip */
    INSN_LDX_MEM(BPF_W, R1, R7, IP_SRC_OFF),

    /* [31] r2 = dst_ip */
    INSN_LDX_MEM(BPF_W, R2, R7, IP_DST_OFF),

    /* [32] r1 ^= dst_ip */
    INSN_ALU64_REG(BPF_XOR, R1, R2),

    /* [33] r2 = src_port */
    INSN_LDX_MEM(BPF_H, R2, R7, L4_SPORT_OFF),

    /* [34] r1 ^= src_port */
    INSN_ALU64_REG(BPF_XOR, R1, R2),

    /* [35] r2 = dst_port */
    INSN_LDX_MEM(BPF_H, R2, R7, L4_DPORT_OFF),

    /* [36] r1 ^= dst_port */
    INSN_ALU64_REG(BPF_XOR, R1, R2),

    /* [37] slot = hash % backend_count (32-bit ALU to avoid div-by-zero width
       issues) */
    INSN_ALU_REG(BPF_MOD, R1, R3),

    /* --- Build backend key: {svc_id:u32, slot:u32} --- */

    /* [38] stack[-24] = svc_id */
    INSN_STX_MEM(BPF_W, R10, R4, -24),

    /* [39] stack[-20] = slot */
    INSN_STX_MEM(BPF_W, R10, R1, -20),

    /* --- Backend map lookup --- */

    /* [40-41] r1 = backend_map FD (patched at load time) */
    INSN_LD_MAP_FD(R1, 0),

    /* [42] r2 = &backend_key (r10 - 24) */
    INSN_MOV64_REG(R2, R10),
    /* [43] */
    INSN_ALU64_IMM(BPF_ADD, R2, -24),

    /* [44] r0 = bpf_map_lookup_elem(backend_map, &backend_key) */
    INSN_CALL(BPF_FUNC_map_lookup_elem),

    /* [45] if not found: goto ROUTE_LOOKUP */
    INSN_JMP_IMM(BPF_JEQ, R0, 0, 4), /* → [50] ROUTE */

    /* --- DSR redirect: packet goes to backend's veth, VIP intact --- */

    /* [46] r1 = ifindex from backend_map value */
    INSN_LDX_MEM(BPF_W, R1, R0, 0),

    /* [47] r2 = 0 (flags) */
    INSN_MOV64_IMM(R2, 0),

    /* [48] r0 = bpf_redirect(ifindex, 0) */
    INSN_CALL(BPF_FUNC_redirect),

    /* [49] return XDP_REDIRECT */
    INSN_EXIT(),

    /* === ROUTE_LOOKUP: existing L3 steering (dst_ip → ifindex) === */

    /* [50-51] r1 = route_map FD (patched at load time) */
    INSN_LD_MAP_FD(R1, 0),

    /* [52] r2 = &dst_ip (r10 - 4) */
    INSN_MOV64_REG(R2, R10),
    /* [53] */
    INSN_ALU64_IMM(BPF_ADD, R2, -4),

    /* [54] r0 = bpf_map_lookup_elem(route_map, &dst_ip) */
    INSN_CALL(BPF_FUNC_map_lookup_elem),

    /* [55] if not found: goto PASS */
    INSN_JMP_IMM(BPF_JEQ, R0, 0, 4), /* → [60] PASS */

    /* [56] r1 = ifindex from route_map value */
    INSN_LDX_MEM(BPF_W, R1, R0, 0),

    /* [57] r2 = 0 */
    INSN_MOV64_IMM(R2, 0),

    /* [58] r0 = bpf_redirect(ifindex, 0) */
    INSN_CALL(BPF_FUNC_redirect),

    /* [59] return XDP_REDIRECT */
    INSN_EXIT(),

    /* === PASS: let kernel handle it === */

    /* [60] */
    INSN_MOV64_IMM(R0, XDP_PASS),
    /* [61] */
    INSN_EXIT(),
};

#define XDP_STEERING_PROG_LEN                                                  \
	(sizeof(xdp_steering_prog) / sizeof(xdp_steering_prog[0]))

/*
 * Map FD patch indices — each INSN_LD_MAP_FD takes 2 instruction slots.
 * Patch the first slot's .imm field with the real map FD.
 */
#define XDP_SVC_MAP_FD_IDX                                                     \
	21 /* service_map: {vip,port,proto} → {svc_id,count} */
#define XDP_BACKEND_MAP_FD_IDX 40 /* backend_map: {svc_id,slot} → {ifindex} */
#define XDP_ROUTE_MAP_FD_IDX   50 /* route_map: {dst_ip} → {ifindex} */

#endif /* ERLKOENIG_XDP_H */
