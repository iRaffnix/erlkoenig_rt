/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * erlkoenig_nft.h - Per-container nftables via setns().
 *
 * Applies pre-built nftables netlink batches inside a container's
 * network namespace. The batch is built by Erlang (nft_batch:wrap)
 * and sent as a raw binary blob via CMD_NFT_SETUP.
 *
 * IMPORTANT: setns() affects the calling thread. The C runtime is
 * single-threaded by design (one process per container). If the
 * runtime ever becomes multi-threaded, these functions MUST be
 * serialized via a dedicated helper thread.
 *
 * Required capabilities: CAP_SYS_ADMIN (setns), CAP_NET_ADMIN (nft).
 */

#ifndef ERLKOENIG_NFT_H
#define ERLKOENIG_NFT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * erlkoenig_nft_apply - Apply nftables batch in container netns.
 *
 * @child_pid: Container process PID (host pidns)
 * @batch:     Complete nftables netlink batch (BATCH_BEGIN + msgs + BATCH_END)
 * @batch_len: Length of batch in bytes
 *
 * Opens a NETLINK_NETFILTER socket inside the container's netns,
 * sends the batch, drains ACKs. The batch is transactional: if
 * any message fails, the kernel rolls back the entire batch.
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_nft_apply(pid_t child_pid, const uint8_t *batch,
			size_t batch_len);

/*
 * erlkoenig_nft_list - Dump nftables ruleset from container netns.
 *
 * @child_pid: Container process PID (host pidns)
 * @out:       Output buffer (caller-allocated)
 * @out_len:   Size of output buffer
 * @used:      Actual bytes written
 *
 * Returns 0 on success, negative errno on failure.
 */
int erlkoenig_nft_list(pid_t child_pid, uint8_t *out, size_t out_len,
		       size_t *used);

#endif /* ERLKOENIG_NFT_H */
