/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * erlkoenig_cg.h - cgroup v2 management for containers.
 *
 * Creates per-container cgroups, sets resource limits, and
 * tears down cgroups on container exit. All operations are
 * pure file I/O on cgroupfs — no external tools.
 *
 * Base path auto-detection:
 *   1. systemd-delegated: reads /proc/self/cgroup
 *   2. Fallback: /sys/fs/cgroup/erlkoenig/
 */

#ifndef ERLKOENIG_CG_H
#define ERLKOENIG_CG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Detect the cgroup base path for this runtime instance.
 *
 * Tries systemd delegation first (reads /proc/self/cgroup),
 * falls back to /sys/fs/cgroup/erlkoenig/ for manual starts.
 *
 * Returns 0 on success, -errno on failure.
 */
int erlkoenig_cg_detect_base(char *path, size_t len);

/*
 * Create a cgroup for a container, set limits, move PID into it.
 *
 * @pid:           Container child PID
 * @name:          Container name (used as cgroup directory: ct-<name>)
 * @memory_max:    Memory limit in bytes (0 = no limit)
 * @pids_max:      PID limit (0 = no limit)
 * @cpu_weight:    CPU weight 1-10000 (0 = default 100)
 * @cgroup_path_out: Receives the full cgroup path (for metrics/cleanup)
 * @path_len:      Size of cgroup_path_out buffer
 *
 * Returns 0 on success, -errno on failure.
 * On failure, partially created cgroups are cleaned up.
 */
int erlkoenig_cg_setup(pid_t pid, const char *name, uint64_t memory_max,
		       uint32_t pids_max, uint32_t cpu_weight,
		       char *cgroup_path_out, size_t path_len);

/*
 * Tear down a container's cgroup.
 *
 * Writes "1" to cgroup.kill (kills all remaining processes),
 * waits briefly, then removes the directory.
 *
 * Safe to call with NULL or empty path (no-op).
 */
void erlkoenig_cg_teardown(const char *cgroup_path);

#endif /* ERLKOENIG_CG_H */
