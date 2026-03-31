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
 * erlkoenig_ns_internal.h - Internal functions for testing.
 *
 * These functions implement individual container setup steps.
 * They are NOT part of the public API (erlkoenig_ns.h) but are
 * exposed here so the test suite can exercise each step in
 * isolation with real kernel operations.
 *
 * In release builds, -fvisibility=hidden ensures these symbols
 * do not appear in the final binary's export table.
 */

#ifndef ERLKOENIG_NS_INTERNAL_H
#define ERLKOENIG_NS_INTERNAL_H

#include <sys/types.h>
#include <stdint.h>

/*
 * Phase 1: Dateisystem aufbauen
 */

/*
 * ek_mkdtemp_rootfs - Create a temporary directory for the rootfs.
 * @rootfs:	Buffer for the path (filled on success)
 * @rootfs_len:	Size of the buffer
 *
 * Reads ERLKOENIG_ROOTFS_BASE from env, defaults to /tmp.
 * Returns 0 on success, negative errno on failure.
 */
int ek_mkdtemp_rootfs(char *rootfs, size_t rootfs_len);

/*
 * ek_bind_mount_dev - Bind-mount a host device into the rootfs.
 * @rootfs:	Path to rootfs root
 * @name:	Device name (e.g. "null", "zero")
 * @host_path:	Host device path (e.g. "/dev/null")
 * @mode:	File mode for the mount target
 *
 * Creates an empty file at <rootfs>/dev/<name> and bind-mounts
 * the host device on top. Must be called BEFORE pivot_root.
 * Returns 0 on success, negative errno on failure.
 */
int ek_bind_mount_dev(const char *rootfs, int rootfs_fd, const char *name,
		      const char *host_path, mode_t mode);

/*
 * ek_mount_procfs - Mount /proc with hidepid=2.
 * @rootfs:	Path to rootfs root (proc mounted at <rootfs>/proc)
 *
 * hidepid=2 hides other processes' /proc entries, preventing
 * information leaks between containers. Returns 0/-errno.
 */
int ek_mount_procfs(const char *rootfs);

/*
 * ek_bind_mount_volume - Bind-mount a host directory into the rootfs.
 * @rootfs:	Path to rootfs root
 * @source:	Absolute host directory path
 * @dest:	Absolute container directory path
 * @opts:	EK_VOLUME_F_* flags (EK_VOLUME_F_READONLY etc.)
 *
 * Creates the dest directory under rootfs (mkdir -p), then bind-mounts
 * the source on top. For read-only: MS_BIND + MS_BIND|MS_REMOUNT|MS_RDONLY.
 * Must be called BEFORE pivot_root (host paths still visible).
 * Returns 0 on success, negative errno on failure.
 */
int ek_bind_mount_volume(const char *rootfs, const char *source,
			 const char *dest, uint32_t opts);

/*
 * Phase 2: Isolation herstellen
 */

/*
 * ek_pivot_root - Switch to the new rootfs and detach the old one.
 * @rootfs:	Path to the prepared rootfs
 *
 * Uses the runc pattern: bind-mount rootfs on itself, chdir,
 * pivot_root(".", "."), umount2(".", MNT_DETACH), chdir("/").
 * After this call, the process sees only the new rootfs.
 * Returns 0/-errno.
 */
int ek_pivot_root(const char *rootfs);

/*
 * ek_mask_paths - Mask sensitive /proc paths (OCI masked paths).
 *
 * Bind-mounts /dev/null over sensitive files (/proc/kcore, etc.)
 * and mounts empty read-only tmpfs over sensitive directories.
 * Must be called AFTER pivot_root (paths are at /proc/...).
 * Returns 0/-errno. Silently skips paths that don't exist.
 */
int ek_mask_paths(void);

/*
 * ek_setup_readonly_rootfs - Remount / read-only, /tmp writable.
 * @rootfs_size_mb:	Size limit for /tmp tmpfs (0 = default 64 MB)
 *
 * Creates /tmp if needed, remounts / as read-only, then mounts
 * a writable tmpfs on /tmp for application scratch space.
 * Returns 0/-errno.
 */
int ek_setup_readonly_rootfs(uint32_t rootfs_size_mb);

/*
 * Phase 3: Rechte einschraenken
 */

/*
 * ek_set_rlimits - Set resource limits for the container process.
 *
 * RLIMIT_NPROC=1024, RLIMIT_NOFILE=1024, RLIMIT_FSIZE=256MB,
 * RLIMIT_CORE=0. Defense-in-depth alongside cgroup limits.
 * Returns 0/-errno.
 */
int ek_set_rlimits(void);

/*
 * ek_reset_signals - Reset forwarded signal handlers to SIG_DFL.
 *
 * After fork() from PID 1 (mini-init), PID 2 inherits the
 * signal forwarding handlers. This resets them so the application
 * gets default signal behavior.
 * Returns 0 (always succeeds).
 */
int ek_reset_signals(void);

/*
 * Phase 4: Prozessmodell (already in separate files)
 *
 * erlkoenig_drop_caps()    → erlkoenig_caps.h
 * erlkoenig_apply_seccomp() → erlkoenig_seccomp.h
 * run_init()               → internal to erlkoenig_ns.c (tested via spawn)
 */

#endif /* ERLKOENIG_NS_INTERNAL_H */
