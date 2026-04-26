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
 * erlkoenig_ns.c - Container namespace setup.
 *
 * Creates a child process in isolated PID/NET/MNT/UTS/IPC/CGROUP
 * namespaces. The child inherits file capabilities from the parent
 * (set via setcap on the erlkoenig_rt binary) and uses them for
 * mount, pivot_root, setresuid, and capability dropping.
 *
 * Flow:
 *   1. Parent: mkdtemp(), clone(CLONE_NEWPID|CLONE_NEWNET|...)
 *   2. Parent: sends rootfs path via sync_pipe, replies to Erlang
 *   3. Child: mounts tmpfs, bind-mounts devices, pivot_root
 *   4. Erlang: cgroup, network setup, sends CMD_GO
 *   5. Parent: sends 'G' on go_pipe
 *   6. Child: drop caps, seccomp, execve
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "erlkoenig_ns.h"
#include "erlkoenig_proto.h"
#include "erlkoenig_log.h"
#include "erlkoenig_cleanup.h"
#include "erlkoenig_caps.h"
#include "erlkoenig_seccomp.h"
#include "erlkoenig_ns_internal.h"

#include <linux/close_range.h>
#include <linux/openat2.h>
#include <linux/landlock.h>

#define STACK_SIZE (1024UL * 1024)

/* -- Modern kernel primitives (RT-003) ---------------------------- */

/*
 * ek_openat2 - openat2() wrapper with RESOLVE_IN_ROOT.
 *
 * Kernel-enforced path resolution within a root directory.
 * Eliminates symlink traversal attacks (CVE-2019-5736).
 *
 * Requires kernel >= 5.6. No fallback — if openat2 is not available,
 * the runtime refuses to start. This is a hard security requirement.
 */
static int ek_openat2(int dirfd, const char *path, int flags, mode_t mode)
{
	struct open_how how = {
	    .flags = (uint64_t)(unsigned int)flags,
	    .mode = (uint64_t)mode,
	    .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
	    /* Note: RESOLVE_NO_XDEV removed — OverlayFS merges
	     * multiple filesystems (EROFS lower + tmpfs upper),
	     * and NO_XDEV blocks cross-device lookups which are
	     * normal on overlay mounts. RESOLVE_IN_ROOT alone
	     * prevents path escape. */
	};

	int fd = (int)syscall(SYS_openat2, dirfd, path, &how, sizeof(how));

	if (fd < 0 && errno == ENOSYS) {
		LOG_ERR("FATAL: openat2(dirfd=%d, path=%s) returned ENOSYS. "
			"Kernel >= 5.6 required. Check that no seccomp "
			"filter (e.g. systemd ProtectKernelModules) blocks "
			"SYS_openat2 (%d).",
			dirfd, path, SYS_openat2);
		_exit(1);
	}

	return fd;
}

/*
 * ek_close_range - Close all FDs >= lowfd in one syscall.
 *
 * Used before execve to prevent FD leaks into the container.
 * Falls back to manual close loop on kernels < 5.9.
 */
static void ek_close_range_above(int lowfd)
{
	if (syscall(SYS_close_range, (unsigned int)lowfd, ~0U,
		    CLOSE_RANGE_CLOEXEC) == 0)
		return;

	/*
	 * Fallback: iterate /proc/self/fd and set FD_CLOEXEC.
	 * Must use fcntl(F_SETFD, FD_CLOEXEC), NOT close() —
	 * close() would destroy error_pipe_wr which needs to
	 * survive until execve (O_CLOEXEC closes it on exec).
	 */
	LOG_WARN("close_range not available, falling back to /proc/self/fd");
	DIR *dir = opendir("/proc/self/fd");

	if (!dir)
		return;

	int dirfd_num = dirfd(dir);
	struct dirent *de;

	while ((de = readdir(dir)) != NULL) {
		int fd = atoi(de->d_name);

		if (fd >= lowfd && fd != dirfd_num)
			fcntl(fd, F_SETFD, FD_CLOEXEC);
	}
	closedir(dir);
}

/*
 * No CLONE_NEWUSER: erlkoenig_rt uses file capabilities (setcap).
 * The child inherits the parent's caps after clone() and uses them
 * for mount/pivot_root/setresuid/cap-dropping. This avoids user
 * namespace complications (AppArmor userns policy, /proc access).
 *
 * Required file caps: cap_sys_admin, cap_net_admin, cap_sys_chroot,
 * cap_sys_ptrace, cap_setpcap, cap_setuid, cap_setgid, cap_dac_override
 */
#define CLONE_FLAGS                                                            \
	(CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS |            \
	 CLONE_NEWIPC | CLONE_NEWCGROUP | SIGCHLD)

/*
 * clone3() support (Linux 5.3+).
 * Structured interface, supports CLONE_CLEAR_SIGHAND (5.5+) to
 * reset all signal handlers in the child — cleaner than inheriting
 * the parent's handlers. Falls back to clone() on ENOSYS.
 */
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif

/*
 * Note on keyring isolation:
 * 0x200000000 is CLONE_INTO_CGROUP (not CLONE_NEWKEYS — that flag
 * does not exist yet). Keyring isolation is provided implicitly by
 * the PID namespace boundary. Explicit isolation via
 * keyctl(KEYCTL_JOIN_SESSION_KEYRING) can be added in child_init
 * if needed in the future.
 */

struct clone3_args {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t set_tid_size;
	uint64_t cgroup;
};

/*
 * CLONE_PIDFD (Linux 5.2+): kernel returns a pidfd for the child.
 * pidfd eliminates PID reuse races — kill/wait target a specific
 * process incarnation, not just a PID number that could be recycled.
 */
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif

static pid_t try_clone3(int (*fn)(void *), void *arg, int clone_flags,
			int *pidfd_out)
{
	int pidfd = -1;
	struct clone3_args cl_args = {
	    .flags = ((uint64_t)(unsigned int)clone_flags & ~(uint64_t)0xFF) |
		     CLONE_CLEAR_SIGHAND | CLONE_PIDFD,
	    .exit_signal = (uint64_t)((unsigned int)clone_flags & 0xFFu),
	    .pidfd = (uint64_t)(uintptr_t)&pidfd,
	};
	/*
	 * Do NOT set stack/stack_size. With stack=0 the child
	 * inherits the parent's stack (copy-on-write), like fork().
	 * Setting an explicit stack causes the child's SP to move
	 * to the new stack, but the return address from syscall()
	 * is on the old stack — instant SIGSEGV.
	 * The explicit stack is only needed for the clone() fallback.
	 */

	pid_t pid = (pid_t)syscall(SYS_clone3, &cl_args, sizeof(cl_args));

	if (pid == 0) {
		/* Child: call the init function, then exit */
		_exit(fn(arg));
	}
	if (pid > 0 && pidfd_out)
		*pidfd_out = pidfd;
	return pid;
}

/*
 * close_safe - Close an FD and set it to -1.
 * Avoids double-close bugs in error paths.
 */
#define close_safe(fd)                                                         \
	do {                                                                   \
		if ((fd) >= 0) {                                               \
			if (close(fd) && errno != EINTR)                       \
				LOG_WARN("close(%d): %s", (fd),                \
					 strerror(errno));                     \
			(fd) = -1;                                             \
		}                                                              \
	} while (0)

struct child_args {
	int sync_pipe_rd; /* Receives rootfs base path from parent */
	int go_pipe_rd;
	int ready_pipe_wr; /* Child writes 'R' after pivot_root + ro remount */
	int stdout_wr;	   /* -1 in PTY mode */
	int stderr_wr;	   /* -1 in PTY mode */
	int stdin_rd;	   /* Stdin pipe read-end (-1 in PTY mode) */
	int pty_slave;	   /* PTY slave FD (-1 in pipe mode) */
	int error_pipe_wr; /* CLOEXEC pipe: closed on exec, errno on failure */
	int binary_fd;	   /* FD for app binary (opened before clone) */
	int rootfs_fd;	   /* O_DIRECTORY FD on rootfs (for openat2) */
	char loop_dev[32]; /* Pre-attached loop device path (EROFS mode) */
	const struct erlkoenig_spawn_opts *opts;
};

/*
 * mkdtemp_rootfs - Create a temporary directory for the container rootfs.
 *
 * Only creates the directory. The child process handles mounting
 * tmpfs, creating devices, and pivot_root.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ek_mkdtemp_rootfs(char *rootfs, size_t rootfs_len)
{
	int ret;
	const char *base = getenv("ERLKOENIG_ROOTFS_BASE");

	if (!base || base[0] == '\0')
		base = "/tmp";
	ret = snprintf(rootfs, rootfs_len, "%s/erlkoenig_XXXXXX", base);
	if (ret < 0 || (size_t)ret >= rootfs_len)
		return -ENAMETOOLONG;

	if (!mkdtemp(rootfs))
		return -errno;

	return 0;
}

/*
 * bind_mount_dev - Bind-mount a host device node into the rootfs.
 *
 * We create an empty file and bind-mount the host device on top.
 * This is the same approach used by podman/crun/bubblewrap.
 *
 * Must be called BEFORE pivot_root (host /dev still visible).
 */
int ek_bind_mount_dev(const char *rootfs, int rootfs_fd, const char *name,
		      const char *host_path, mode_t mode)
{
	char devpath[64];
	char abs_path[ERLKOENIG_ROOTFS_MAX + 64];

	snprintf(devpath, sizeof(devpath), "dev/%s", name);

	/* Create empty mount target via openat2 (RESOLVE_IN_ROOT) */
	{
		_cleanup_close_ int fd = ek_openat2(
		    rootfs_fd, devpath, O_CREAT | O_WRONLY | O_CLOEXEC, mode);
		if (fd < 0) {
			LOG_SYSCALL("openat2(dev)");
			return -errno;
		}
	}

	/* mount() needs absolute path (no AT_* support) */
	snprintf(abs_path, sizeof(abs_path), "%s/dev/%s", rootfs, name);
	return ek_mount(host_path, abs_path, NULL, MS_BIND, NULL,
			"mount(bind-dev)");
}

/*
 * ek_mkdir_p - Create directory and all parent components under rootfs.
 * @base:	Base path (rootfs prefix)
 * @relpath:	Path relative to base (must start with '/')
 * @mode:	Directory mode for newly created directories
 *
 * Returns 0 on success, negative errno on failure.
 */
static int ek_mkdir_p(const char *base, const char *relpath, mode_t mode)
{
	/*
	 * Buffer sized for rootfs prefix + full dest path. Callers pass
	 * a short rootfs (ERLKOENIG_ROOTFS_MAX) and a dest from the
	 * volume struct (ERLKOENIG_MAX_PATH), so the concatenation can
	 * exceed ERLKOENIG_MAX_PATH even though each component fits.
	 */
	char path[ERLKOENIG_MAX_PATH + ERLKOENIG_ROOTFS_MAX];
	int ret;
	size_t base_len = strlen(base);

	ret = snprintf(path, sizeof(path), "%s%s", base, relpath);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -ENAMETOOLONG;

	/* Walk each component after base, creating directories */
	for (size_t i = base_len + 1; path[i] != '\0'; i++) {
		if (path[i] == '/') {
			path[i] = '\0';
			if (mkdir(path, mode) && errno != EEXIST) {
				LOG_SYSCALL("mkdir(mkdir_p)");
				return -errno;
			}
			path[i] = '/';
		}
	}
	/* Create the final component */
	if (mkdir(path, mode) && errno != EEXIST) {
		LOG_SYSCALL("mkdir(mkdir_p final)");
		return -errno;
	}
	return 0;
}

/*
 * ek_validate_dest_path - Validate a container destination path.
 *
 * Checks: must be absolute, no empty segments, no "." or ".." components.
 * Returns 0 on valid, -EINVAL on invalid.
 */
static int ek_validate_dest_path(const char *dest)
{
	const char *p;
	const char *seg_start;

	if (!dest || dest[0] != '/')
		return -EINVAL;

	p = dest;
	while (*p == '/')
		p++;

	while (*p) {
		seg_start = p;
		while (*p && *p != '/')
			p++;
		size_t seg_len = (size_t)(p - seg_start);

		if (seg_len == 0) {
			/* skip consecutive slashes */
			p++;
			continue;
		}
		if (seg_len == 1 && seg_start[0] == '.')
			return -EINVAL;
		if (seg_len == 2 && seg_start[0] == '.' && seg_start[1] == '.')
			return -EINVAL;

		while (*p == '/')
			p++;
	}

	return 0;
}

/*
 * Bit-mask of MS_* flags that require a second MS_BIND|MS_REMOUNT pass.
 * Linux silently ignores these on the initial MS_BIND; we have to set
 * them on a remount. The subset mirrors what crun and util-linux
 * consider "per-mount" security flags.
 */
#define EK_REMOUNT_FLAGS                                                       \
	(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME |           \
	 MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME)

/*
 * Translate wire-level EK_PROP_* enum to the kernel's MS_* propagation
 * bit. Returns 0 for EK_PROP_NONE (caller must skip the set-propagation
 * step entirely — MS_PRIVATE etc. are exclusive, you can't OR them).
 */
static unsigned long propagation_to_ms(uint8_t prop)
{
	switch (prop) {
	case EK_PROP_PRIVATE:
		return MS_PRIVATE;
	case EK_PROP_SLAVE:
		return MS_SLAVE;
	case EK_PROP_SHARED:
		return MS_SHARED;
	case EK_PROP_UNBINDABLE:
		return MS_UNBINDABLE;
	case EK_PROP_NONE:
	default:
		return 0;
	}
}

/*
 * ek_bind_mount_volume - Bind-mount a host directory into the container rootfs.
 * @rootfs:	Path to the rootfs root (before pivot_root)
 * @vol:	Full volume spec (paths, flags, propagation, data)
 *
 * The source must be an existing directory. The destination is created
 * (mkdir -p) under rootfs. The mount is done before pivot_root, so host
 * paths are still visible.
 *
 * Flow:
 *   1. Initial MS_BIND[|MS_REC] — establishes the bind.
 *   2. MS_REMOUNT with EK_REMOUNT_FLAGS if any are requested — Linux
 *      ignores these on the first MS_BIND.
 *   3. MS_<PROP>[|MS_REC] if propagation requested — separate call,
 *      propagation bits are exclusive of other flags.
 *
 * Returns 0 on success, negative errno on failure.
 */
int ek_bind_mount_volume(const char *rootfs, const struct erlkoenig_volume *vol)
{
	/* rootfs prefix + dest — see ek_mkdir_p for the same rationale. */
	char target[ERLKOENIG_MAX_PATH + ERLKOENIG_ROOTFS_MAX];
	char fd_source[64];
	struct stat st;
	const char *source = vol->source;
	const char *dest = vol->dest;
	uint32_t flags = vol->flags;
	int ret;

	/*
	 * 1. Validate and open source atomically.
	 *
	 * SECURITY: open with O_PATH|O_DIRECTORY|O_NOFOLLOW prevents
	 * TOCTOU race — the FD pins the inode, so a subsequent
	 * symlink replacement of the path has no effect. Mount via
	 * /proc/self/fd/<n> uses the pinned inode, not the path.
	 */
	if (!source || source[0] != '/') {
		LOG_ERR("volume source must be absolute: %s",
			source ? source : "(null)");
		return -EINVAL;
	}

	_cleanup_close_ int src_fd =
	    open(source, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (src_fd < 0) {
		if (errno == ELOOP)
			LOG_ERR("volume source is a symlink (rejected): %s",
				source);
		else
			LOG_SYSCALL("open(volume source)");
		return -errno;
	}

	if (fstat(src_fd, &st)) {
		LOG_SYSCALL("fstat(volume source)");
		return -errno;
	}
	if (!S_ISDIR(st.st_mode)) {
		LOG_ERR("volume source is not a directory: %s", source);
		return -ENOTDIR;
	}

	/* 2. Validate dest: absolute, no traversal */
	ret = ek_validate_dest_path(dest);
	if (ret) {
		LOG_ERR("volume dest path invalid: %s", dest);
		return ret;
	}

	/* 3. Create target directory under rootfs */
	ret = ek_mkdir_p(rootfs, dest, 0755);
	if (ret) {
		LOG_ERR("failed to create volume target: %s%s", rootfs, dest);
		return ret;
	}

	/* 4. Build full target path */
	ret = snprintf(target, sizeof(target), "%s%s", rootfs, dest);
	if (ret < 0 || (size_t)ret >= sizeof(target))
		return -ENAMETOOLONG;

	/*
	 * 5. Initial bind via /proc/self/fd/<n>. Using a user-supplied
	 * MS_BIND isn't strictly necessary on the flags arg here (we
	 * always want a bind), but honour MS_REC if the caller asked
	 * for a recursive bind (e.g. `rbind`).
	 */
	snprintf(fd_source, sizeof(fd_source), "/proc/self/fd/%d", src_fd);
	unsigned long bind_flags = MS_BIND;
	if (flags & MS_REC)
		bind_flags |= MS_REC;
	ret = ek_mount(fd_source, target, NULL, bind_flags, NULL,
		       "mount(bind-volume)");
	if (ret)
		return ret;

	/*
	 * 6. Apply per-mount flags (ro, nosuid, nodev, noexec, atime
	 * family) via MS_REMOUNT. The kernel ignores these on the
	 * first MS_BIND; Explicit remount is the canonical recipe.
	 * `data` is fs-specific passthrough — for bind mounts this is
	 * usually empty, but tmpfs/procfs paths go through here too.
	 */
	uint32_t remount_bits = flags & EK_REMOUNT_FLAGS;
	int need_remount = remount_bits || vol->clear || vol->data[0];
	if (need_remount) {
		const char *data = vol->data[0] ? vol->data : NULL;
		ret = ek_mount(NULL, target, NULL,
			       MS_BIND | MS_REMOUNT | remount_bits, data,
			       "mount(remount volume)");
		if (ret) {
			umount2(target, MNT_DETACH);
			return ret;
		}
	}

	/*
	 * 7. Apply propagation if requested. Propagation flags are
	 * exclusive of everything else — they need their own mount(2)
	 * call with source/fstype/data set to NULL.
	 */
	unsigned long prop_ms = propagation_to_ms(vol->propagation);
	if (prop_ms) {
		unsigned long prop_flags = prop_ms;
		if (vol->recursive)
			prop_flags |= MS_REC;
		ret = ek_mount(NULL, target, NULL, prop_flags, NULL,
			       "mount(propagation volume)");
		if (ret) {
			umount2(target, MNT_DETACH);
			return ret;
		}
	}

	LOG_INFO("volume mounted: %s -> %s%s (flags=0x%x prop=%u%s)", source,
		 rootfs, dest, flags, vol->propagation,
		 vol->recursive ? " rec" : "");
	return 0;
}

/*
 * prepare_rootfs_erofs - Set up rootfs from an EROFS image + OverlayFS.
 *
 * Mounts the EROFS image read-only, creates a tmpfs upper layer,
 * and mounts OverlayFS to combine them. The container gets:
 *   - /app from EROFS (read-only, compressed, verified)
 *   - All writes go to the tmpfs upper layer
 *   - No binary copy needed (it's in the image)
 */
static int prepare_rootfs_erofs(const char *rootfs,
				const struct erlkoenig_spawn_opts *opts,
				const char *loop_dev)
{
	int ret;
	char lower[ERLKOENIG_ROOTFS_MAX + 32];
	char upper[ERLKOENIG_ROOTFS_MAX + 32];
	char work[ERLKOENIG_ROOTFS_MAX + 32];
	char overlay_opts[ERLKOENIG_ROOTFS_MAX * 3 + 128];

	_cleanup_umask_ mode_t old_umask = umask(0);

	/*
	 * 1. Create subdirectories under rootfs for the mount stack.
	 *    rootfs/       ← will be the OverlayFS merged view
	 *    rootfs/.lower ← EROFS image (read-only)
	 *    rootfs/.upper ← tmpfs (writable)
	 *    rootfs/.work  ← OverlayFS work directory
	 */
	snprintf(lower, sizeof(lower), "%s/.lower", rootfs);
	snprintf(upper, sizeof(upper), "%s/.upper", rootfs);
	snprintf(work, sizeof(work), "%s/.work", rootfs);

	/* Mount a small tmpfs on rootfs to hold the mount points */
	ret = ek_mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=4m,mode=0755",
		       "mount(erofs-scaffold)");
	if (ret)
		return ret;

	_cleanup_umount_ const char *umount_guard = rootfs;

	if (mkdir(lower, 0755))
		return -errno;
	if (mkdir(upper, 0755))
		return -errno;
	if (mkdir(work, 0755))
		return -errno;

	/*
	 * 2. Mount EROFS image via pre-attached loop device.
	 *
	 * The parent attached the image to the loop device before clone()
	 * to avoid kernel lock contention (LOOP_CTL_GET_FREE is serialized)
	 * in the child's critical path. We just mount it.
	 */
	ret =
	    ek_mount(loop_dev, lower, "erofs", MS_RDONLY, NULL, "mount(erofs)");
	if (ret) {
		LOG_ERR("EROFS mount failed: %s → %s", opts->image_path, lower);
		return ret;
	}
	LOG_INFO("EROFS: %s on %s via %s", opts->image_path, lower, loop_dev);

	/* 3. Mount OverlayFS: lower=EROFS, upper=tmpfs, merged=rootfs */
	snprintf(overlay_opts, sizeof(overlay_opts),
		 "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work);

	/* We need a separate merged dir — can't overlay on rootfs itself
	 * while lower/upper are subdirs of rootfs. Use a bind-mount trick:
	 * create .merged, mount overlay there, then move-mount to rootfs.
	 */
	char merged[ERLKOENIG_ROOTFS_MAX + 32];

	snprintf(merged, sizeof(merged), "%s/.merged", rootfs);
	if (mkdir(merged, 0755))
		return -errno;

	ret = ek_mount("overlay", merged, "overlay", 0, overlay_opts,
		       "mount(overlay)");
	if (ret) {
		LOG_ERR("OverlayFS mount failed");
		return ret;
	}

	/*
	 * 4. Bind-mount merged on top of rootfs so pivot_root sees it.
	 * After this, rootfs IS the merged OverlayFS view.
	 */
	ret = ek_mount(merged, rootfs, NULL, MS_BIND | MS_REC, NULL,
		       "mount(bind merged→rootfs)");
	if (ret)
		return ret;

	/* 5. Create device dirs and mount points in the merged view */
	{
		_cleanup_close_ int rfd = open(rootfs, O_DIRECTORY | O_CLOEXEC);
		if (rfd < 0)
			return -errno;

		/* These go into the upper layer automatically */
		if (mkdirat(rfd, "dev", 0755) && errno != EEXIST)
			return -errno;
		if (mkdirat(rfd, "proc", 0555) && errno != EEXIST)
			return -errno;
		if (mkdirat(rfd, "tmp", 01777) && errno != EEXIST)
			return -errno;
		if (mkdirat(rfd, "etc", 0755) && errno != EEXIST)
			return -errno;

		/*
		 * Device nodes: mount a minimal tmpfs on /dev and create
		 * nodes with mknod. This replaces 4 bind-mounts (each is
		 * a mount syscall) with 1 mount + 4 mknod — faster.
		 */
		{
			char devdir[ERLKOENIG_ROOTFS_MAX + 16];
			snprintf(devdir, sizeof(devdir), "%s/dev", rootfs);
			ret = ek_mount("tmpfs", devdir, "tmpfs",
				       MS_NOSUID | MS_NOEXEC,
				       "size=64k,mode=0755", "mount(devtmpfs)");
			if (ret)
				return ret;

			static const struct {
				const char *name;
				mode_t mode;
				unsigned int major;
				unsigned int minor;
			} devs[] = {
			    {"null", 0666 | S_IFCHR, 1, 3},
			    {"zero", 0666 | S_IFCHR, 1, 5},
			    {"random", 0444 | S_IFCHR, 1, 8},
			    {"urandom", 0444 | S_IFCHR, 1, 9},
			};
			for (size_t d = 0; d < 4; d++) {
				char path[ERLKOENIG_ROOTFS_MAX + 32];
				snprintf(path, sizeof(path), "%s/dev/%s",
					 rootfs, devs[d].name);
				if (mknod(path, devs[d].mode,
					  makedev(devs[d].major,
						  devs[d].minor))) {
					LOG_SYSCALL("mknod(dev)");
					return -errno;
				}
			}
		}

		/* Bind-mount volumes */
		for (uint8_t i = 0; i < opts->num_volumes; i++) {
			ret = ek_bind_mount_volume(rootfs, &opts->volumes[i]);
			if (ret)
				return ret;
		}

		/*
		 * Write resolv.conf (goes to upper layer) iff a resolver
		 * IP was explicitly passed. dns_ip == 0 means the operator
		 * (via the strict-mode capability framework) declared this
		 * container does NOT need DNS - leave /etc/resolv.conf
		 * absent so getaddrinfo() fails fast and loudly instead of
		 * silently falling back to a default that may or may not
		 * route.
		 */
		if (opts->dns_ip != 0) {
			_cleanup_close_ int fd =
			    ek_openat2(rfd, "etc/resolv.conf",
				       O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
			if (fd < 0) {
				LOG_SYSCALL("openat2(etc/resolv.conf)");
				return -errno;
			}
			char resolv[48];
			uint8_t *ip = (uint8_t *)&opts->dns_ip;
			snprintf(resolv, sizeof(resolv),
				 "nameserver %u.%u.%u.%u\n", ip[0], ip[1],
				 ip[2], ip[3]);
			if (write(fd, resolv, strlen(resolv)) < 0) {
				LOG_SYSCALL("write(resolv.conf)");
				return -errno;
			}
		}
	}

	/* No binary copy needed — /app is in the EROFS image */
	LOG_INFO("EROFS rootfs ready: image=%s merged=%s", opts->image_path,
		 rootfs);

	umount_guard = NULL; /* success */
	return 0;
}

/*
 * prepare_rootfs_in_child - Set up the rootfs inside the child.
 *
 * Called by the child after clone(). The child inherits file
 * capabilities from the parent and can mount tmpfs, bind-mount
 * devices, etc.
 *
 * Layout:
 *   <rootfs>/
 *     proc/        (mountpoint for procfs)
 *     dev/
 *       null       bind-mount from /dev/null
 *       zero       bind-mount from /dev/zero
 *       random     bind-mount from /dev/random
 *       urandom    bind-mount from /dev/urandom
 *     etc/
 *       resolv.conf  nameserver <dns_ip>
 *     tmp/         (writable tmpfs for application)
 *     app          (bind-mount of binary, read-only)
 */
static int prepare_rootfs_in_child(const char *rootfs,
				   const struct erlkoenig_spawn_opts *opts,
				   int binary_fd, int rootfs_fd)
{
	int ret;

	_cleanup_umask_ mode_t old_umask = umask(0);

	/* Mount tmpfs on the rootfs directory */
	char mount_opts[64];
	uint32_t size = opts->rootfs_size_mb > 0 ? opts->rootfs_size_mb : 64;

	snprintf(mount_opts, sizeof(mount_opts), "size=%um,mode=0755", size);

	ret = ek_mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, mount_opts,
		       "mount(tmpfs)");
	if (ret)
		return ret;

	/*
	 * From here on, any failure must umount the rootfs.
	 * _cleanup_umount_ handles this automatically on scope exit.
	 * Set guard to NULL on success to prevent umount.
	 */
	_cleanup_umount_ const char *umount_guard = rootfs;

	/*
	 * Re-open rootfs_fd after tmpfs mount — the old dirfd may
	 * not see the tmpfs mount if it was opened before.
	 */
	_cleanup_close_ int rfd = open(rootfs, O_DIRECTORY | O_CLOEXEC);
	if (rfd < 0) {
		LOG_SYSCALL("open(rootfs dir)");
		return -errno;
	}
	(void)rootfs_fd; /* replaced by rfd after mount */

	/*
	 * RT-003 §1.1: All directory/file creation uses mkdirat/openat2
	 * with the rootfs dirfd. Kernel-enforced RESOLVE_IN_ROOT prevents
	 * symlink traversal attacks (CVE-2019-5736).
	 */

	/* Create directory structure — mkdirat relative to rootfs */
	if (mkdirat(rfd, "proc", 0555) && errno != EEXIST)
		return -errno;
	if (mkdirat(rfd, "dev", 0755) && errno != EEXIST)
		return -errno;
	if (mkdirat(rfd, "tmp", 01777) && errno != EEXIST)
		return -errno;
	if (mkdirat(rfd, "etc", 0755) && errno != EEXIST)
		return -errno;

	/*
	 * Device nodes: mount a minimal tmpfs on /dev and create
	 * nodes with mknod. Replaces 4 bind-mounts with 1 mount + 4 mknod.
	 */
	{
		char devdir[ERLKOENIG_ROOTFS_MAX + 16];
		snprintf(devdir, sizeof(devdir), "%s/dev", rootfs);
		ret = ek_mount("tmpfs", devdir, "tmpfs", MS_NOSUID | MS_NOEXEC,
			       "size=64k,mode=0755", "mount(devtmpfs)");
		if (ret)
			return ret;

		static const struct {
			const char *name;
			mode_t mode;
			unsigned int major;
			unsigned int minor;
		} devs[] = {
		    {"null", 0666 | S_IFCHR, 1, 3},
		    {"zero", 0666 | S_IFCHR, 1, 5},
		    {"random", 0444 | S_IFCHR, 1, 8},
		    {"urandom", 0444 | S_IFCHR, 1, 9},
		};
		for (size_t d = 0; d < 4; d++) {
			char path[ERLKOENIG_ROOTFS_MAX + 32];
			snprintf(path, sizeof(path), "%s/dev/%s", rootfs,
				 devs[d].name);
			if (mknod(path, devs[d].mode,
				  makedev(devs[d].major, devs[d].minor))) {
				LOG_SYSCALL("mknod(dev)");
				return -errno;
			}
		}
	}

	/* Bind-mount persistent volumes (before pivot_root) */
	for (uint8_t i = 0; i < opts->num_volumes; i++) {
		ret = ek_bind_mount_volume(rootfs, &opts->volumes[i]);
		if (ret)
			return ret;
	}

	/*
	 * Create /etc/resolv.conf only when a resolver IP was explicitly
	 * passed. dns_ip == 0 means strict-mode opt-out (the operator
	 * declared this container does NOT need DNS) - leave the file
	 * absent so getaddrinfo() fails fast and loudly.
	 */
	if (opts->dns_ip != 0) {
		_cleanup_close_ int fd =
		    ek_openat2(rfd, "etc/resolv.conf",
			       O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
		if (fd < 0) {
			LOG_SYSCALL("openat2(etc/resolv.conf)");
			return -errno;
		}

		char resolv[48];
		uint8_t *ip = (uint8_t *)&opts->dns_ip;
		snprintf(resolv, sizeof(resolv), "nameserver %u.%u.%u.%u\n",
			 ip[0], ip[1], ip[2], ip[3]);

		if (write(fd, resolv, strlen(resolv)) < 0) {
			LOG_SYSCALL("write(resolv.conf)");
			return -errno;
		}
	}

	/* Copy the target binary to /app via openat2 (RESOLVE_IN_ROOT) */
	{
		_cleanup_close_ int dst = ek_openat2(
		    rfd, "app", O_CREAT | O_WRONLY | O_CLOEXEC, 0555);
		if (dst < 0) {
			LOG_SYSCALL("open(app)");
			return -errno;
		}

		char buf[8192];
		ssize_t nr;

		for (;;) {
			nr = read(binary_fd, buf, sizeof(buf));
			if (nr > 0) {
				ssize_t written = 0;

				while (written < nr) {
					ssize_t nw =
					    write(dst, buf + written,
						  (size_t)(nr - written));
					if (nw < 0) {
						if (errno == EINTR)
							continue;
						LOG_SYSCALL("write(app)");
						return -errno;
					}
					written += nw;
				}
			} else if (nr == 0) {
				break; /* EOF — copy complete */
			} else if (errno == EINTR) {
				continue; /* signal — retry read */
			} else {
				LOG_SYSCALL("read(binary_fd)");
				return -errno;
			}
		}
	}

	/* Success — prevent cleanup from unmounting */
	umount_guard = NULL;
	return 0;
}

static int do_pivot_root_syscall(const char *new_root, const char *put_old)
{
	return (int)syscall(SYS_pivot_root, new_root, put_old);
}

int ek_mount_procfs(const char *rootfs)
{
	char proc_path[ERLKOENIG_ROOTFS_MAX + 32];

	PATH_JOIN(proc_path, "%s/proc", rootfs);
	return ek_mount("proc", proc_path, "proc",
			MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2",
			"mount(proc)");
}

int ek_pivot_root(const char *rootfs)
{
	int ret;

	/*
	 * Make the entire mount tree private. Without this,
	 * shared mount propagation causes pivot_root to fail
	 * with EINVAL (same issue in runc/crun).
	 */
	ret = ek_mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL,
		       "mount(private /)");
	if (ret)
		return ret;

	/*
	 * pivot_root(".", ".") trick (runc, since Linux 3.17):
	 *
	 * 1. Bind-mount rootfs on itself (required: must be mount point)
	 * 2. chdir into it
	 * 3. pivot_root(".", ".") swaps root and cwd atomically
	 * 4. umount2(".", MNT_DETACH) drops the old root
	 *
	 * This eliminates the .put_old directory entirely. The old root
	 * ends up as "." after the pivot, which we immediately detach.
	 * Simpler, race-free, and matches what runc/crun do.
	 */
	ret = ek_mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL,
		       "mount(bind rootfs)");
	if (ret)
		return ret;

	if (chdir(rootfs)) {
		LOG_SYSCALL("chdir(rootfs)");
		umount2(rootfs, MNT_DETACH);
		return -errno;
	}

	if (do_pivot_root_syscall(".", ".")) {
		LOG_SYSCALL("pivot_root");
		umount2(rootfs, MNT_DETACH);
		return -errno;
	}

	/* Old root is now "." — detach it */
	if (umount2(".", MNT_DETACH)) {
		LOG_SYSCALL("umount2(old root)");
		return -errno;
	}

	if (chdir("/")) {
		LOG_SYSCALL("chdir(/)");
		return -errno;
	}

	return 0;
}

/*
 * OCI standard masked paths. Bind-mount /dev/null over sensitive
 * files, mount empty read-only tmpfs over sensitive directories.
 * Prevents container processes from reading kernel information.
 */
static const char *masked_paths[] = {
    "/proc/acpi",	   "/proc/kcore",	  "/proc/keys",
    "/proc/latency_stats", "/proc/timer_list",	  "/proc/sched_debug",
    "/proc/scsi",	   "/proc/sysrq-trigger",
};

#define N_MASKED_PATHS (sizeof(masked_paths) / sizeof(masked_paths[0]))

int ek_mask_paths(void)
{
	size_t i;

	for (i = 0; i < N_MASKED_PATHS; i++) {
		/*
		 * Try bind-mount /dev/null first (covers files).
		 * If ENOTDIR, it's a directory — mount empty tmpfs.
		 * Skip stat() call to save a syscall per path.
		 */
		if (mount("/dev/null", masked_paths[i], NULL,
			  MS_BIND | MS_RDONLY, NULL) == 0) {
			/*
			 * Remount to apply NOSUID/NODEV/NOEXEC on top of the
			 * bind — MS_BIND alone carries the source's per-mount
			 * flags, so without this the mask has weaker flags
			 * than intended. RDONLY on /dev/null already blocks
			 * kernel-memory reads via /proc/kcore etc., so a
			 * remount failure is a hardening gap (log, continue)
			 * not a full security hole.
			 */
			if (mount(NULL, masked_paths[i], NULL,
				  MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID |
				      MS_NODEV | MS_NOEXEC,
				  NULL))
				LOG_WARN("mount(mask remount %s): %s",
					 masked_paths[i], strerror(errno));
			continue;
		}
		if (errno == ENOENT || errno == EACCES)
			continue;

		/* Directory: mount empty read-only tmpfs */
		if (mount("tmpfs", masked_paths[i], "tmpfs",
			  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
			  "size=0,nr_inodes=1")) {
			if (errno == ENOENT || errno == EACCES)
				continue;
			LOG_SYSCALL("mount(mask)");
			return -errno;
		}
	}

	return 0;
}

int ek_setup_readonly_rootfs(uint32_t rootfs_size_mb)
{
	int ret;
	uint32_t size = rootfs_size_mb > 0 ? rootfs_size_mb : 64;

	/*
	 * Read-only rootfs: create /tmp mount point while rootfs is
	 * still writable, then remount / read-only, then mount a
	 * writable tmpfs on /tmp for application scratch space.
	 *
	 * Order: mkdir -> remount-ro -> mount-tmpfs
	 */
	if (mkdir("/tmp", 0777) && errno != EEXIST) {
		LOG_SYSCALL("mkdir(/tmp)");
		return -errno;
	}

	ret = ek_mount("", "/", "", MS_REMOUNT | MS_RDONLY | MS_BIND, NULL,
		       "mount(remount-ro)");
	if (ret)
		return ret;

	{
		char tmpfs_opts[64];

		snprintf(tmpfs_opts, sizeof(tmpfs_opts), "size=%um", size);

		ret = ek_mount("tmpfs", "/tmp", "tmpfs",
			       MS_NOSUID | MS_NODEV | MS_NOEXEC, tmpfs_opts,
			       "mount(/tmp)");
		if (ret)
			return ret;
	}

	LOG_INFO("rootfs remounted read-only, /tmp writable (%u MB)", size);
	return 0;
}

int ek_set_rlimits(void)
{
	struct rlimit rl;

	/* Max 1024 processes (fork bomb protection) */
	rl.rlim_cur = 1024;
	rl.rlim_max = 1024;
	if (setrlimit(RLIMIT_NPROC, &rl)) {
		LOG_SYSCALL("setrlimit(NPROC)");
		return -errno;
	}

	/* Max 1024 open file descriptors */
	rl.rlim_cur = 1024;
	rl.rlim_max = 1024;
	if (setrlimit(RLIMIT_NOFILE, &rl)) {
		LOG_SYSCALL("setrlimit(NOFILE)");
		return -errno;
	}

	/* Max 256 MB file size (prevents filling /tmp) */
	rl.rlim_cur = 256 * 1024 * 1024;
	rl.rlim_max = 256 * 1024 * 1024;
	if (setrlimit(RLIMIT_FSIZE, &rl)) {
		LOG_SYSCALL("setrlimit(FSIZE)");
		return -errno;
	}

	/* No core dumps (prevent info leak) */
	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rl)) {
		LOG_SYSCALL("setrlimit(CORE)");
		return -errno;
	}

	return 0;
}

/*
 * Mini-Init (PID 1 in container namespace)
 * =========================================
 *
 * Problem: In einem PID-Namespace ist der erste Prozess PID 1
 * (init). Der Linux-Kernel schuetzt PID 1 besonders:
 *
 *   - Signale ohne installierten Handler werden IGNORIERT
 *     (auch SIGSEGV via raise()!)
 *   - Nur SIGKILL/SIGSTOP vom Parent-Namespace wirken immer
 *   - SIGTERM, SIGINT etc. werden verworfen wenn kein Handler da ist
 *
 * Das heisst: eine normale Binary als PID 1 kann nicht sauber per
 * SIGTERM gestoppt werden, und Crashes (SIGSEGV, SIGABRT) werden
 * verschluckt -- der Prozess laeuft einfach weiter oder exitiert
 * mit Code 0 statt dem erwarteten Signal.
 *
 * Loesung: Nach dem Namespace-Setup forkt child_init() sich selbst.
 * PID 1 wird unser Mini-Init, die eigentliche Binary laeuft als
 * PID 2. Der Init-Prozess:
 *
 *   1. Installiert Signal-Handler fuer SIGTERM, SIGINT, SIGHUP,
 *      SIGUSR1, SIGUSR2, SIGQUIT
 *   2. Leitet empfangene Signale an PID 2 (die App) weiter
 *   3. Wartet per waitpid() auf das Ende der App
 *   4. Exitiert mit dem gleichen Status:
 *      - Normaler Exit: exit(code)
 *      - Signal-Tod: re-raised das Signal mit SIG_DFL
 *
 * Dieses Muster ist identisch mit Docker's --init (tini) und
 * loest das Problem transparent fuer alle Container-Binaries.
 */

/* PID of the actual application (PID 2), used by signal handler */
static volatile pid_t g_app_pid;

/*
 * init_signal_handler - Forward signals to the app process.
 *
 * Runs as PID 1's signal handler. Sends the received signal
 * to the app (PID 2). If the app is already gone, the kill()
 * fails harmlessly with ESRCH.
 */
static void init_signal_handler(int sig)
{
	pid_t pid = g_app_pid;

	if (pid > 0)
		kill(pid, sig);
}

/*
 * Signals that the init process forwards to the app.
 * SIGKILL/SIGSTOP can't be caught, so they're not listed.
 * SIGCHLD is handled separately (waitpid).
 */
static const int forwarded_signals[] = {SIGTERM, SIGINT,  SIGHUP,
					SIGUSR1, SIGUSR2, SIGQUIT};

#define N_FORWARDED (sizeof(forwarded_signals) / sizeof(forwarded_signals[0]))

int ek_reset_signals(void)
{
	struct sigaction dfl = {
	    .sa_handler = SIG_DFL,
	};
	size_t i;

	for (i = 0; i < N_FORWARDED; i++)
		sigaction(forwarded_signals[i], &dfl, NULL);

	return 0;
}

/*
 * run_init - Mini-init main loop (runs as PID 1).
 * @app_pid:	PID of the application process (PID 2 in our namespace)
 *
 * Forwards signals, reaps zombies, exits when the app exits.
 * Never returns -- calls _exit() directly.
 */
static void run_init(pid_t app_pid)
{
	int status;
	pid_t ret;
	size_t i;

	g_app_pid = app_pid;

	/* Install signal forwarding handlers */
	struct sigaction sa = {
	    .sa_handler = init_signal_handler,
	    .sa_flags = SA_RESTART,
	};
	sigemptyset(&sa.sa_mask);

	for (i = 0; i < N_FORWARDED; i++)
		sigaction(forwarded_signals[i], &sa, NULL);

	/* Main loop: wait for children, reap zombies */
	for (;;) {
		do {
			ret = waitpid(-1, &status, 0);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			/* No more children -- shouldn't happen */
			_exit(1);
		}

		if (ret != app_pid)
			continue; /* Reap zombie, not our app */

		/*
		 * App exited. Reproduce its exit status so the
		 * parent (erlkoenig_rt) sees the correct cause of death.
		 */
		if (WIFSIGNALED(status)) {
			/*
			 * App killed by signal. We can't re-raise
			 * because we're PID 1 (kernel ignores it).
			 * Use the 128+sig convention instead --
			 * erlkoenig_rt decodes this back to a signal.
			 */
			_exit(128 + WTERMSIG(status));
		} else if (WIFEXITED(status)) {
			_exit(WEXITSTATUS(status));
		}

		_exit(1);
	}
}

/*
 * apply_landlock_container - Deny all filesystem access inside container.
 *
 * Creates an empty Landlock ruleset (no rules = deny everything).
 * After activation, the process can only use pre-opened FDs (stdin,
 * stdout, stderr, pipes). New open() calls return EACCES.
 *
 * Graceful fallback: if Landlock is not available (kernel < 5.13),
 * logs a warning and returns 0 (success). The container still runs
 * but without Landlock protection.
 *
 * Must be called AFTER seccomp and cap drop, BEFORE execve.
 */
static int apply_landlock_container(void)
{
	int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
			       LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		LOG_INFO("Landlock: not available (kernel < 5.13), skipping");
		return 0; /* graceful fallback */
	}

	__u64 fs_rights =
	    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
	    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
	    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	    LANDLOCK_ACCESS_FS_MAKE_SYM;

	if (abi >= 2)
		fs_rights |= LANDLOCK_ACCESS_FS_REFER;
	if (abi >= 3)
		fs_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;

	struct landlock_ruleset_attr attr = {
	    .handled_access_fs = fs_rights,
	};

	int ruleset_fd =
	    (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (ruleset_fd < 0) {
		LOG_WARN("landlock_create_ruleset: %s", strerror(errno));
		return 0; /* non-fatal */
	}

	/* Allow EXECUTE on /app — the container binary.
	 * Everything else is denied. */
	{
		int app_dir = open("/app", O_PATH | O_CLOEXEC);
		if (app_dir >= 0) {
			struct landlock_path_beneath_attr app_rule = {
			    .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE |
					      LANDLOCK_ACCESS_FS_READ_FILE,
			    .parent_fd = app_dir,
			};
			syscall(SYS_landlock_add_rule, ruleset_fd,
				LANDLOCK_RULE_PATH_BENEATH, &app_rule, 0);
			close(app_dir);
		}
	}

	/*
	 * NO_NEW_PRIVS is already set by erlkoenig_drop_caps (which is
	 * called before this function and checks its own prctl result).
	 * We re-assert it here because Landlock's man page documents it
	 * as a hard precondition for LANDLOCK_RESTRICT_SELF. If the flag
	 * is already on, this second call is a no-op; if it somehow went
	 * off, this restores it before the restrict call fails harder.
	 */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		LOG_WARN("prctl(NO_NEW_PRIVS) before landlock: %s",
			 strerror(errno));

	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0)) {
		LOG_WARN("landlock_restrict_self: %s", strerror(errno));
		close(ruleset_fd);
		return 0; /* non-fatal */
	}

	close(ruleset_fd);
	LOG_INFO("Landlock: container filesystem access denied (ABI v%d)", abi);
	return 0;
}

/*
 * child_init - Runs inside the cloned child (PID 1 in new namespace).
 *
 * 1. Read rootfs path from sync pipe
 * 2. Prepare rootfs (mount tmpfs, bind-mount devices)
 * 3. Mount procfs, pivot_root
 * 4. Wait for GO signal from Erlang
 * 5. Set UID/GID, redirect stdio
 * 6. Fork: PID 1 becomes init, PID 2 does execve
 */
static int child_init(void *arg)
{
	struct child_args *ca = arg;
	const struct erlkoenig_spawn_opts *opts = ca->opts;
	char rootfs[ERLKOENIG_ROOTFS_MAX];
	ssize_t n;
	pid_t app_pid;
	int ret;

	/*
	 * Read rootfs path from parent via sync pipe.
	 * The child inherits file capabilities from the parent binary
	 * (set via setcap) and can perform privileged operations.
	 */
	do {
		n = read(ca->sync_pipe_rd, rootfs, sizeof(rootfs) - 1);
	} while (n < 0 && errno == EINTR);

	if (n <= 0) {
		LOG_ERR("child: failed to read rootfs path");
		return 1;
	}
	rootfs[(size_t)n] = '\0';

	close_safe(ca->sync_pipe_rd);

	/* Prepare rootfs: EROFS+OverlayFS if image provided, else tmpfs+copy */
	if (opts->image_path[0] != '\0') {
		ret = prepare_rootfs_erofs(rootfs, opts, ca->loop_dev);
		close_safe(ca->binary_fd); /* not needed in image mode */
	} else {
		ret = prepare_rootfs_in_child(rootfs, opts, ca->binary_fd,
					      ca->rootfs_fd);
		close_safe(ca->binary_fd);
	}
	if (ret) {
		LOG_ERR("child: rootfs setup failed: %s", strerror(-ret));
		return 1;
	}

	/* Mount procfs with hidepid=2 to hide other processes' info */
	if (ek_mount_procfs(rootfs))
		return 1;

	/* Isolate mount tree, pivot to new rootfs, detach old root */
	if (ek_pivot_root(rootfs))
		return 1;

	/* Mask sensitive /proc paths (OCI standard masked paths) */
	if (ek_mask_paths())
		return 1;

	/* Read-only rootfs with writable /tmp */
	if (ek_setup_readonly_rootfs(opts->rootfs_size_mb))
		return 1;

	/*
	 * Signal the parent that rootfs setup is complete.
	 *
	 * At this point: EROFS mounted, OverlayFS merged, pivot_root done,
	 * procfs mounted, paths masked, rootfs remounted read-only.
	 * The parent waits for this signal before replying to SPAWN —
	 * without it, CMD_WRITE_FILE could race against pivot_root.
	 */
	{
		uint8_t ready = 'R';
		ssize_t wr;

		do {
			wr = write(ca->ready_pipe_wr, &ready, 1);
		} while (wr < 0 && errno == EINTR);
		close_safe(ca->ready_pipe_wr);

		if (wr != 1) {
			LOG_ERR("child: failed to send ready signal");
			return 1;
		}
	}

	/*
	 * Wait for GO byte from parent. This gives Erlang time to
	 * set up networking (veth pair into our netns) before execve.
	 */
	{
		uint8_t go_byte;
		ssize_t go_n;

		do {
			go_n = read(ca->go_pipe_rd, &go_byte, 1);
		} while (go_n < 0 && errno == EINTR);

		close_safe(ca->go_pipe_rd);

		if (go_n != 1 || go_byte != 'G') {
			LOG_ERR("child: failed to receive GO signal");
			return 1;
		}
	}

	/*
	 * Keep capabilities across UID change (Minijail pattern).
	 * Without this, setresuid drops all caps when moving away
	 * from UID 0. We need caps to survive so erlkoenig_drop_caps
	 * can set securebits and then drop them explicitly.
	 */
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
		LOG_SYSCALL("prctl(KEEPCAPS)");
		return 1;
	}

	/* Drop supplementary groups, then set GID/UID.
	 * setresgid/setresuid set all three IDs (real, effective, saved)
	 * atomically. Plain setgid/setuid may leave the saved-ID unchanged,
	 * enabling privilege escalation back to the original UID.
	 *
	 * Caps survive this because PR_SET_KEEPCAPS is set above.
	 * erlkoenig_drop_caps() will then set securebits (which locks
	 * KEEPCAPS off permanently) and drop all caps explicitly.
	 */
	if (setgroups(0, NULL) && errno != EPERM) {
		LOG_SYSCALL("setgroups");
		return 1;
	}
	/*
	 * Skip setresgid/setresuid when gid/uid == 0: the process
	 * is already root, calling setresuid(0,0,0) is a no-op.
	 * Caps are still dropped by erlkoenig_drop_caps() regardless.
	 */
	if (opts->gid != 0) {
		if (setresgid(opts->gid, opts->gid, opts->gid)) {
			LOG_SYSCALL("setresgid");
			return 1;
		}
	}
	if (opts->uid != 0) {
		if (setresuid(opts->uid, opts->uid, opts->uid)) {
			LOG_SYSCALL("setresuid");
			return 1;
		}
	}

	/*
	 * Redirect stdin and stdout before fork (pipe mode only).
	 * In PTY mode, PID 2 sets up the slave terminal itself.
	 * stderr stays on the original FD so that LOG_* messages
	 * from caps/seccomp setup (in PID 2 before execve) go to
	 * erlkoenig_rt's stderr, not the container output pipe.
	 */
	if (ca->pty_slave < 0) {
		/* Pipe mode: redirect stdin and stdout */
		if (ca->stdin_rd >= 0) {
			if (dup2(ca->stdin_rd, STDIN_FILENO) < 0) {
				LOG_SYSCALL("dup2(stdin pipe)");
				return 1;
			}
			if (ca->stdin_rd > STDIN_FILENO)
				close(ca->stdin_rd);
		} else {
			int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);

			if (devnull < 0) {
				LOG_SYSCALL("open(/dev/null)");
				return 1;
			}
			if (dup2(devnull, STDIN_FILENO) < 0) {
				LOG_SYSCALL("dup2(stdin)");
				return 1;
			}
			if (devnull > STDIN_FILENO)
				close(devnull);
		}
		if (dup2(ca->stdout_wr, STDOUT_FILENO) < 0) {
			LOG_SYSCALL("dup2(stdout)");
			return 1;
		}
		if (ca->stdout_wr > STDERR_FILENO)
			close(ca->stdout_wr);
	}

	/*
	 * Fork into init (PID 1) + app (PID 2).
	 *
	 * We stay as PID 1 and become the mini-init that forwards
	 * signals and reaps the app. The child (PID 2) does execve.
	 * See the "Mini-Init" comment block above for the rationale.
	 */
	app_pid = fork();
	if (app_pid < 0) {
		LOG_SYSCALL("fork(init)");
		return 1;
	}

	if (app_pid == 0) {
		/*
		 * Child (PID 2): harden, redirect I/O, execve.
		 *
		 * PTY mode: setsid + TIOCSCTTY + dup2 slave to all FDs.
		 * Pipe mode: dup2 stderr pipe.
		 *
		 * The error_pipe_wr has O_CLOEXEC set. On successful execve
		 * it is closed automatically (parent reads EOF = success).
		 * On failure we write errno into it so the parent can report
		 * the actual error.
		 */

		/* Reset signal handlers inherited from PID 1 (mini-init) */
		ek_reset_signals();

		/* Set resource limits (fork bomb, FD, file size, core) */
		ek_set_rlimits();

		if (erlkoenig_drop_caps(opts->caps_keep))
			_exit(126);
		if (opts->seccomp_profile != SECCOMP_PROFILE_NONE) {
			if (erlkoenig_apply_seccomp(opts->seccomp_profile))
				_exit(126);
		}

		/* Open the app binary BEFORE Landlock activation.
		 * O_PATH: reference only, no read permission needed.
		 * O_CLOEXEC: closed on successful exec.
		 * After Landlock, open("/app") would fail with EACCES. */
		int app_fd = open("/app", O_PATH | O_CLOEXEC);

		/* NOW activate Landlock — deny all filesystem access.
		 * Pre-opened FDs (stdin/stdout/stderr/pipes/app_fd) still work.
		 * Non-fatal: graceful fallback on kernels < 5.13. */
		apply_landlock_container();

		if (ca->pty_slave >= 0) {
			/* PTY mode: new session, controlling terminal */
			if (setsid() < 0)
				_exit(126);
			if (ioctl(ca->pty_slave, TIOCSCTTY, 0) < 0)
				_exit(126);
			if (dup2(ca->pty_slave, STDIN_FILENO) < 0)
				_exit(126);
			if (dup2(ca->pty_slave, STDOUT_FILENO) < 0)
				_exit(126);
			if (dup2(ca->pty_slave, STDERR_FILENO) < 0)
				_exit(126);
			if (ca->pty_slave > STDERR_FILENO)
				close(ca->pty_slave);
		} else {
			/* Pipe mode: redirect stderr */
			if (dup2(ca->stderr_wr, STDERR_FILENO) < 0)
				_exit(126);
			if (ca->stderr_wr > STDERR_FILENO)
				close(ca->stderr_wr);
		}

		/*
		 * RT-003 §1.5: close_range — close all FDs >= 3 except
		 * error_pipe_wr (which has O_CLOEXEC and will close on exec).
		 * Prevents any FD leak from the runtime into the container.
		 *
		 * Using CLOSE_RANGE_CLOEXEC: marks FDs for close-on-exec
		 * rather than closing immediately, so error_pipe_wr still
		 * works if execveat fails.
		 */
		ek_close_range_above(3);

		/*
		 * RT-003 §1.6: execveat(AT_EMPTY_PATH) — exec via FD.
		 * Opens /app with O_PATH (no read, just reference),
		 * then execveat on the FD. No path lookup at exec time,
		 * eliminating TOCTOU races (binary swap between open and exec).
		 *
		 * SECURITY: only fall back to execve on ENOSYS (kernel
		 * too old for execveat). Any other error (EACCES, ENOEXEC,
		 * ETXTBSY) goes directly to error reporting — falling back
		 * to path-based execve would reopen the TOCTOU window.
		 */
		{
			/* app_fd was opened BEFORE Landlock activation.
			 * If open failed (no /app), fall back to path-based
			 * exec. */
			if (app_fd >= 0) {
				syscall(SYS_execveat, app_fd, "", opts->argv,
					opts->envp, AT_EMPTY_PATH);
				int saved_errno = errno;

				close(app_fd);
				if (saved_errno != ENOSYS) {
					/* Real error — don't fall back to
					 * path-based execve (TOCTOU) */
					errno = saved_errno;
					goto exec_failed;
				}
			}
		}
		/* ENOSYS or open("/app") failed — path-based fallback */
		execve("/app", opts->argv, opts->envp);
	exec_failed:

		/* exec failed — report errno through the error pipe */
		{
			int err = errno;
			ssize_t wr;

			do {
				wr =
				    write(ca->error_pipe_wr, &err, sizeof(err));
			} while (wr < 0 && errno == EINTR);
		}
		_exit(127);
	}

	/* PID 1: close FDs only PID 2 needs */
	if (ca->pty_slave >= 0)
		close(ca->pty_slave);
	if (ca->stderr_wr > STDERR_FILENO)
		close(ca->stderr_wr);

	/* Parent (PID 1): become init, forward signals, wait */
	run_init(app_pid);
	/* run_init never returns */
	return 1;
}

int erlkoenig_spawn(const struct erlkoenig_spawn_opts *opts,
		    struct erlkoenig_container *ct)
{
	_cleanup_close_ int sync_rd = -1, sync_wr = -1;
	_cleanup_close_ int ready_rd = -1, ready_wr = -1;
	_cleanup_close_ int go_rd = -1, go_wr = -1;
	_cleanup_close_ int out_rd = -1, out_wr = -1;
	_cleanup_close_ int err_rd = -1, err_wr = -1;
	_cleanup_close_ int exec_err_rd = -1, exec_err_wr = -1;
	_cleanup_close_ int in_rd = -1, in_wr = -1;
	_cleanup_close_ int pty_master = -1, pty_slave = -1;
	_cleanup_close_ int binary_fd = -1;
	_cleanup_close_ int rootfs_fd = -1;
	char rootfs[ERLKOENIG_ROOTFS_MAX];
	struct child_args ca = {0};
	void *child_stack = MAP_FAILED;
	int flags;
	pid_t pid;
	ssize_t written;
	int ret;
	int child_pidfd = -1;
	int pty_mode = (opts->flags & ERLKOENIG_SPAWN_FLAG_PTY) != 0;

	memset(ct, 0, sizeof(*ct));
	ct->child_pid = -1;
	ct->go_pipe = -1;
	ct->stdout_fd = -1;
	ct->stderr_fd = -1;
	ct->exec_err_fd = -1;
	ct->stdin_fd = -1;
	ct->pty_master = -1;

	/*
	 * In image mode (EROFS), the binary is inside the image as /app.
	 * Skip host-side validation and binary open — the child will
	 * exec /app from the mounted EROFS image.
	 */
	if (opts->image_path[0] == '\0') {
		/* Validate binary path (tmpfs mode only) */
		size_t path_len = strlen(opts->binary_path);

		if (path_len == 0 || opts->binary_path[0] != '/') {
			LOG_ERR("binary path must be absolute: %s",
				opts->binary_path);
			return -EINVAL;
		}

		/*
		 * Open binary FD before clone.  The child copies the binary
		 * via this FD, avoiding path traversal issues.
		 *
		 * Previously we did access(X_OK) here before the open() as a
		 * friendly-error convenience.  That pattern is a classic
		 * TOCTOU (CERT-C FIO01-C): an attacker with write access to
		 * the parent directory could swap the file between the
		 * check and the use, and access() checks REAL-uid while
		 * open() uses effective-uid — two different security
		 * views.  The executable-bit check that actually matters
		 * happens at execve() time inside the container anyway.
		 */
		binary_fd = open(opts->binary_path, O_RDONLY | O_CLOEXEC);
		if (binary_fd < 0) {
			ret = -errno;
			LOG_ERR("open %s: %s", opts->binary_path,
				strerror(errno));
			return ret;
		}
	} else {
		/* Image mode: pre-attach EROFS image to loop device.
		 *
		 * Done in the parent BEFORE clone() to avoid kernel lock
		 * contention (LOOP_CTL_GET_FREE is serialized). The child
		 * only needs to mount() the ready loop device — one syscall
		 * instead of four.
		 *
		 * The previous access(R_OK) check before open() was a
		 * TOCTOU gap; we now rely on open() itself for the
		 * readability check below (same rationale as binary_path).
		 */

		int ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
		if (ctl < 0) {
			ret = -errno;
			LOG_SYSCALL("open(/dev/loop-control)");
			return ret;
		}
		int loop_nr = (int)ioctl(ctl, 0x4C82 /* LOOP_CTL_GET_FREE */);
		close(ctl);
		if (loop_nr < 0) {
			ret = -errno;
			LOG_SYSCALL("LOOP_CTL_GET_FREE");
			return ret;
		}
		snprintf(ca.loop_dev, sizeof(ca.loop_dev), "/dev/loop%d",
			 loop_nr);

		int loop_fd = open(ca.loop_dev, O_RDWR | O_CLOEXEC);
		if (loop_fd < 0) {
			ret = -errno;
			LOG_SYSCALL("open(loop)");
			return ret;
		}
		int img_fd = open(opts->image_path, O_RDONLY | O_CLOEXEC);
		if (img_fd < 0) {
			close(loop_fd);
			ret = -errno;
			LOG_SYSCALL("open(image)");
			return ret;
		}
		if (ioctl(loop_fd, 0x4C00 /* LOOP_SET_FD */, img_fd)) {
			close(img_fd);
			close(loop_fd);
			ret = -errno;
			LOG_SYSCALL("LOOP_SET_FD");
			return ret;
		}
		close(img_fd);
		close(loop_fd);
		LOG_INFO("EROFS: pre-attached %s to %s", opts->image_path,
			 ca.loop_dev);
	}

	/*
	 * Create temp directory for rootfs. The actual rootfs setup
	 * (mount tmpfs, devices, etc.) happens inside the child.
	 *
	 * On failure we MUST goto out_cleanup_rootfs — in image mode we
	 * already pre-attached the EROFS image to /dev/loopN above. A bare
	 * return here would leave the loop device attached, leaking host
	 * resources on every failed spawn (kernel has a finite loop-device
	 * pool). ek_mkdtemp_rootfs leaves the rootfs buffer holding the
	 * unexpanded template, so the cleanup's rmdir() is a safe no-op.
	 */
	ret = ek_mkdtemp_rootfs(rootfs, sizeof(rootfs));
	if (ret) {
		LOG_ERR("mkdtemp_rootfs failed: %s", strerror(-ret));
		rootfs[0] = '\0'; /* don't rmdir a half-printed template */
		goto out_cleanup_rootfs;
	}
	snprintf(ct->rootfs_path, sizeof(ct->rootfs_path), "%s", rootfs);

	/* Open rootfs directory FD for openat2 (RESOLVE_IN_ROOT) */
	rootfs_fd = open(rootfs, O_DIRECTORY | O_CLOEXEC);
	if (rootfs_fd < 0) {
		ret = -errno;
		LOG_ERR("open(rootfs dir): %s", strerror(errno));
		goto out_cleanup_rootfs;
	}

	/* Create sync pipe: parent writes rootfs path, child reads */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(sync)");
			goto out_cleanup_rootfs;
		}
		sync_rd = p[0];
		sync_wr = p[1];
	}

	/* Create GO pipe: parent writes 'G' when Erlang is ready */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(go)");
			goto out_cleanup_rootfs;
		}
		go_rd = p[0];
		go_wr = p[1];
	}

	/* Create READY pipe: child writes 'R' after pivot_root + ro */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(ready)");
			goto out_cleanup_rootfs;
		}
		ready_rd = p[0];
		ready_wr = p[1];
	}

	/* Create stdout/stderr pipes: child writes, parent reads */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(stdout)");
			goto out_cleanup_rootfs;
		}
		out_rd = p[0];
		out_wr = p[1];
	}
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(stderr)");
			goto out_cleanup_rootfs;
		}
		err_rd = p[0];
		err_wr = p[1];
	}

	/* Error pipe for execve failure reporting (CLOEXEC trick).
	 * On successful execve the write-end is closed automatically.
	 * On failure, PID 2 writes errno into it before _exit(127). */
	{
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(exec_err)");
			goto out_cleanup_rootfs;
		}
		exec_err_rd = p[0];
		exec_err_wr = p[1];
	}

	/* Create PTY or stdin pipe depending on mode */
	if (pty_mode) {
		pty_master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (pty_master < 0) {
			ret = -errno;
			LOG_SYSCALL("posix_openpt");
			goto out_cleanup_rootfs;
		}
		if (grantpt(pty_master)) {
			ret = -errno;
			LOG_SYSCALL("grantpt");
			goto out_cleanup_rootfs;
		}
		if (unlockpt(pty_master)) {
			ret = -errno;
			LOG_SYSCALL("unlockpt");
			goto out_cleanup_rootfs;
		}
		char *slave_name = ptsname(pty_master);

		if (!slave_name) {
			ret = -errno;
			LOG_SYSCALL("ptsname");
			goto out_cleanup_rootfs;
		}
		pty_slave = open(slave_name, O_RDWR | O_NOCTTY);
		if (pty_slave < 0) {
			ret = -errno;
			LOG_SYSCALL("open(pty slave)");
			goto out_cleanup_rootfs;
		}
		LOG_DBG("PTY allocated: master=%d slave=%s", pty_master,
			slave_name);
	} else {
		/* Pipe mode: create stdin pipe */
		int p[2];

		if (pipe2(p, O_CLOEXEC)) {
			ret = -errno;
			LOG_SYSCALL("pipe2(stdin)");
			goto out_cleanup_rootfs;
		}
		in_rd = p[0];
		in_wr = p[1];
	}

	/*
	 * Allocate clone stack with guard page.
	 *
	 * Layout (low → high addresses):
	 *   [GUARD PAGE (4K, PROT_NONE)] [STACK (1 MB, PROT_READ|WRITE)]
	 *
	 * Stack overflow hits the guard page → SIGSEGV instead of
	 * silent memory corruption. The guard page costs 4 KB of
	 * virtual address space but zero physical RAM (PROT_NONE
	 * pages are never backed by physical memory).
	 */
	{
		size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);

		child_stack =
		    mmap(NULL, STACK_SIZE + page_sz, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
		if (child_stack == MAP_FAILED) {
			ret = -errno;
			LOG_SYSCALL("mmap(child_stack)");
			goto out_cleanup_rootfs;
		}
		/* Leave first page as PROT_NONE (guard), unlock the rest */
		if (mprotect((char *)child_stack + page_sz, STACK_SIZE,
			     PROT_READ | PROT_WRITE)) {
			ret = -errno;
			LOG_SYSCALL("mprotect(child_stack)");
			munmap(child_stack, STACK_SIZE + page_sz);
			child_stack = MAP_FAILED;
			goto out_cleanup_rootfs;
		}
	}

	ca.sync_pipe_rd = sync_rd;
	ca.go_pipe_rd = go_rd;
	ca.ready_pipe_wr = ready_wr;
	ca.stdout_wr = pty_mode ? -1 : out_wr;
	ca.stderr_wr = pty_mode ? -1 : err_wr;
	ca.stdin_rd = pty_mode ? -1 : in_rd;
	ca.pty_slave = pty_mode ? pty_slave : -1;
	ca.error_pipe_wr = exec_err_wr;
	ca.binary_fd = binary_fd;
	ca.rootfs_fd = rootfs_fd;
	ca.opts = opts;

	/*
	 * The read-ends must NOT have O_CLOEXEC in the child.
	 * clone() copies FDs; the child needs pipe read-ends.
	 * Clear CLOEXEC on all child-side FDs before clone.
	 */
	flags = fcntl(sync_rd, F_GETFD);
	if (flags < 0) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}
	if (fcntl(sync_rd, F_SETFD, flags & ~FD_CLOEXEC)) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}

	flags = fcntl(go_rd, F_GETFD);
	if (flags < 0) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}
	if (fcntl(go_rd, F_SETFD, flags & ~FD_CLOEXEC)) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}

	flags = fcntl(ready_wr, F_GETFD);
	if (flags < 0) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}
	if (fcntl(ready_wr, F_SETFD, flags & ~FD_CLOEXEC)) {
		ret = -errno;
		goto out_cleanup_rootfs;
	}

	/* stdin read-end or PTY slave needs to survive into the child */
	if (pty_mode) {
		flags = fcntl(pty_slave, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(pty_slave, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	} else if (in_rd >= 0) {
		flags = fcntl(in_rd, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(in_rd, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	}

	/* stdout/stderr write-ends need to survive into the child (pipe mode)
	 */
	if (!pty_mode) {
		flags = fcntl(out_wr, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(out_wr, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}

		flags = fcntl(err_wr, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(err_wr, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	}

	/* binary_fd must survive into the child for copying the app binary.
	 * In image mode, binary_fd is -1 (not opened) — skip. */
	if (binary_fd >= 0) {
		flags = fcntl(binary_fd, F_GETFD);
		if (flags < 0) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
		if (fcntl(binary_fd, F_SETFD, flags & ~FD_CLOEXEC)) {
			ret = -errno;
			goto out_cleanup_rootfs;
		}
	}

	/* rootfs_fd needs to survive into child for openat2 */
	flags = fcntl(rootfs_fd, F_GETFD);
	if (flags >= 0)
		fcntl(rootfs_fd, F_SETFD, flags & ~FD_CLOEXEC);

	/*
	 * Try clone3() first (Linux 5.3+, CLONE_CLEAR_SIGHAND 5.5+).
	 * Falls back to clone() on older kernels (ENOSYS).
	 * clone3 inherits the parent's stack (COW), no explicit stack needed.
	 * The explicit stack is only used by the clone() fallback.
	 */
	pid = try_clone3(child_init, &ca, CLONE_FLAGS, &child_pidfd);
	if (pid < 0 && errno == ENOSYS) {
		LOG_INFO("clone3 not available, falling back to clone");
		/* Stack pointer: skip guard page, point to top of stack */
		size_t guard_sz = (size_t)sysconf(_SC_PAGESIZE);

		pid = clone(child_init,
			    (char *)child_stack + guard_sz + STACK_SIZE,
			    CLONE_FLAGS, &ca);
		/* Fallback: get pidfd via pidfd_open (Linux 5.3+) */
		if (pid > 0) {
			child_pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
			if (child_pidfd < 0)
				LOG_INFO("pidfd_open: %s (PID reuse "
					 "protection unavailable)",
					 strerror(errno));
		}
	}
	if (pid < 0) {
		ret = -errno;
		LOG_SYSCALL("clone");
		goto out_cleanup_rootfs;
	}

	/* Parent: close child-side FDs, child has its own copies */
	close_safe(sync_rd);
	close_safe(go_rd);
	close_safe(ready_wr);
	close_safe(out_wr);
	close_safe(err_wr);
	close_safe(exec_err_wr);
	close_safe(in_rd);
	close_safe(pty_slave);
	close_safe(binary_fd);

	/* Free clone stack — child has its own copy after clone */
	munmap(child_stack, STACK_SIZE + (size_t)sysconf(_SC_PAGESIZE));
	child_stack = MAP_FAILED;

	/*
	 * Send rootfs path to child so it can prepare rootfs + pivot_root.
	 * The child blocks on read() until we write here.
	 * The path is always < PIPE_BUF (4096), so the write is atomic.
	 */
	do {
		written = write(sync_wr, rootfs, strlen(rootfs));
	} while (written < 0 && errno == EINTR);

	if (written != (ssize_t)strlen(rootfs)) {
		ret = (written < 0) ? -errno : -EIO;
		LOG_SYSCALL("write(rootfs path)");
		goto out_kill_child;
	}

	/* Close sync write-end: child only needs rootfs path once */
	close_safe(sync_wr);

	/*
	 * Wait for the child to signal that rootfs setup is complete.
	 *
	 * The child writes 'R' on ready_pipe after pivot_root + remount-ro.
	 * Without this sync, CMD_WRITE_FILE could race: /proc/<pid>/root
	 * would still point to the host root instead of the container root
	 * because pivot_root hasn't happened yet.
	 *
	 * If the child dies during setup, read() returns 0 (EOF).
	 */
	{
		uint8_t ready_byte;
		ssize_t rn;

		do {
			rn = read(ready_rd, &ready_byte, 1);
		} while (rn < 0 && errno == EINTR);

		close_safe(ready_rd);

		if (rn != 1 || ready_byte != 'R') {
			LOG_ERR("child failed during rootfs setup "
				"(ready signal not received)");
			ret = -ECHILD;
			goto out_kill_child;
		}
	}

	LOG_DBG("child rootfs ready (pivot_root complete)");

	/* Fill container state -- steal FDs so cleanup won't close them */
	ct->child_pid = pid;
	ct->child_pidfd = child_pidfd;
	child_pidfd = -1; /* ownership transferred */
	ct->go_pipe = steal_fd(&go_wr);
	ct->exec_err_fd = steal_fd(&exec_err_rd);
	if (pty_mode) {
		ct->pty_master = steal_fd(&pty_master);
		ct->stdout_fd = -1;
		ct->stderr_fd = -1;
		ct->stdin_fd = -1;
	} else {
		ct->pty_master = -1;
		ct->stdout_fd = steal_fd(&out_rd);
		ct->stderr_fd = steal_fd(&err_rd);
		ct->stdin_fd = steal_fd(&in_wr);
	}
	snprintf(ct->netns_path, sizeof(ct->netns_path), "/proc/%d/ns/net",
		 (int)pid);

	LOG_INFO("spawned child pid=%d netns=%s", (int)pid, ct->netns_path);
	return 0;

out_kill_child:
	kill(pid, SIGKILL);
	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;
	close_safe(child_pidfd);
out_cleanup_rootfs:
	/* Pipe FDs auto-closed by _cleanup_close_ at return */
	if (child_stack != MAP_FAILED)
		munmap(child_stack, STACK_SIZE + (size_t)sysconf(_SC_PAGESIZE));
	/* Detach loop device if we pre-attached it */
	if (ca.loop_dev[0] != '\0') {
		int lfd = open(ca.loop_dev, O_RDWR | O_CLOEXEC);
		if (lfd >= 0) {
			ioctl(lfd, 0x4C01 /* LOOP_CLR_FD */, 0);
			close(lfd);
		}
	}
	/*
	 * mkdtemp_rootfs only creates an empty directory.
	 * The tmpfs mount happens inside the child.
	 * If we get here before the child ran, just rmdir.
	 * If the child already mounted, umount first.
	 */
	umount2(rootfs, MNT_DETACH); /* May fail (EINVAL) if not mounted */
	rmdir(rootfs);
	return ret;
}

int erlkoenig_go(struct erlkoenig_container *ct)
{
	uint8_t go_byte = 'G';
	ssize_t written;

	if (ct->go_pipe < 0)
		return -EINVAL;

	/*
	 * Send GO byte to child. The child is blocked in read()
	 * after pivot_root, waiting for this signal before execve.
	 * This gives Erlang time to set up networking (veth pair
	 * into the child's network namespace) between SPAWN and GO.
	 */
	do {
		written = write(ct->go_pipe, &go_byte, 1);
	} while (written < 0 && errno == EINTR);

	/*
	 * Save errno BEFORE close_safe — close() can overwrite errno
	 * and we'd return the wrong error code.
	 */
	int saved_errno = errno;

	close_safe(ct->go_pipe);

	if (written != 1)
		return (written < 0) ? -saved_errno : -EIO;

	return 0;
}

void erlkoenig_cleanup(struct erlkoenig_container *ct)
{
	close_safe(ct->go_pipe);
	close_safe(ct->stdout_fd);
	close_safe(ct->stderr_fd);
	close_safe(ct->exec_err_fd);
	close_safe(ct->stdin_fd);
	close_safe(ct->pty_master);
	close_safe(ct->child_pidfd);
	ct->child_pid = -1;
}
