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
 * erlkoenig_cleanup.h - RAII cleanup helpers (inspired by crun/systemd).
 *
 * Uses GCC's __attribute__((cleanup())) to auto-close FDs and
 * restore state when variables go out of scope.
 *
 * Example:
 *     _cleanup_close_ int fd = open("/dev/null", O_RDWR);
 *     if (fd < 0)
 *         return -errno;
 *     // fd is auto-closed when it goes out of scope
 *
 * To keep an FD past scope exit, steal it:
 *     result->fd = steal_fd(&fd);  // sets fd = -1, cleanup is a no-op
 */

#ifndef ERLKOENIG_CLEANUP_H
#define ERLKOENIG_CLEANUP_H

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "erlkoenig_log.h"

#define _cleanup_(f) __attribute__((cleanup(f)))

/* -- File descriptor cleanup -------------------------------------- */

static inline void cleanup_close(int *fd)
{
	if (*fd >= 0) {
		if (close(*fd) && errno != EINTR)
			LOG_WARN("close(%d): %s", *fd, strerror(errno));
	}
}

#define _cleanup_close_ _cleanup_(cleanup_close)

/*
 * steal_fd - Take ownership of an FD from a cleanup variable.
 * Returns the FD and sets the source to -1 so cleanup won't close it.
 */
static inline int steal_fd(int *fd)
{
	int ret = *fd;

	*fd = -1;
	return ret;
}

/* -- umask cleanup ------------------------------------------------ */

static inline void cleanup_umask(mode_t *old)
{
	umask(*old);
}

#define _cleanup_umask_ _cleanup_(cleanup_umask)

/* -- Umount cleanup (for rootfs setup) ---------------------------- */

static inline void cleanup_umount_detach(const char **path)
{
	if (*path)
		umount2(*path, MNT_DETACH);
}

#define _cleanup_umount_ _cleanup_(cleanup_umount_detach)

/* -- Mount helper with unified error handling --------------------- */

/*
 * ek_mount - mount() wrapper with LOG_SYSCALL on failure.
 * Returns 0 on success, -errno on failure.
 */
static inline int ek_mount(const char *src, const char *tgt, const char *type,
			   unsigned long flags, const char *data,
			   const char *label)
{
	if (mount(src, tgt, type, flags, data)) {
		LOG_SYSCALL(label);
		return -errno;
	}
	return 0;
}

/* -- Path construction with bounds check -------------------------- */

/*
 * PATH_JOIN - snprintf into a fixed buffer with automatic bounds check.
 * Returns -ENAMETOOLONG on truncation or snprintf failure.
 *
 * Usage:
 *     char path[PATH_MAX];
 *     PATH_JOIN(path, "%s/proc", rootfs);
 */
#define PATH_JOIN(buf, fmt, ...)                                               \
	do {                                                                   \
		int _pj_r = snprintf(buf, sizeof(buf), fmt, __VA_ARGS__);      \
		if (_pj_r < 0 || (size_t)_pj_r >= sizeof(buf))                 \
			return -ENAMETOOLONG;                                  \
	} while (0)

#endif /* ERLKOENIG_CLEANUP_H */
