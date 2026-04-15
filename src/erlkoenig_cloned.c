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
 * erlkoenig_cloned.c - CVE-2019-5736 self-protection via memfd re-exec.
 *
 * Threat model
 * ------------
 * A privileged container process (with CAP_DAC_OVERRIDE or running as
 * host-root, ill-advised but possible) can open /proc/<rt-pid>/exe for
 * writing. On classical kernels this yielded an executable, writable
 * fd that could be used to overwrite the live runtime binary from
 * inside the container — identical in spirit to the runC CVE-2019-5736.
 *
 * Defense
 * -------
 * At startup we:
 *   1. open("/proc/self/exe", O_RDONLY)
 *   2. memfd_create(MFD_CLOEXEC | MFD_ALLOW_SEALING)
 *   3. copy contents via read()/write()
 *   4. fcntl(F_ADD_SEALS, SEAL_WRITE|SEAL_SHRINK|SEAL_GROW|SEAL_SEAL)
 *   5. fexecve(memfd, argv, environ) with ERLKOENIG_RT_CLONED=1 set
 *
 * After the re-exec, /proc/self/exe points at the sealed memfd; the
 * on-disk binary may be rewritten without any effect on the running
 * process, and any fd the attacker obtains to /proc/self/exe is a
 * read-only, size-sealed handle to kernel-private memory.
 *
 * Degradation
 * -----------
 * On any failure we LOG_WARN and return, letting main() continue
 * unprotected. The runtime must not refuse to start just because the
 * kernel is too old or SELinux/AppArmor denies memfd_create — the
 * unprotected fallback is still functional, the same way crun's
 * ensure_cloned_binary() is best-effort.
 */

#include "erlkoenig_cloned.h"
#include "erlkoenig_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define EK_CLONED_ENV  "ERLKOENIG_RT_CLONED"
#define EK_CLONED_NAME "erlkoenig_rt"
#define EK_CLONED_SEALS                                                        \
	(F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

/* musl declares char **environ in <unistd.h>. */

/* Copy all readable bytes from src_fd to dst_fd using a stack buffer. */
static int ek_cloned_copy(int dst_fd, int src_fd)
{
	unsigned char buf[8192];

	for (;;) {
		ssize_t n = read(src_fd, buf, sizeof(buf));

		if (n == 0)
			return 0;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		unsigned char *p = buf;
		ssize_t left = n;

		while (left > 0) {
			ssize_t w = write(dst_fd, p, (size_t)left);

			if (w < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			p += w;
			left -= w;
		}
	}
}

void ek_cloned_reexec(char *const argv[])
{
	/* Sentinel: we are the re-exec'd child, protection is already in place.
	 */
	if (getenv(EK_CLONED_ENV))
		return;

	/* Each TU owns its own static g_log_level (see erlkoenig_log.h);
	 * call init here so LOG_INFO/LOG_WARN in this file respect
	 * ERLKOENIG_LOG, since main()'s init runs later than we do. */
	erlkoenig_log_init();

	int src = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);

	if (src < 0) {
		LOG_WARN("[cloned] open(/proc/self/exe) failed: %s — "
			 "continuing unprotected",
			 strerror(errno));
		return;
	}

	int mfd = memfd_create(EK_CLONED_NAME, MFD_CLOEXEC | MFD_ALLOW_SEALING);

	if (mfd < 0) {
		/* ENOSYS: Linux < 3.17. EPERM/EACCES: LSM denial. Treat all
		 * alike and continue unprotected. */
		LOG_WARN(
		    "[cloned] memfd_create failed: %s — continuing unprotected",
		    strerror(errno));
		close(src);
		return;
	}

	if (ek_cloned_copy(mfd, src) < 0) {
		LOG_WARN("[cloned] copy /proc/self/exe -> memfd failed: %s",
			 strerror(errno));
		close(mfd);
		close(src);
		return;
	}
	close(src);

	if (fcntl(mfd, F_ADD_SEALS, EK_CLONED_SEALS) < 0) {
		LOG_WARN(
		    "[cloned] F_ADD_SEALS failed: %s — continuing unprotected",
		    strerror(errno));
		close(mfd);
		return;
	}

	/* Mark the re-exec'd image so we short-circuit on the second main(). */
	if (setenv(EK_CLONED_ENV, "1", 1) < 0) {
		LOG_WARN("[cloned] setenv failed: %s", strerror(errno));
		close(mfd);
		return;
	}

	LOG_INFO("[cloned] running from memfd, on-disk binary insulated");

	/* fexecve() will dup the fd internally; MFD_CLOEXEC is fine. */
	fexecve(mfd, argv, environ);

	/* fexecve only returns on failure. At this point we've already set
	 * the env sentinel, so falling through would risk a dirty state.
	 * Still, per policy we degrade rather than abort: best-effort. */
	LOG_WARN("[cloned] fexecve failed: %s — continuing unprotected",
		 strerror(errno));
	(void)unsetenv(EK_CLONED_ENV);
	close(mfd);
}
