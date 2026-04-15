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
 * erlkoenig_cloned.h - CVE-2019-5736 style self-protection.
 *
 * Copies the running /proc/self/exe into a sealed memfd and re-exec's
 * from that fd, so a later compromised container cannot overwrite the
 * privileged runtime binary on disk via /proc/<rt-pid>/exe.
 *
 * See erlkoenig_cloned.c for the threat model.
 */

#ifndef ERLKOENIG_CLONED_H
#define ERLKOENIG_CLONED_H

/*
 * ek_cloned_reexec - Clone /proc/self/exe into a sealed memfd and
 * fexecve() the current process from that fd.
 *
 * Idempotent: sets ERLKOENIG_RT_CLONED=1 and short-circuits on a
 * second call in the re-exec'd child.
 *
 * Degrades gracefully: on any failure (old kernel, ENOSYS,
 * SELinux/AppArmor denial, etc.) it logs and returns, letting the
 * caller continue unprotected rather than refusing to start.
 *
 * Must be called from main() BEFORE any non-trivial setup (signal
 * handlers, file descriptors that would be leaked across execve,
 * etc.) since successful execution replaces the process image.
 *
 * @argv: argv from main(), passed through verbatim to fexecve()
 */
void ek_cloned_reexec(char *const argv[]);

#endif /* ERLKOENIG_CLONED_H */
