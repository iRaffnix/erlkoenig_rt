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
 * erlkoenig_devfilter.h - eBPF cgroup device filter.
 *
 * Generates and attaches a BPF_PROG_TYPE_CGROUP_DEVICE program
 * to restrict which devices a container can access.
 *
 * cgroup v2 has no devices.deny/devices.allow files -- device
 * access control requires an eBPF program attached to the cgroup.
 * This follows the same approach as crun/runc.
 *
 * The BPF program is a simple allowlist filter:
 *   - For each allowed device: check type/major/minor/access
 *   - If any rule matches: return 1 (allow)
 *   - Default: return 0 (deny)
 */

#ifndef ERLKOENIG_DEVFILTER_H
#define ERLKOENIG_DEVFILTER_H

#include <stdint.h>
#include <stddef.h>

/* Device types (matches BPF_DEVCG_DEV_*) */
#define EK_DEV_BLOCK 1
#define EK_DEV_CHAR  2

/* Access types (bitmask, matches BPF_DEVCG_ACC_*) */
#define EK_DEV_ACC_MKNOD 1
#define EK_DEV_ACC_READ	 2
#define EK_DEV_ACC_WRITE 4
#define EK_DEV_ACC_RWM	 7 /* read + write + mknod */

/* Wildcard: matches any major/minor */
#define EK_DEV_WILDCARD (-1)

/*
 * A single device access rule.
 *
 * Example: allow read/write to /dev/null (char 1:3):
 *   { .type = EK_DEV_CHAR, .major = 1, .minor = 3,
 *     .access = EK_DEV_ACC_RWM }
 *
 * Wildcard major/minor: allow all PTY slaves (char 136:*):
 *   { .type = EK_DEV_CHAR, .major = 136, .minor = EK_DEV_WILDCARD,
 *     .access = EK_DEV_ACC_RWM }
 */
struct ek_dev_rule {
	int32_t type;	 /* EK_DEV_CHAR or EK_DEV_BLOCK (0 = wildcard) */
	int32_t major;	 /* major number (EK_DEV_WILDCARD = any) */
	int32_t minor;	 /* minor number (EK_DEV_WILDCARD = any) */
	uint32_t access; /* bitmask of EK_DEV_ACC_* */
};

/*
 * Attach a device filter to a cgroup directory.
 *
 * Opens cgroup_path as a directory fd, generates a BPF program
 * from the allowlist rules, loads it into the kernel, and attaches
 * it to the cgroup.
 *
 * @param cgroup_path  Absolute path to cgroup directory
 *                     (e.g. "/sys/fs/cgroup/erlkoenig/ct-abc123")
 * @param rules        Array of allowed device rules
 * @param n_rules      Number of rules in the array
 * @return             0 on success, -errno on failure
 */
int ek_devfilter_attach(const char *cgroup_path,
			const struct ek_dev_rule *rules, size_t n_rules);

/*
 * Default OCI-compatible device allowlist.
 *
 * Allows: null, zero, full, random, urandom, tty, ptmx, pts/N
 * Denies: everything else.
 */
extern const struct ek_dev_rule ek_default_dev_rules[];
extern const size_t ek_default_dev_rules_count;

#endif /* ERLKOENIG_DEVFILTER_H */
