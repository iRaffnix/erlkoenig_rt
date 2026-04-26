/*
 * probe_caps__sys_admin_dropped.c
 *
 * Asserts: CAP_SYS_ADMIN has been dropped from the effective and
 * permitted sets by erlkoenig_drop_caps. capget() must show
 * effective and permitted as zero (or at least: CAP_SYS_ADMIN bit
 * unset). Bounding set must also have CAP_SYS_ADMIN cleared.
 *
 * Expected: exit 0 ("OK"). If CAP_SYS_ADMIN is still in any of
 * effective/permitted/bounding, the probe exits 1 with a finding.
 *
 * Profile: DEFAULT (capget is allowed, prctl is allowed).
 */

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	struct __user_cap_data_struct data[2] = {0};

	if (syscall(SYS_capget, &hdr, data) < 0)
		PROBE_FINDING("capget() failed: %s — cannot verify cap state",
			      strerror(errno));

	if (data[0].effective & (1U << CAP_SYS_ADMIN))
		PROBE_FINDING(
		    "CAP_SYS_ADMIN still in effective set "
		    "(eff=0x%x:%x perm=0x%x:%x)",
		    data[1].effective, data[0].effective, data[1].permitted,
		    data[0].permitted);

	if (data[0].permitted & (1U << CAP_SYS_ADMIN))
		PROBE_FINDING(
		    "CAP_SYS_ADMIN still in permitted set "
		    "(eff=0x%x:%x perm=0x%x:%x)",
		    data[1].effective, data[0].effective, data[1].permitted,
		    data[0].permitted);

	int b = prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0);
	if (b < 0)
		PROBE_FINDING("PR_CAPBSET_READ(CAP_SYS_ADMIN) failed: %s",
			      strerror(errno));
	if (b == 1)
		PROBE_FINDING(
		    "CAP_SYS_ADMIN still in bounding set");

	PROBE_OK("CAP_SYS_ADMIN dropped from effective, permitted, bounding");
}
