/*
 * probe_caps__sys_ptrace_dropped.c
 *
 * Asserts: CAP_SYS_PTRACE dropped from effective/permitted/bounding.
 * Profile: DEFAULT.
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
		PROBE_FINDING("capget() failed: %s", strerror(errno));

	if (data[0].effective & (1U << CAP_SYS_PTRACE))
		PROBE_FINDING("CAP_SYS_PTRACE still in effective");
	if (data[0].permitted & (1U << CAP_SYS_PTRACE))
		PROBE_FINDING("CAP_SYS_PTRACE still in permitted");

	int b = prctl(PR_CAPBSET_READ, CAP_SYS_PTRACE, 0, 0, 0);
	if (b == 1)
		PROBE_FINDING("CAP_SYS_PTRACE still in bounding set");

	PROBE_OK("CAP_SYS_PTRACE dropped");
}
