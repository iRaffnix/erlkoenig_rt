/*
 * probe_caps__sys_module_dropped.c
 *
 * Asserts: CAP_SYS_MODULE dropped. Without it, init_module / finit_module
 * fails with EPERM even before seccomp gets to it.
 *
 * Profile: DEFAULT.
 */

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	int b = prctl(PR_CAPBSET_READ, CAP_SYS_MODULE, 0, 0, 0);
	if (b < 0)
		PROBE_FINDING("PR_CAPBSET_READ(CAP_SYS_MODULE) failed: %s",
			      strerror(errno));
	if (b == 1)
		PROBE_FINDING("CAP_SYS_MODULE still in bounding set");

	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	struct __user_cap_data_struct data[2] = {0};

	if (syscall(SYS_capget, &hdr, data) < 0)
		PROBE_FINDING("capget() failed: %s", strerror(errno));

	if (data[0].effective & (1U << CAP_SYS_MODULE))
		PROBE_FINDING("CAP_SYS_MODULE still in effective");

	PROBE_OK("CAP_SYS_MODULE dropped");
}
