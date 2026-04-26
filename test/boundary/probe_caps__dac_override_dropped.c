/*
 * probe_caps__dac_override_dropped.c
 *
 * Asserts: CAP_DAC_OVERRIDE dropped. Without it, root inside the
 * container cannot bypass file-permission checks.
 *
 * Profile: DEFAULT.
 */

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "probe_common.h"

int main(void)
{
	int b = prctl(PR_CAPBSET_READ, CAP_DAC_OVERRIDE, 0, 0, 0);
	if (b == 1)
		PROBE_FINDING("CAP_DAC_OVERRIDE still in bounding set");

	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	    .pid = 0,
	};
	struct __user_cap_data_struct data[2] = {0};

	if (syscall(SYS_capget, &hdr, data) < 0)
		PROBE_FINDING("capget() failed: %s", strerror(errno));

	if (data[0].effective & (1U << CAP_DAC_OVERRIDE))
		PROBE_FINDING("CAP_DAC_OVERRIDE still in effective");
	if (data[0].permitted & (1U << CAP_DAC_OVERRIDE))
		PROBE_FINDING("CAP_DAC_OVERRIDE still in permitted");

	PROBE_OK("CAP_DAC_OVERRIDE dropped");
}
