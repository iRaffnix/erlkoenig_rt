/*
 * probe_caps__bounding_set_empty.c
 *
 * Asserts: under the strict default (caps_keep == 0), the entire
 * bounding set is empty. Iterates 0..63, fails on first cap that
 * remains.
 *
 * Profile: DEFAULT.
 */

#include <sys/prctl.h>

#include "probe_common.h"

int main(void)
{
	for (int cap = 0; cap < 64; cap++) {
		int b = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
		if (b < 0)
			continue; /* cap not defined on this kernel */
		if (b == 1)
			PROBE_FINDING("cap %d still in bounding set under "
				      "caps_keep=0",
				      cap);
	}
	PROBE_OK("bounding set empty");
}
