/*
 * probe_fs__no_dev_mem.c
 *
 * Asserts: /dev/mem is not present in the container rootfs. Per
 * SPEC-EK-021 §4 "Minimales Rootfs", only /dev/null and /dev/urandom
 * exist. /dev/mem would expose physical memory.
 *
 * Profile: DEFAULT.
 */

#include <fcntl.h>
#include <sys/stat.h>

#include "probe_common.h"

int main(void)
{
	struct stat st;
	if (stat("/dev/mem", &st) == 0) {
		/* /dev/mem present — but is it bind-mounted to /dev/null? */
		struct stat null_st;
		if (stat("/dev/null", &null_st) == 0 &&
		    st.st_dev == null_st.st_dev &&
		    st.st_ino == null_st.st_ino)
			PROBE_OK("/dev/mem present but bind-mounted to /dev/null");
		PROBE_FINDING("/dev/mem present in container rootfs (dev=%lu "
			      "ino=%lu) — physical memory exposure path",
			      (unsigned long)st.st_dev,
			      (unsigned long)st.st_ino);
	}
	if (errno == ENOENT)
		PROBE_OK("/dev/mem not present");
	PROBE_FINDING("/dev/mem stat failed unexpectedly: %s",
		      strerror(errno));
}
