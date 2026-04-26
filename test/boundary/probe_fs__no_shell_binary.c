/*
 * probe_fs__no_shell_binary.c
 *
 * Asserts: minimal rootfs has no shell. Per SPEC-EK-021 §4: "Kein
 * /bin/sh → kein Shell-Escape". Also covers /bin/bash, /bin/dash,
 * /usr/bin/sh, /usr/bin/bash, /busybox.
 *
 * Profile: DEFAULT.
 */

#include <sys/stat.h>

#include "probe_common.h"

static const char *shells[] = {
    "/bin/sh",     "/bin/bash",     "/bin/dash",     "/bin/zsh",
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/busybox",
    "/bin/busybox", "/usr/bin/busybox",
};

int main(void)
{
	for (size_t i = 0; i < sizeof(shells) / sizeof(shells[0]); i++) {
		struct stat st;
		if (stat(shells[i], &st) == 0)
			PROBE_FINDING("shell binary present: %s "
				      "— shell-escape surface available",
				      shells[i]);
	}
	PROBE_OK("no shell binaries in rootfs");
}
