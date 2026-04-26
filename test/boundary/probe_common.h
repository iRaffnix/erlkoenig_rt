/*
 * probe_common.h - Shared helpers for boundary probes.
 *
 * Each probe is a tiny statically-linked container workload that
 * asserts a single boundary property. Probes do NOT escape; they
 * verify that a forbidden operation is denied with the expected
 * errno/signal.
 *
 * Conventions:
 *   - PROBE_OK:       the boundary held; exit 0
 *   - PROBE_FINDING:  the boundary leaked; print finding text on
 *                     stderr and exit 1
 *   - PROBE_SKIP:     the test cannot run on this kernel/profile;
 *                     print on stderr and exit 77 (autotools convention)
 *
 * For seccomp-kill probes: the probe attempts the denied syscall.
 * If the process survives, that itself is the finding (the harness
 * detects "did not die from SIGSYS" via WTERMSIG inspection).
 */

#ifndef BOUNDARY_PROBE_COMMON_H
#define BOUNDARY_PROBE_COMMON_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROBE_OK_EXIT      0
#define PROBE_FINDING_EXIT 1
#define PROBE_SKIP_EXIT    77

#define PROBE_FINDING(fmt, ...)                                                \
	do {                                                                   \
		dprintf(STDERR_FILENO, "FINDING: " fmt "\n", ##__VA_ARGS__);   \
		_exit(PROBE_FINDING_EXIT);                                     \
	} while (0)

#define PROBE_OK(fmt, ...)                                                     \
	do {                                                                   \
		dprintf(STDERR_FILENO, "OK: " fmt "\n", ##__VA_ARGS__);        \
		_exit(PROBE_OK_EXIT);                                          \
	} while (0)

#define PROBE_SKIP(fmt, ...)                                                   \
	do {                                                                   \
		dprintf(STDERR_FILENO, "SKIP: " fmt "\n", ##__VA_ARGS__);      \
		_exit(PROBE_SKIP_EXIT);                                        \
	} while (0)

#endif
