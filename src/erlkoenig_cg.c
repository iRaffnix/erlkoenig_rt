/*
 * Copyright 2026 Erlkoenig Contributors
 *
 * Licensed under the Apache License, Version 2.0
 */

/*
 * erlkoenig_cg.c - cgroup v2 management for containers.
 *
 * Implements the same cgroup pattern as erlkoenig_cgroup.erl
 * (Erlang orchestrator) so both can work with the same cgroup
 * hierarchy. The C runtime creates per-container cgroups under
 * a base path that is auto-detected from systemd delegation
 * or falls back to /sys/fs/cgroup/erlkoenig/.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "erlkoenig_cg.h"
#include "erlkoenig_log.h"

#define CGROUP_ROOT   "/sys/fs/cgroup"
#define FALLBACK_BASE CGROUP_ROOT "/erlkoenig"

/*
 * write_file - Write a string to a file (cgroup knob).
 * Returns 0 on success, -errno on failure.
 */
static int write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	if (fd < 0)
		return -errno;

	size_t len = strlen(value);
	ssize_t n = write(fd, value, len);
	int ret = (n == (ssize_t)len) ? 0 : -errno;

	close(fd);
	return ret;
}

int erlkoenig_cg_detect_base(char *path, size_t len)
{
	/*
	 * Read /proc/self/cgroup to find our cgroup v2 path.
	 * Format: "0::/path\n" (cgroup v2 unified hierarchy)
	 */
	char buf[4096];
	int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		/* No /proc/self/cgroup — use fallback */
		int ret = snprintf(path, len, "%s", FALLBACK_BASE);

		if (ret < 0 || (size_t)ret >= len)
			return -ENAMETOOLONG;
		return 0;
	}

	ssize_t n = read(fd, buf, sizeof(buf) - 1);

	close(fd);

	if (n <= 0) {
		snprintf(path, len, "%s", FALLBACK_BASE);
		return 0;
	}
	buf[n] = '\0';

	/*
	 * Parse cgroup v2 entry: "0::/some/path\n"
	 * We look for the line starting with "0::"
	 */
	char *line = buf;

	while (line && *line) {
		if (line[0] == '0' && line[1] == ':' && line[2] == ':') {
			char *cg_path = line + 3;
			char *newline = strchr(cg_path, '\n');

			if (newline)
				*newline = '\0';

			/* Strip trailing /init or child cgroup names */
			char *last_slash = strrchr(cg_path, '/');

			if (last_slash && last_slash != cg_path) {
				const char *tail = last_slash + 1;

				if (strcmp(tail, "init") == 0 ||
				    strcmp(tail, "beam") == 0)
					*last_slash = '\0';
			}

			if (strcmp(cg_path, "/") == 0) {
				/* Root cgroup — use fallback */
				snprintf(path, len, "%s", FALLBACK_BASE);
			} else {
				/* Delegated cgroup — use directly */
				snprintf(path, len, "%s%s", CGROUP_ROOT,
					 cg_path);
			}
			return 0;
		}
		line = strchr(line, '\n');
		if (line)
			line++;
	}

	/* No v2 entry found — fallback */
	snprintf(path, len, "%s", FALLBACK_BASE);
	return 0;
}

int erlkoenig_cg_setup(pid_t pid, const char *name, uint64_t memory_max,
		       uint32_t pids_max, uint32_t cpu_weight,
		       char *cgroup_path_out, size_t path_len)
{
	char base[4096];
	char knob[4096 + 64];
	char value[64];
	int ret;

	/* Detect base path */
	ret = erlkoenig_cg_detect_base(base, sizeof(base));
	if (ret) {
		LOG_ERR("cgroup: detect base failed: %s", strerror(-ret));
		return ret;
	}

	/* Ensure base directory exists */
	mkdir(base, 0755); /* may already exist */

	/* Enable controllers in base cgroup.
	 * Without this, child cgroups can't use pids.max/memory.max.
	 * Harmless if already enabled or not supported. */
	snprintf(knob, sizeof(knob), "%s/cgroup.subtree_control", base);
	write_file(knob, "+pids +memory +cpu");

	/* Build container cgroup path: <base>/ct-<name> */
	ret = snprintf(cgroup_path_out, path_len, "%s/ct-%s", base, name);
	if (ret < 0 || (size_t)ret >= path_len)
		return -ENAMETOOLONG;

	/* Create container cgroup directory */
	if (mkdir(cgroup_path_out, 0755) && errno != EEXIST) {
		ret = -errno;
		LOG_ERR("cgroup: mkdir %s: %s", cgroup_path_out,
			strerror(errno));
		return ret;
	}

	/*
	 * Set memory and pids limits. These are SECURITY boundaries — if the
	 * caller requested a limit and we cannot apply it, the caller gets a
	 * hard error rather than a container without the declared guard-rail
	 * (OOM / fork-bomb risk on the host). cpu.weight is QoS-only, so a
	 * weight-set failure stays a warning.
	 */
	if (memory_max > 0) {
		snprintf(knob, sizeof(knob), "%s/memory.max", cgroup_path_out);
		snprintf(value, sizeof(value), "%llu",
			 (unsigned long long)memory_max);
		ret = write_file(knob, value);
		if (ret) {
			LOG_ERR("cgroup: set memory.max=%s: %s", value,
				strerror(-ret));
			rmdir(cgroup_path_out);
			cgroup_path_out[0] = '\0';
			return ret;
		}
		LOG_INFO("cgroup: memory.max = %llu bytes",
			 (unsigned long long)memory_max);
	}

	if (pids_max > 0) {
		snprintf(knob, sizeof(knob), "%s/pids.max", cgroup_path_out);
		snprintf(value, sizeof(value), "%u", pids_max);
		ret = write_file(knob, value);
		if (ret) {
			LOG_ERR("cgroup: set pids.max=%s: %s", value,
				strerror(-ret));
			rmdir(cgroup_path_out);
			cgroup_path_out[0] = '\0';
			return ret;
		}
		LOG_INFO("cgroup: pids.max = %u", pids_max);
	}

	if (cpu_weight > 0) {
		snprintf(knob, sizeof(knob), "%s/cpu.weight", cgroup_path_out);
		snprintf(value, sizeof(value), "%u", cpu_weight);
		ret = write_file(knob, value);
		if (ret)
			LOG_WARN("cgroup: set cpu.weight=%s: %s", value,
				 strerror(-ret));
		else
			LOG_INFO("cgroup: cpu.weight = %u", cpu_weight);
	}

	/* Move container PID into cgroup */
	snprintf(knob, sizeof(knob), "%s/cgroup.procs", cgroup_path_out);
	snprintf(value, sizeof(value), "%d", (int)pid);
	ret = write_file(knob, value);
	if (ret) {
		LOG_ERR("cgroup: attach pid %d to %s: %s", (int)pid,
			cgroup_path_out, strerror(-ret));
		/* Cleanup on failure */
		rmdir(cgroup_path_out);
		cgroup_path_out[0] = '\0';
		return ret;
	}

	LOG_INFO("cgroup: container attached to %s", cgroup_path_out);
	return 0;
}

void erlkoenig_cg_teardown(const char *cgroup_path)
{
	char knob[4096 + 64];

	if (!cgroup_path || cgroup_path[0] == '\0')
		return;

	/*
	 * Kill all processes in the cgroup. If the write fails we log it
	 * loudly: this is the mechanism that guarantees container shutdown
	 * on teardown. A silent failure would leave container processes
	 * running on the host while the orchestrator thinks the container
	 * is gone (resource leak + possibly a stale attacker foothold).
	 */
	snprintf(knob, sizeof(knob), "%s/cgroup.kill", cgroup_path);
	{
		int kret = write_file(knob, "1");
		if (kret)
			LOG_ERR("cgroup: kill %s: %s — container processes "
				"may still be running",
				cgroup_path, strerror(-kret));
	}

	/* Brief wait for processes to die (signal-safe) */
	{
		struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000000};
		struct timespec rem;

		while (nanosleep(&ts, &rem) && errno == EINTR)
			ts = rem;
	}

	/* Remove the cgroup directory */
	if (rmdir(cgroup_path))
		LOG_WARN("cgroup: rmdir %s: %s", cgroup_path, strerror(errno));
	else
		LOG_INFO("cgroup: teardown %s", cgroup_path);
}
