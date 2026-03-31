/*
 * stdout_flood.c - Schreibt N Megabytes auf stdout.
 *
 * Fuer Durchsatz-Benchmarks der stdout-Pipe. Schreibt in 64KB
 * Bloecken so schnell wie moeglich und beendet sich dann.
 *
 * Usage: stdout_flood [MB]  (default: 10)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int mb = 10;
	char buf[65536];

	if (argc > 1)
		mb = atoi(argv[1]);

	memset(buf, 'A', sizeof(buf));

	size_t total = (size_t)mb * 1024 * 1024;
	size_t written = 0;

	while (written < total) {
		size_t chunk = sizeof(buf);

		if (total - written < chunk)
			chunk = total - written;

		ssize_t n = write(STDOUT_FILENO, buf, chunk);

		if (n <= 0)
			break;
		written += (size_t)n;
	}

	dprintf(STDERR_FILENO, "stdout_flood: wrote %zu bytes\n", written);
	return 0;
}
