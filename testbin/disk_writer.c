/*
 * disk_writer.c - Schreibt Daten auf die Festplatte (tmpfs).
 *
 * Zum Testen von Disk-Limits. Schreibt alle 500ms einen Block
 * (default 4 MB) nach /tmp/data, bis kein Platz mehr ist.
 *
 * Build: gcc -static -o ../build/disk_writer disk_writer.c
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_BLOCK_MB 4
#define WRITE_PATH       "/tmp/data"

int main(int argc, char **argv)
{
	int block_mb = DEFAULT_BLOCK_MB;
	size_t block_size;
	size_t total = 0;
	int i = 0;
	FILE *f;

	if (argc > 1)
		block_mb = atoi(argv[1]);

	block_size = (size_t)block_mb * 1024 * 1024;

	char *block = malloc(block_size);

	if (!block) {
		dprintf(STDERR_FILENO, "disk_writer: malloc failed\n");
		return 1;
	}
	memset(block, 'D', block_size);

	dprintf(STDERR_FILENO,
		"disk_writer: schreibe %d MB Bloecke nach %s\n",
		block_mb, WRITE_PATH);

	f = fopen(WRITE_PATH, "wb");
	if (!f) {
		dprintf(STDERR_FILENO, "disk_writer: fopen failed: %s\n",
			strerror(errno));
		return 1;
	}

	for (;;) {
		size_t written = fwrite(block, 1, block_size, f);

		if (written < block_size) {
			dprintf(STDERR_FILENO,
				"disk_writer: write failed bei %zu MB "
				"(kein Platz mehr)\n",
				total / (1024 * 1024));
			fclose(f);
			return 1;
		}

		fflush(f);
		total += written;
		i++;

		dprintf(STDERR_FILENO,
			"disk_writer: [%d] %zu MB geschrieben\n",
			i, total / (1024 * 1024));

		usleep(500000);
	}
}
