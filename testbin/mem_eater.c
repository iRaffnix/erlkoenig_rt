/*
 * mem_eater.c - Allokiert schrittweise Speicher.
 *
 * Zum Testen von cgroup Memory-Limits. Allokiert alle 500ms
 * einen Block (default 8 MB) und schreibt ihn voll, bis der
 * OOM-Killer zuschlaegt oder das Limit erreicht ist.
 *
 * Build: gcc -static -o ../build/mem_eater mem_eater.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_BLOCK_MB 8

int main(int argc, char **argv)
{
	int block_mb = DEFAULT_BLOCK_MB;
	size_t block_size;
	size_t total = 0;
	int i = 0;

	if (argc > 1)
		block_mb = atoi(argv[1]);

	block_size = (size_t)block_mb * 1024 * 1024;

	dprintf(STDERR_FILENO,
		"mem_eater: allokiere %d MB Bloecke bis OOM\n", block_mb);

	for (;;) {
		char *block = malloc(block_size);

		if (!block) {
			dprintf(STDERR_FILENO,
				"mem_eater: malloc fehlgeschlagen bei %zu MB\n",
				total / (1024 * 1024));
			return 1;
		}

		/* Seiten tatsaechlich anfassen (sonst lazy allocation) */
		memset(block, 'X', block_size);
		total += block_size;
		i++;

		dprintf(STDERR_FILENO,
			"mem_eater: [%d] %zu MB allokiert\n",
			i, total / (1024 * 1024));

		usleep(500000); /* 500ms */
	}
}
