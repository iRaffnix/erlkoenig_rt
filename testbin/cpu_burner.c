/*
 * cpu_burner.c - Verbrennt CPU-Zeit fuer cgroup cpu.weight Tests.
 *
 * Rechnet in einer Endlosschleife (SHA-256-aehnliches Bit-Mixing)
 * und gibt alle 500ms den aktuellen Durchsatz aus. Laeuft bis
 * SIGTERM oder der Container gestoppt wird.
 *
 * Optionaler Parameter: Anzahl Threads (default 1).
 *
 * Build: gcc -static -o cpu_burner cpu_burner.c -lpthread
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig)
{
	(void)sig;
	running = 0;
}

/*
 * Bit-mixing loop — keeps the CPU busy with integer arithmetic.
 * Not cryptographically meaningful, just hard to optimize away.
 */
static uint64_t burn(uint64_t iterations)
{
	uint64_t state = 0x6a09e667f3bcc908ULL;

	for (uint64_t i = 0; i < iterations && running; i++) {
		state ^= i;
		state = (state << 13) | (state >> 51);
		state *= 0x9e3779b97f4a7c15ULL;
		state ^= state >> 17;
	}
	return state;
}

int main(int argc, char **argv)
{
	int threads = 1;
	uint64_t batch = 10000000; /* 10M iterations per report */

	if (argc > 1)
		threads = atoi(argv[1]);

	(void)threads; /* TODO: multi-thread support */

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	dprintf(STDOUT_FILENO, "cpu_burner: starting (%d thread)\n", threads);

	uint64_t total = 0;

	while (running) {
		uint64_t sink = burn(batch);
		total += batch;

		dprintf(STDOUT_FILENO,
			"cpu_burner: %llu M iterations (sink=%llx)\n",
			(unsigned long long)(total / 1000000),
			(unsigned long long)sink);
	}

	dprintf(STDOUT_FILENO,
		"cpu_burner: stopped after %llu M iterations\n",
		(unsigned long long)(total / 1000000));
	return 0;
}
