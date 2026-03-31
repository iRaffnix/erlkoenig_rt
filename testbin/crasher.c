/*
 * crasher.c - Segfaulted nach N Sekunden.
 *
 * Zum Testen des Container-Crash-Handlings.
 * Schreibt jede Sekunde auf stderr, dann SIGSEGV.
 *
 * Build: gcc -static -o ../build/crasher crasher.c
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DEFAULT_SECONDS 5

int main(int argc, char **argv)
{
	int seconds = DEFAULT_SECONDS;
	int i;

	if (argc > 1)
		seconds = atoi(argv[1]);

	dprintf(STDERR_FILENO, "crasher: werde in %d Sekunden segfaulten\n",
		seconds);

	for (i = seconds; i > 0; i--) {
		dprintf(STDERR_FILENO, "crasher: noch %d...\n", i);
		sleep(1);
	}

	dprintf(STDERR_FILENO, "crasher: BOOM!\n");

	/*
	 * In einem PID-Namespace sind wir PID 1. Der Kernel ignoriert
	 * selbst raise(SIGSEGV) mit SIG_DFL fuer init. Ein echter
	 * Null-Pointer-Dereference erzwingt den Crash auf Hardware-Ebene.
	 */
	volatile int *p = NULL;
	*p = 42;

	return 0;
}
