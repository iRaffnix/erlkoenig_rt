/*
 * hello_output.c - Schreibt auf stdout und stderr.
 *
 * Testet Container-Output-Forwarding:
 *   stdout: 3 Zeilen mit Zaehler
 *   stderr: 1 Warnzeile
 *
 * Build: gcc -static -o ../build/hello_output hello_output.c
 */

#include <stdio.h>
#include <unistd.h>

int main(void)
{
	fprintf(stdout, "stdout: Zeile 1\n");
	fflush(stdout);
	fprintf(stderr, "stderr: Warnung!\n");
	fprintf(stdout, "stdout: Zeile 2\n");
	fflush(stdout);
	fprintf(stdout, "stdout: Zeile 3 (fertig)\n");
	fflush(stdout);
	return 0;
}
