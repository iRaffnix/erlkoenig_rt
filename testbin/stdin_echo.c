/*
 * stdin_echo.c - Read stdin line-by-line, echo back to stdout.
 *
 * Used for PTY/stdin integration tests. Prefixes each line
 * with "echo: " so the test can verify round-trip delivery.
 * Exits cleanly on EOF.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 4096

int main(void)
{
	char buf[BUFSIZE];
	ssize_t n;

	/* Unbuffered I/O for immediate response */
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("stdin_echo: ready\n");

	while ((n = read(STDIN_FILENO, buf, sizeof(buf) - 1)) > 0) {
		buf[n] = '\0';
		printf("echo: %s", buf);
		/* If input didn't end with newline, add one */
		if (n > 0 && buf[n - 1] != '\n')
			printf("\n");
	}

	printf("stdin_echo: bye\n");
	return 0;
}
