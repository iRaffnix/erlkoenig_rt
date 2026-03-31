/*
 * sleeper.c - Minimal static binary for container demos.
 *
 * Build: gcc -static -o ../build/sleeper sleeper.c
 */

#include <unistd.h>

int main(void)
{
	sleep(120);
	return 0;
}
