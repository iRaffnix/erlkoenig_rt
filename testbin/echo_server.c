/*
 * echo_server.c - Minimaler TCP Echo-Server fuer Container-Demos.
 *
 * Lauscht auf Port 7777 (oder argv[1]), akzeptiert eine Verbindung
 * nach der anderen und schickt alles zurueck was reinkommt.
 *
 * Build: gcc -static -o ../build/echo_server echo_server.c
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 7777
#define BUFSIZE      4096

int main(int argc, char **argv)
{
	int port = DEFAULT_PORT;
	int listenfd, connfd, opt;
	struct sockaddr_in addr;
	char buf[BUFSIZE];
	ssize_t n;

	if (argc > 1)
		port = atoi(argv[1]);

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		perror("socket");
		return 1;
	}

	opt = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons((uint16_t)port);

	if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("bind");
		return 1;
	}

	if (listen(listenfd, 1)) {
		perror("listen");
		return 1;
	}

	/* Signalisiere: bereit */
	dprintf(STDERR_FILENO, "echo: listening on port %d\n", port);

	for (;;) {
		connfd = accept(listenfd, NULL, NULL);
		if (connfd < 0)
			continue;

		dprintf(STDERR_FILENO, "echo: client connected\n");

		while ((n = read(connfd, buf, sizeof(buf))) > 0) {
			if (write(connfd, buf, (size_t)n) != n)
				break;
		}

		dprintf(STDERR_FILENO, "echo: client disconnected\n");
		close(connfd);
	}
}
