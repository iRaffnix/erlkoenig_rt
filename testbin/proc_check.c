/*
 * proc_check.c - Prueft ob /proc-Pfade korrekt gemaskt sind.
 *
 * Fuer jeden OCI-Standard masked path:
 *   - Datei: open() + read() -> "MASKED" wenn leer/EACCES, "OPEN" wenn lesbar
 *   - Verzeichnis: opendir() -> "MASKED" wenn leer, "OPEN" wenn Eintraege
 *
 * Ausgabe auf stdout: "MASKED /proc/kcore" oder "OPEN /proc/kcore"
 *
 * Build: gcc -static -o proc_check proc_check.c
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *paths[] = {
	"/proc/acpi",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/sched_debug",
	"/proc/scsi",
	"/proc/sysrq-trigger",
};

#define N_PATHS (sizeof(paths) / sizeof(paths[0]))

static int check_dir(const char *path)
{
	DIR *d = opendir(path);
	if (!d)
		return 1; /* can't open -> masked */

	struct dirent *ent;
	int has_entries = 0;
	while ((ent = readdir(d)) != NULL) {
		if (ent->d_name[0] == '.' &&
		    (ent->d_name[1] == '\0' ||
		     (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
			continue;
		has_entries = 1;
		break;
	}
	closedir(d);
	return !has_entries; /* empty dir -> masked */
}

static int check_file(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1; /* can't open -> masked */

	char buf[1];
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);
	return (n <= 0); /* empty/unreadable -> masked */
}

int main(void)
{
	struct stat st;
	size_t i;

	for (i = 0; i < N_PATHS; i++) {
		if (stat(paths[i], &st)) {
			/* Path doesn't exist on this kernel — skip */
			printf("SKIP %s\n", paths[i]);
			fflush(stdout);
			continue;
		}

		int masked;
		if (S_ISDIR(st.st_mode))
			masked = check_dir(paths[i]);
		else
			masked = check_file(paths[i]);

		printf("%s %s\n", masked ? "MASKED" : "OPEN", paths[i]);
		fflush(stdout);
	}

	printf("DONE\n");
	fflush(stdout);
	return 0;
}
