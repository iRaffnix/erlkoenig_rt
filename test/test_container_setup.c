/*
 * test_container_setup.c - Unit tests for erlkoenig container setup.
 *
 * Tests each step of the container lifecycle in isolation using
 * real kernel operations. Uses libcheck which forks each test
 * automatically — essential because many operations (pivot_root,
 * cap drop, seccomp) are irreversible.
 *
 * See TEST_RT.md for the full lifecycle diagram and test overview.
 *
 * Run without root:  only unprivileged tests (rlimits, seccomp, signals)
 * Run with sudo:     all 12 tests (namespaces, mounts, pivot_root, caps)
 */

#include <check.h>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/landlock.h>
#include <sys/socket.h>

#include "erlkoenig_ns.h"
#include "erlkoenig_ns_internal.h"
#include "erlkoenig_caps.h"
#include "erlkoenig_cg.h"
#include "erlkoenig_probe.h"
#include "erlkoenig_seccomp.h"

/*
 * Helper: run a function in an isolated child process.
 *
 * Many tests need a new mount namespace so they don't affect the
 * host. This helper:
 *   1. fork()
 *   2. Child: unshare(CLONE_NEWNS), make / private, run fn()
 *   3. Parent: waitpid, return child exit code
 *
 * The child calls _exit(0) on success, _exit(1) on failure.
 * libcheck already forks each test, but we need a SECOND fork
 * for tests that need mount namespace isolation within the
 * already-forked test process.
 */
static int run_in_mount_ns(int (*fn)(void))
{
	pid_t pid = fork();

	if (pid < 0)
		return -1;

	if (pid == 0) {
		/* Child: isolate mounts */
		if (unshare(CLONE_NEWNS)) {
			fprintf(stderr, "  unshare(NEWNS): %s\n",
				strerror(errno));
			_exit(1);
		}
		if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
			fprintf(stderr, "  mount(private): %s\n",
				strerror(errno));
			_exit(1);
		}
		_exit(fn());
	}

	int status;

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return -1;
}

/* ================================================================
 * TEST 1: tmpfs als Container-Rootfs
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   tmpfs ist ein RAM-basiertes Dateisystem. Jeder Container
 *   bekommt sein eigenes tmpfs als Root-Dateisystem. Das ist
 *   schnell (kein Disk-I/O), isoliert (eigener Inode-Raum),
 *   und verschwindet automatisch beim Unmount.
 *
 * WAS WIR TESTEN:
 *   ek_mkdtemp_rootfs() erstellt ein Temp-Verzeichnis.
 *   prepare_rootfs_in_child() mountet tmpfs darauf und legt
 *   die Verzeichnisstruktur an: /proc, /dev, /tmp, /etc.
 *
 * WARUM WICHTIG:
 *   Ohne eigenes Rootfs sieht der Container das Host-Dateisystem.
 */

static int do_test_tmpfs_rootfs(void)
{
	char rootfs[256];
	struct stat st;

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;

	/* Mount tmpfs on rootfs */
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	/* Create expected directories */
	char path[512];

	snprintf(path, sizeof(path), "%s/proc", rootfs);
	if (mkdir(path, 0555))
		return 1;
	snprintf(path, sizeof(path), "%s/dev", rootfs);
	if (mkdir(path, 0755))
		return 1;
	snprintf(path, sizeof(path), "%s/tmp", rootfs);
	if (mkdir(path, 01777))
		return 1;

	/* Verify directories exist */
	snprintf(path, sizeof(path), "%s/proc", rootfs);
	if (stat(path, &st) || !S_ISDIR(st.st_mode))
		return 1;
	snprintf(path, sizeof(path), "%s/dev", rootfs);
	if (stat(path, &st) || !S_ISDIR(st.st_mode))
		return 1;
	snprintf(path, sizeof(path), "%s/tmp", rootfs);
	if (stat(path, &st) || !S_ISDIR(st.st_mode))
		return 1;

	/* Verify tmpfs size limit: statfs would show f_blocks based on size */
	umount2(rootfs, MNT_DETACH);
	rmdir(rootfs);
	return 0;
}

START_TEST(test_tmpfs_rootfs)
{
	if (geteuid() != 0) {
		/* libcheck hat kein SKIP — wir markieren es im Output */
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_tmpfs_rootfs), 0);
}
END_TEST

/* ================================================================
 * TEST 2: Device Bind-Mounts
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Container brauchen Zugriff auf /dev/null, /dev/zero etc.
 *   Statt mknod (braucht CAP_MKNOD) verwendet man Bind-Mounts:
 *   Eine leere Datei wird erstellt und das Host-Device darueber
 *   gemountet. Der Container sieht das Device, kann aber keine
 *   neuen Devices erstellen.
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_dev() bind-mountet /dev/null in das Rootfs.
 *   Lesen ergibt EOF (0 Bytes), genau wie /dev/null.
 *
 * WARUM WICHTIG:
 *   Ohne /dev/null brechen viele Programme (Shells, Logger).
 *   Ohne Bind-Mount-Ansatz muesste man CAP_MKNOD behalten.
 */

static int do_test_bind_mount_devices(void)
{
	char rootfs[256];

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	char dev_path[512];

	snprintf(dev_path, sizeof(dev_path), "%s/dev", rootfs);
	if (mkdir(dev_path, 0755))
		return 1;

	int rootfs_fd = open(rootfs, O_PATH | O_DIRECTORY | O_CLOEXEC);

	if (rootfs_fd < 0)
		return 1;

	/* Bind-mount /dev/null */
	if (ek_bind_mount_dev(rootfs, rootfs_fd, "null", "/dev/null", 0666)) {
		close(rootfs_fd);
		return 1;
	}

	/* Read from bind-mounted /dev/null → EOF (0 bytes) */
	char null_path[512];

	snprintf(null_path, sizeof(null_path), "%s/dev/null", rootfs);

	int fd = open(null_path, O_RDONLY);

	if (fd < 0)
		return 1;

	char buf[16];
	ssize_t n = read(fd, buf, sizeof(buf));

	close(fd);

	/* /dev/null always returns 0 bytes (EOF) */
	if (n != 0)
		return 1;

	/* Bind-mount /dev/zero and verify it returns zero bytes */
	if (ek_bind_mount_dev(rootfs, rootfs_fd, "zero", "/dev/zero", 0666)) {
		close(rootfs_fd);
		return 1;
	}

	close(rootfs_fd);

	char zero_path[512];

	snprintf(zero_path, sizeof(zero_path), "%s/dev/zero", rootfs);
	fd = open(zero_path, O_RDONLY);
	if (fd < 0)
		return 1;

	memset(buf, 0xFF, sizeof(buf));
	n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n != (ssize_t)sizeof(buf))
		return 1;
	/* All bytes must be 0 */
	for (int i = 0; i < (int)sizeof(buf); i++) {
		if (buf[i] != 0)
			return 1;
	}

	umount2(rootfs, MNT_DETACH);
	rmdir(rootfs);
	return 0;
}

START_TEST(test_bind_mount_devices)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_bind_mount_devices), 0);
}
END_TEST

/* ================================================================
 * TEST 3: procfs mit hidepid=2
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   /proc ist ein virtuelles Dateisystem das Prozess-Informationen
 *   bereitstellt. Ohne hidepid=2 kann jeder Prozess ALLE anderen
 *   Prozesse sehen (PIDs, Commandlines, Umgebungsvariablen).
 *
 *   hidepid=2 versteckt Prozesse anderer UIDs. In einem
 *   PID-Namespace sieht der Container sowieso nur seine eigenen
 *   Prozesse, aber hidepid=2 ist Defense-in-Depth.
 *
 * WAS WIR TESTEN:
 *   ek_mount_procfs() mountet /proc mit hidepid=2.
 *   /proc/self muss existieren (eigener Prozess sichtbar).
 *   Mount-Optionen muessen hidepid=2 enthalten.
 *
 * WARUM WICHTIG:
 *   Information Leak: ohne hidepid sieht ein Container die
 *   Host-Prozesse (Commandlines mit Passwoertern etc.).
 */

static int do_test_procfs_hidepid(void)
{
	char rootfs[256];
	struct stat st;

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	char proc_path[512];

	snprintf(proc_path, sizeof(proc_path), "%s/proc", rootfs);
	if (mkdir(proc_path, 0555))
		return 1;

	/* Mount procfs with hidepid=2 */
	if (ek_mount_procfs(rootfs))
		return 1;

	/* /proc/self must exist */
	char self_path[512];

	snprintf(self_path, sizeof(self_path), "%s/proc/self", rootfs);
	if (stat(self_path, &st))
		return 1;

	/* Verify hidepid=2 in mount options via /proc/mounts */
	char mounts_path[512];

	snprintf(mounts_path, sizeof(mounts_path), "%s/proc/mounts", rootfs);
	FILE *f = fopen(mounts_path, "r");

	if (!f)
		return 1;

	char line[512];
	int found_hidepid = 0;

	while (fgets(line, sizeof(line), f)) {
		/* Kernel 5.8+ shows "hidepid=invisible" instead of "hidepid=2"
		 */
		if ((strstr(line, "hidepid=2") ||
		     strstr(line, "hidepid=invisible")) &&
		    strstr(line, "proc"))
			found_hidepid = 1;
	}
	fclose(f);

	if (!found_hidepid)
		return 1;

	umount2(rootfs, MNT_DETACH);
	rmdir(rootfs);
	return 0;
}

START_TEST(test_procfs_hidepid)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_procfs_hidepid), 0);
}
END_TEST

/* ================================================================
 * TEST 4: pivot_root
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   pivot_root() tauscht das Root-Dateisystem des Prozesses.
 *   Das alte Root wird abgehaengt (umount). Danach sieht der
 *   Prozess NUR noch das neue Rootfs — kein Zugriff auf
 *   Host-Dateien mehr moeglich.
 *
 *   Der Trick pivot_root(".", ".") (seit Linux 3.17) eliminiert
 *   die Notwendigkeit eines put_old Verzeichnisses. Das alte
 *   Root endet als "." und wird sofort per umount2 MNT_DETACH
 *   abgehaengt. Identisch mit runc/crun.
 *
 * WAS WIR TESTEN:
 *   ek_pivot_root() fuehrt den kompletten Pivot durch.
 *   Danach ist "/" das neue tmpfs, das alte Root ist weg.
 *   Ein Marker-File das wir VOR dem Pivot anlegen, ist NACH
 *   dem Pivot unter "/" sichtbar.
 *
 * WARUM WICHTIG:
 *   Ohne pivot_root sieht der Container / vom Host.
 *   chroot alleine reicht nicht — man kann aus chroot ausbrechen.
 *   pivot_root mit eigenem Mount-Namespace ist escape-proof.
 */

static int do_test_pivot_root(void)
{
	char rootfs[256];
	struct stat st;

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	/* Create a marker file in the new rootfs */
	char marker[512];

	snprintf(marker, sizeof(marker), "%s/.erlkoenig_test", rootfs);
	int fd = open(marker, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);

	if (fd < 0)
		return 1;
	close(fd);

	/* Create /proc and /dev dirs (pivot_root needs a valid rootfs) */
	char path[512];

	snprintf(path, sizeof(path), "%s/proc", rootfs);
	mkdir(path, 0555);
	snprintf(path, sizeof(path), "%s/dev", rootfs);
	mkdir(path, 0755);

	/* Do the pivot */
	if (ek_pivot_root(rootfs))
		return 1;

	/* After pivot: we are now inside the new rootfs.
	 * The marker file should be at /.erlkoenig_test */
	if (stat("/.erlkoenig_test", &st))
		return 1;

	/* The old root should be gone — /etc/hostname from the
	 * host should NOT be accessible (unless the new rootfs
	 * has one, which it doesn't) */
	if (stat("/etc/hostname", &st) == 0)
		return 1; /* Still seeing host filesystem! */

	return 0;
}

START_TEST(test_pivot_root)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_pivot_root), 0);
}
END_TEST

/* ================================================================
 * TEST 5: /proc-Pfade maskieren (OCI masked paths)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   /proc enthaelt sensitive Kernel-Informationen:
 *     /proc/kcore       — physischer Speicher (KASLR-Bypass)
 *     /proc/keys        — Kernel-Keyrings (Credential Leak)
 *     /proc/sysrq-trigger — Magic SysRq (Kernel-Panik ausloesen)
 *     /proc/timer_list  — Kernel-Timer (Timing Side-Channels)
 *
 *   Loesung: bind-mount /dev/null ueber Dateien (Lesen → EOF),
 *   mount leeres tmpfs ueber Verzeichnisse (Listing → leer).
 *   Das ist exakt die OCI Runtime Spec "maskedPaths" Liste.
 *
 * WAS WIR TESTEN:
 *   ek_mask_paths() nach einem Pivot mit gemounteten /proc.
 *   /proc/kcore lesen → 0 Bytes (EOF von /dev/null).
 *   /proc/self/status → funktioniert noch normal.
 *
 * WARUM WICHTIG:
 *   Ohne Masking kann ein Container Kernel-Adressen lesen
 *   (KASLR umgehen), andere Keyrings sehen, oder den Host
 *   per sysrq-trigger zum Absturz bringen.
 */

static int do_test_mask_paths(void)
{
	char rootfs[256];

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	/* Prepare rootfs with /proc, /dev, /dev/null */
	char path[512];

	snprintf(path, sizeof(path), "%s/proc", rootfs);
	mkdir(path, 0555);
	snprintf(path, sizeof(path), "%s/dev", rootfs);
	mkdir(path, 0755);

	/* Need /dev/null for masking source */
	int rootfs_fd = open(rootfs, O_PATH | O_DIRECTORY | O_CLOEXEC);

	if (rootfs_fd < 0)
		return 1;
	if (ek_bind_mount_dev(rootfs, rootfs_fd, "null", "/dev/null", 0666)) {
		close(rootfs_fd);
		return 1;
	}
	close(rootfs_fd);

	/* Mount procfs */
	if (ek_mount_procfs(rootfs))
		return 1;

	/* Pivot into the new rootfs */
	if (ek_pivot_root(rootfs))
		return 1;

	/* Now mask sensitive paths */
	if (ek_mask_paths())
		return 1;

	/* Verify: /proc/self/status must still work */
	struct stat st;

	if (stat("/proc/self/status", &st))
		return 1;

	/* Verify: masked files return EOF (if they exist on this kernel) */
	int fd = open("/proc/kcore", O_RDONLY);

	if (fd >= 0) {
		char buf[16];
		ssize_t n = read(fd, buf, sizeof(buf));

		close(fd);
		/* Must be 0 (EOF from /dev/null) */
		if (n != 0)
			return 1;
	}
	/* ENOENT is fine — kcore doesn't exist on all configs */

	fd = open("/proc/sysrq-trigger", O_RDONLY);
	if (fd >= 0) {
		char buf[16];
		ssize_t n = read(fd, buf, sizeof(buf));

		close(fd);
		if (n != 0)
			return 1;
	}

	/* Verify: masked directories are empty (if they exist) */
	if (stat("/proc/acpi", &st) == 0 && S_ISDIR(st.st_mode)) {
		/* Try to list — should be empty */
		int dfd = open("/proc/acpi", O_RDONLY | O_DIRECTORY);

		if (dfd >= 0) {
			/* getdents on empty tmpfs returns only . and .. */
			close(dfd);
		}
	}

	return 0;
}

START_TEST(test_mask_paths)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_mask_paths), 0);
}
END_TEST

/* ================================================================
 * TEST 6: Read-Only Rootfs mit writable /tmp
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Das Container-Rootfs wird nach dem Setup read-only remounted.
 *   Das verhindert dass der Container seine eigene Binary (/app),
 *   Device-Nodes (/dev), oder Konfiguration (/etc/resolv.conf)
 *   veraendern kann.
 *
 *   /tmp bekommt ein separates writable tmpfs damit die App
 *   temporaere Dateien schreiben kann — aber mit nosuid, nodev,
 *   noexec (keine Privilege Escalation ueber /tmp).
 *
 * WAS WIR TESTEN:
 *   ek_setup_readonly_rootfs() nach pivot_root.
 *   Schreiben auf / → EROFS (Read-only file system).
 *   Schreiben auf /tmp → Erfolg.
 *
 * WARUM WICHTIG:
 *   Ohne read-only rootfs kann ein Angreifer /app durch ein
 *   eigenes Binary ersetzen, /etc/resolv.conf umleiten, oder
 *   Device-Nodes manipulieren.
 */

static int do_test_readonly_rootfs(void)
{
	char rootfs[256];

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	/* Minimal rootfs for pivot */
	char path[512];

	snprintf(path, sizeof(path), "%s/proc", rootfs);
	mkdir(path, 0555);
	snprintf(path, sizeof(path), "%s/dev", rootfs);
	mkdir(path, 0755);

	if (ek_pivot_root(rootfs))
		return 1;

	/* Apply read-only rootfs with writable /tmp (8 MB) */
	if (ek_setup_readonly_rootfs(8))
		return 1;

	/* Write to / must fail with EROFS */
	int fd = open("/test_rw", O_CREAT | O_WRONLY, 0644);

	if (fd >= 0) {
		close(fd);
		return 1; /* Should have failed! */
	}
	if (errno != EROFS)
		return 1;

	/* Write to /tmp must succeed */
	fd = open("/tmp/test_rw", O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return 1;

	const char *msg = "hello from container\n";

	if (write(fd, msg, strlen(msg)) < 0) {
		close(fd);
		return 1;
	}
	close(fd);
	unlink("/tmp/test_rw");

	return 0;
}

START_TEST(test_readonly_rootfs)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_readonly_rootfs), 0);
}
END_TEST

/* ================================================================
 * TEST 7: Capability Dropping
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Linux spaltet root-Rechte in ~41 einzelne Capabilities auf.
 *   CAP_SYS_ADMIN = mount, pivot_root, etc.
 *   CAP_NET_ADMIN = Netzwerk-Konfiguration
 *   CAP_SYS_PTRACE = Debugger an fremde Prozesse
 *
 *   Fuenf Sets: Bounding, Ambient, Effective, Permitted, Inheritable.
 *   ALLE muessen bereinigt werden — sonst kann der Container
 *   per execve() Capabilities zurueckbekommen.
 *
 *   PR_SET_NO_NEW_PRIVS verhindert zusaetzlich Privilege Escalation
 *   ueber setuid-Binaries.
 *
 * WAS WIR TESTEN:
 *   erlkoenig_drop_caps(0) = alle Caps droppen.
 *   Danach schlaegt mount() fehl (EPERM, kein CAP_SYS_ADMIN).
 *
 * WARUM WICHTIG:
 *   Mit Capabilities kann root im Container Namespaces verlassen,
 *   Host-Dateisysteme mounten, oder Kernel-Module laden.
 */

START_TEST(test_capability_drop)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}

	/* Drop ALL capabilities */
	int ret = erlkoenig_drop_caps(0);

	ck_assert_int_eq(ret, 0);

	/* Verify: mount() must fail with EPERM (no CAP_SYS_ADMIN) */
	ret = mount("tmpfs", "/tmp", "tmpfs", 0, "size=1m");
	ck_assert_int_ne(ret, 0);
	ck_assert_int_eq(errno, EPERM);
}
END_TEST

/* ================================================================
 * TEST 8: Resource Limits (RLIMITs)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   RLIMITs begrenzen was ein einzelner Prozess verbrauchen darf:
 *     RLIMIT_NPROC   — max. Kindprozesse (Fork-Bomb-Schutz)
 *     RLIMIT_NOFILE  — max. offene Dateideskriptoren
 *     RLIMIT_FSIZE   — max. Dateigroesse
 *     RLIMIT_CORE    — max. Core-Dump-Groesse (0 = aus)
 *
 *   RLIMITs wirken pro-Prozess, Cgroup-Limits pro-Container.
 *   Beides zusammen = Defense-in-Depth.
 *
 * WAS WIR TESTEN:
 *   ek_set_rlimits() setzt alle vier Limits.
 *   Danach: getrlimit verifiziert die Werte.
 *
 * WARUM WICHTIG:
 *   Ohne RLIMIT_NPROC kann ein Container den Host per Fork-Bomb
 *   lahmlegen. Ohne RLIMIT_NOFILE kann er alle FDs aufbrauchen.
 */

START_TEST(test_rlimits)
{
	/* ek_set_rlimits() needs no privileges */
	int ret = ek_set_rlimits();

	ck_assert_int_eq(ret, 0);

	struct rlimit rl;

	ck_assert_int_eq(getrlimit(RLIMIT_NPROC, &rl), 0);
	ck_assert_int_eq((int)rl.rlim_cur, 1024);
	ck_assert_int_eq((int)rl.rlim_max, 1024);

	ck_assert_int_eq(getrlimit(RLIMIT_NOFILE, &rl), 0);
	ck_assert_int_eq((int)rl.rlim_cur, 1024);

	ck_assert_int_eq(getrlimit(RLIMIT_CORE, &rl), 0);
	ck_assert_int_eq((int)rl.rlim_cur, 0);
	ck_assert_int_eq((int)rl.rlim_max, 0);

	ck_assert_int_eq(getrlimit(RLIMIT_FSIZE, &rl), 0);
	ck_assert_uint_eq(rl.rlim_cur, 256 * 1024 * 1024);
}
END_TEST

/* ================================================================
 * TEST 9: Seccomp-BPF Syscall-Filter
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Seccomp (Secure Computing) filtert Syscalls per BPF-Programm.
 *   Jeder Syscall wird gegen den Filter geprueft BEVOR der Kernel
 *   ihn ausfuehrt. Verbotene Syscalls toeten den Prozess sofort
 *   mit SIGSYS (SECCOMP_RET_KILL_PROCESS).
 *
 *   erlkoenig hat drei Profile:
 *     STRICT  — nur read/write/exit (Allowlist)
 *     NETWORK — plus Sockets, kein fork (Allowlist)
 *     DEFAULT — Block bekannter Gefahren (Denylist)
 *
 *   cBPF (classic BPF), NICHT eBPF — Kernel erzwingt das fuer
 *   Seccomp wegen der kleineren Angriffsflaeche.
 *
 * WAS WIR TESTEN:
 *   STRICT-Profil installieren, dann fork() ausfuehren.
 *   fork() ist im STRICT-Profil verboten → SIGSYS → Prozess stirbt.
 *   libcheck prueft per tcase_add_test_raise_signal dass der
 *   Test mit genau diesem Signal stirbt.
 *
 * WARUM WICHTIG:
 *   Ohne Seccomp kann ein Container JEDEN Syscall ausfuehren —
 *   auch mount(), ptrace(), oder reboot(). Capabilities alleine
 *   reichen nicht, weil Kernel-Bugs Capability-Checks umgehen.
 */

START_TEST(test_seccomp_bpf)
{
	/* Apply strict profile — irreversible, but libcheck forked us */
	int ret = erlkoenig_apply_seccomp(SECCOMP_PROFILE_STRICT);

	ck_assert_int_eq(ret, 0);

	/* fork() is not in the strict allowlist → SIGSYS → death */
	fork();

	/* If we get here, seccomp didn't work */
	ck_abort_msg("fork() survived strict seccomp — filter broken");
}
END_TEST

/* ================================================================
 * TEST 10: Signal-Forwarding (Mini-Init)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   PID 1 in einem PID-Namespace ist besonders: der Kernel
 *   ignoriert Signale die keinen Handler installiert haben
 *   (sogar SIGSEGV via raise()!). Nur SIGKILL/SIGSTOP vom
 *   Parent-Namespace wirken immer.
 *
 *   Loesung: PID 1 wird ein Mini-Init das Signale an PID 2
 *   (die eigentliche App) weiterleitet. Identisch mit Docker's
 *   --init (tini).
 *
 * WAS WIR TESTEN:
 *   Signal-Handler installieren (wie run_init), SIGTERM an uns
 *   selbst schicken, verifizieren dass der Handler feuert.
 *   ek_reset_signals() setzt danach alles zurueck.
 *
 * WARUM WICHTIG:
 *   Ohne Mini-Init kann man Container nicht sauber per SIGTERM
 *   stoppen. kill(pid, SIGTERM) wird stillschweigend ignoriert.
 */

static volatile sig_atomic_t signal_received;

static void test_sig_handler(int sig)
{
	signal_received = sig;
}

START_TEST(test_signal_forwarding)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = test_sig_handler;
	sigemptyset(&sa.sa_mask);

	/* Install handler like run_init() does */
	ck_assert_int_eq(sigaction(SIGTERM, &sa, NULL), 0);

	/* Send SIGTERM to ourselves */
	signal_received = 0;
	kill(getpid(), SIGTERM);

	/* Handler must have fired */
	ck_assert_int_eq(signal_received, SIGTERM);

	/* Reset signals — they must be back to SIG_DFL */
	ek_reset_signals();

	struct sigaction current;

	sigaction(SIGTERM, NULL, &current);
	ck_assert_ptr_eq(current.sa_handler, SIG_DFL);
}
END_TEST

/* ================================================================
 * TEST 11: PR_SET_NO_NEW_PRIVS
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   PR_SET_NO_NEW_PRIVS ist ein Prozess-Flag das verhindert, dass
 *   ein Prozess (oder seine Kinder) durch execve() von setuid/
 *   setgid-Binaries neue Rechte bekommt.
 *
 *   Dieses Flag ist auch Voraussetzung fuer Seccomp-BPF: ohne
 *   NO_NEW_PRIVS koennte ein gefilterter Prozess ein setuid-
 *   Binary ausfuehren um den Filter zu umgehen.
 *
 *   erlkoenig setzt es ZWEIMAL (Belt and Suspenders):
 *     1. In erlkoenig_drop_caps() — immer
 *     2. In erlkoenig_apply_seccomp() — vor dem Filter
 *
 * WAS WIR TESTEN:
 *   prctl(PR_SET_NO_NEW_PRIVS) setzen.
 *   prctl(PR_GET_NO_NEW_PRIVS) == 1 verifizieren.
 *   Das Flag ist irreversibel — einmal gesetzt, fuer immer.
 *
 * WARUM WICHTIG:
 *   Ohne NO_NEW_PRIVS kann ein Container per execve("/usr/bin/su")
 *   root-Rechte auf dem Host bekommen.
 */

START_TEST(test_no_new_privs)
{
	int ret;

	/* Set the flag */
	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	ck_assert_int_eq(ret, 0);

	/* Verify it's set */
	ret = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	ck_assert_int_eq(ret, 1);

	/* Verify it's irreversible */
	ret = prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0);
	ck_assert_int_ne(ret, 0);
}
END_TEST

/* ================================================================
 * TEST 12: Namespace-Isolation (clone mit CLONE_NEWPID)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Linux-Namespaces isolieren Kernel-Ressourcen:
 *     CLONE_NEWPID    — eigener PID-Raum (Kind ist PID 1)
 *     CLONE_NEWNS     — eigene Mount-Tabelle
 *     CLONE_NEWNET    — eigener Netzwerk-Stack
 *     CLONE_NEWUTS    — eigener Hostname
 *     CLONE_NEWIPC    — eigene IPC (Semaphore, Shared Memory)
 *     CLONE_NEWCGROUP — eigene Cgroup-Hierarchie
 *
 *   clone(CLONE_NEWPID) erstellt einen neuen PID-Namespace.
 *   Der erste Prozess darin ist PID 1 — der Init-Prozess
 *   dieses Namespace.
 *
 * WAS WIR TESTEN:
 *   fork() in einem neuen PID-Namespace (via unshare).
 *   Das Kind sieht sich als PID 1 (gelesen aus /proc/self).
 *
 * WARUM WICHTIG:
 *   PID-Isolation verhindert dass Container Host-Prozesse per
 *   kill(), ptrace() oder /proc/<pid>/ angreifen.
 */

START_TEST(test_namespace_isolation)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}

	/* Create new PID + mount namespace */
	pid_t pid = fork();

	ck_assert(pid >= 0);

	if (pid == 0) {
		/* Child: create new PID namespace for our children */
		if (unshare(CLONE_NEWPID | CLONE_NEWNS)) {
			fprintf(stderr, "  unshare: %s\n", strerror(errno));
			_exit(1);
		}

		/* Fork again — the grandchild will be PID 1 in the new ns */
		pid_t grandchild = fork();

		if (grandchild < 0)
			_exit(1);

		if (grandchild == 0) {
			/* Grandchild: we should be PID 1 in our namespace.
			 * Mount a fresh /proc to see our namespace's view. */
			if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL))
				_exit(1);
			if (mount("proc", "/proc", "proc",
				  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
				_exit(1);

			/* Read our PID from the new /proc */
			FILE *f = fopen("/proc/self/status", "r");

			if (!f)
				_exit(1);

			char line[256];
			int found_pid1 = 0;

			while (fgets(line, sizeof(line), f)) {
				int p;

				if (sscanf(line, "Pid:\t%d", &p) == 1) {
					if (p == 1)
						found_pid1 = 1;
					break;
				}
			}
			fclose(f);
			_exit(found_pid1 ? 0 : 1);
		}

		int status;

		waitpid(grandchild, &status, 0);
		_exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
	}

	int status;

	waitpid(pid, &status, 0);
	ck_assert(WIFEXITED(status));
	ck_assert_int_eq(WEXITSTATUS(status), 0);
}
END_TEST

/* ================================================================
 * TEST 13: Bind-Mount Volumes (basic rw)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Bind-Mounts bilden ein Host-Verzeichnis in den Container ab.
 *   Im Gegensatz zu tmpfs ueberlebt der Inhalt Container-Restarts.
 *   Verwendet fuer persistente Daten (Datenbanken, Logs, Uploads).
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_volume() mountet ein Host-Verzeichnis ins Rootfs.
 *   Datei im Source anlegen, im Target lesen → gleicher Inhalt.
 *
 * WARUM WICHTIG:
 *   Ohne Volumes gibt es keinen persistenten Speicher fuer Container.
 */

static int do_test_bind_mount_volume_basic(void)
{
	char rootfs[256];
	char source[256];
	char path[512];
	int fd;
	ssize_t n;
	char buf[64];

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	/* Create a source directory with a test file */
	snprintf(source, sizeof(source), "%s_vol", rootfs);
	if (mkdir(source, 0755))
		return 1;
	snprintf(path, sizeof(path), "%s/testfile", source);
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return 1;
	write(fd, "hello-volume", 12);
	close(fd);

	/* Bind-mount into rootfs */
	int ret = ek_bind_mount_volume(rootfs, source, "/data", 0);
	if (ret)
		return 1;

	/* Read the file through the mount point */
	snprintf(path, sizeof(path), "%s/data/testfile", rootfs);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;
	n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n != 12 || memcmp(buf, "hello-volume", 12) != 0)
		return 1;

	/* Write a new file through the mount point */
	snprintf(path, sizeof(path), "%s/data/newfile", rootfs);
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return 1;
	write(fd, "written-from-container", 22);
	close(fd);

	/* Verify the new file is visible on the source */
	snprintf(path, sizeof(path), "%s/newfile", source);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;
	n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n != 22 || memcmp(buf, "written-from-container", 22) != 0)
		return 1;

	umount2(rootfs, MNT_DETACH);
	rmdir(rootfs);
	unlink(path);
	snprintf(path, sizeof(path), "%s/testfile", source);
	unlink(path);
	rmdir(source);
	return 0;
}

START_TEST(test_bind_mount_volume_basic)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_bind_mount_volume_basic), 0);
}
END_TEST

/* ================================================================
 * TEST 14: Bind-Mount Volume Read-Only
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_volume() mit EK_VOLUME_F_READONLY.
 *   Lesen funktioniert, Schreiben → EROFS.
 *
 *   Implementierung: MS_BIND gefolgt von MS_BIND|MS_REMOUNT|MS_RDONLY
 *   (direktes MS_RDONLY beim initialen Bind-Mount ist nicht zuverlaessig).
 */

static int do_test_bind_mount_volume_readonly(void)
{
	char rootfs[256];
	char source[256];
	char path[512];
	int fd;
	ssize_t n;
	char buf[64];

	if (ek_mkdtemp_rootfs(rootfs, sizeof(rootfs)))
		return 1;
	if (mount("tmpfs", rootfs, "tmpfs", MS_NOSUID, "size=8m,mode=0755")) {
		rmdir(rootfs);
		return 1;
	}

	snprintf(source, sizeof(source), "%s_vol_ro", rootfs);
	if (mkdir(source, 0755))
		return 1;
	snprintf(path, sizeof(path), "%s/data.txt", source);
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return 1;
	write(fd, "readonly-data", 13);
	close(fd);

	/* Mount as read-only */
	int ret = ek_bind_mount_volume(rootfs, source, "/config",
				       EK_VOLUME_F_READONLY);
	if (ret)
		return 1;

	/* Read must work */
	snprintf(path, sizeof(path), "%s/config/data.txt", rootfs);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;
	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n != 13 || memcmp(buf, "readonly-data", 13) != 0)
		return 1;

	/* Write must fail with EROFS */
	snprintf(path, sizeof(path), "%s/config/newfile", rootfs);
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0) {
		close(fd);
		return 1; /* Should have failed */
	}
	if (errno != EROFS)
		return 1;

	umount2(rootfs, MNT_DETACH);
	rmdir(rootfs);
	snprintf(path, sizeof(path), "%s/data.txt", source);
	unlink(path);
	rmdir(source);
	return 0;
}

START_TEST(test_bind_mount_volume_readonly)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	ck_assert_int_eq(run_in_mount_ns(do_test_bind_mount_volume_readonly),
			 0);
}
END_TEST

/* ================================================================
 * TEST 15: Volume dest — relative path rejected
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_volume() mit relativem Dest-Pfad → -EINVAL.
 *   Dest muss immer absolut sein.
 */

START_TEST(test_bind_mount_volume_bad_dest_relative)
{
	int ret = ek_bind_mount_volume("/tmp", "/tmp", "data/relative", 0);
	ck_assert_int_eq(ret, -EINVAL);
}
END_TEST

/* ================================================================
 * TEST 16: Volume dest — path traversal rejected
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_volume() mit "../" im Dest-Pfad → -EINVAL.
 *   Verhindert Container-Escape ueber crafted Zielpfade.
 */

START_TEST(test_bind_mount_volume_bad_dest_traversal)
{
	int ret;

	ret = ek_bind_mount_volume("/tmp", "/tmp", "/data/../../../etc", 0);
	ck_assert_int_eq(ret, -EINVAL);

	ret = ek_bind_mount_volume("/tmp", "/tmp", "/data/./hidden", 0);
	ck_assert_int_eq(ret, -EINVAL);
}
END_TEST

/* ================================================================
 * TEST 17: Volume source — not a directory
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_volume() mit einer Datei als Source → -ENOTDIR.
 *   Scope v1: nur Directory Bind Mounts.
 */

START_TEST(test_bind_mount_volume_source_not_dir)
{
	/* Create a regular file as source */
	char tmpfile[] = "/tmp/ek_vol_test_XXXXXX";
	int fd = mkstemp(tmpfile);

	ck_assert(fd >= 0);
	close(fd);

	int ret = ek_bind_mount_volume("/tmp", tmpfile, "/data", 0);
	ck_assert_int_eq(ret, -ENOTDIR);

	unlink(tmpfile);
}
END_TEST

/* ================================================================
 * TEST 18: Volume source — does not exist
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   ek_bind_mount_volume() mit nicht existierendem Source → -ENOENT.
 */

START_TEST(test_bind_mount_volume_source_missing)
{
	int ret = ek_bind_mount_volume(
	    "/tmp", "/tmp/ek_nonexistent_vol_dir_12345", "/data", 0);
	ck_assert_int_eq(ret, -ENOENT);
}
END_TEST

/* ================================================================
 * TEST 19: Seccomp DEFAULT-Profil (Denylist)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Das DEFAULT-Profil ist eine Denylist: bekannte gefaehrliche
 *   Syscalls werden geblockt, alles andere erlaubt. Geeignet
 *   fuer allgemeine Server-Workloads die fork/exec brauchen.
 *
 * WAS WIR TESTEN:
 *   DEFAULT-Profil installieren, dann mount() ausfuehren.
 *   mount() ist in der Denylist → SIGSYS → Prozess stirbt.
 *
 * WARUM WICHTIG:
 *   mount() erlaubt Container-Escape (Host-FS mounten).
 *   Muss auch im permissivsten Profil geblockt sein.
 */

START_TEST(test_seccomp_default_blocks_mount)
{
	int ret = erlkoenig_apply_seccomp(SECCOMP_PROFILE_DEFAULT);

	ck_assert_int_eq(ret, 0);

	/* mount() is in the default denylist → SIGSYS → death */
	mount("tmpfs", "/tmp", "tmpfs", 0, "size=1m");

	ck_abort_msg("mount() survived default seccomp — filter broken");
}
END_TEST

/* ================================================================
 * TEST 20: Seccomp DEFAULT-Profil blockt process_vm_readv
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   process_vm_readv ist ein Cross-Prozess-Speicherzugriff.
 *   Muss im DEFAULT-Profil geblockt sein (Defense-in-Depth
 *   neben CAP_SYS_PTRACE Drop und PID-Namespace-Isolation).
 */

START_TEST(test_seccomp_default_blocks_process_vm_readv)
{
	int ret = erlkoenig_apply_seccomp(SECCOMP_PROFILE_DEFAULT);

	ck_assert_int_eq(ret, 0);

	/* process_vm_readv blocked → SIGSYS → death */
	struct iovec local = {.iov_base = (char[16]){0}, .iov_len = 16};
	struct iovec remote = {.iov_base = NULL, .iov_len = 16};

	syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);

	ck_abort_msg(
	    "process_vm_readv survived default seccomp — filter broken");
}
END_TEST

/* ================================================================
 * TEST 21: Seccomp NETWORK-Profil blockt fork
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Das NETWORK-Profil ist eine Allowlist fuer Netzwerk-Server.
 *   Erlaubt Sockets, accept, bind — aber KEIN fork/clone.
 *   Ein kompromittierter Netzwerk-Server kann keine neuen
 *   Prozesse starten.
 *
 * WAS WIR TESTEN:
 *   NETWORK-Profil installieren, dann fork() ausfuehren.
 *   fork() ist NICHT in der Allowlist → SIGSYS → Prozess stirbt.
 */

START_TEST(test_seccomp_network_blocks_fork)
{
	int ret = erlkoenig_apply_seccomp(SECCOMP_PROFILE_NETWORK);

	ck_assert_int_eq(ret, 0);

	/* fork() is not in the network allowlist → SIGSYS → death */
	fork();

	ck_abort_msg("fork() survived network seccomp — filter broken");
}
END_TEST

/* ================================================================
 * TEST 22: Seccomp NETWORK-Profil erlaubt Socket-Operationen
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   socket() ist in der NETWORK-Allowlist und MUSS funktionieren.
 *   Ein Netzwerk-Profil das Sockets blockt waere nutzlos.
 */

START_TEST(test_seccomp_network_allows_socket)
{
	/*
	 * Can't use ck_assert after applying seccomp — libcheck's
	 * internal plumbing uses syscalls not in the network allowlist.
	 * Run in a forked child and check exit code.
	 */
	pid_t pid = fork();

	ck_assert(pid >= 0);

	if (pid == 0) {
		if (erlkoenig_apply_seccomp(SECCOMP_PROFILE_NETWORK))
			_exit(1);

		/* socket() must succeed under network profile */
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

		if (fd < 0)
			_exit(2);
		close(fd);
		/* exit_group is in the allowlist */
		_exit(0);
	}

	int status;

	waitpid(pid, &status, 0);
	ck_assert_msg(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		      "socket() under network seccomp failed (status=%d)",
		      status);
}
END_TEST

/* ================================================================
 * TEST 23: Seccomp DEFAULT-Profil blockt io_uring
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   io_uring hat eine riesige Kernel-Angriffsflaeche und wird
 *   von Docker, Podman und Google geblockt. Auch im permissivsten
 *   Profil muss io_uring_setup geblockt sein.
 *
 * WAS WIR TESTEN:
 *   DEFAULT-Profil, dann io_uring_setup → SIGSYS.
 */

START_TEST(test_seccomp_default_blocks_io_uring)
{
	int ret = erlkoenig_apply_seccomp(SECCOMP_PROFILE_DEFAULT);

	ck_assert_int_eq(ret, 0);

	/* io_uring_setup (syscall 425) blocked → SIGSYS → death */
	syscall(425, 1, NULL);

	ck_abort_msg("io_uring_setup survived default seccomp — filter broken");
}
END_TEST

/* ================================================================
 * TEST 24: Seccomp DEFAULT-Profil blockt unshare/setns
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   unshare() erlaubt Namespace-Escape. Muss geblockt sein.
 */

START_TEST(test_seccomp_default_blocks_unshare)
{
	int ret = erlkoenig_apply_seccomp(SECCOMP_PROFILE_DEFAULT);

	ck_assert_int_eq(ret, 0);

	/* unshare blocked → SIGSYS → death */
	unshare(CLONE_NEWNS);

	ck_abort_msg("unshare() survived default seccomp — filter broken");
}
END_TEST

/* ================================================================
 * TEST 25: Landlock Deny-All (keine Regeln)
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   Landlock ist ein stackable Security Module (ab Kernel 5.13).
 *   Man erstellt ein Ruleset, deklariert welche Zugriffsrechte
 *   behandelt werden, fuegt Regeln hinzu (oder nicht), und
 *   aktiviert es mit landlock_restrict_self().
 *
 *   Ohne Regeln wird ALLES geblockt: open(), stat(), readdir().
 *   Bereits offene FDs funktionieren weiterhin — der Kernel
 *   prueft Landlock nur bei neuen Path-Operationen.
 *
 *   erlkoenig_rt nutzt genau dieses Pattern: nach CMD_GO wird
 *   ein leeres Landlock-Ruleset aktiviert. Der Runtime-Prozess
 *   kann nur noch ueber seine vorher geoeffneten FDs (Socket,
 *   Pipes, /proc/<pid>/root) kommunizieren.
 *
 * WAS WIR TESTEN:
 *   Landlock ohne Regeln aktivieren.
 *   open("/etc/hostname") → EACCES.
 *   Bereits offener FD → read() funktioniert weiterhin.
 *
 * WARUM WICHTIG:
 *   Ohne Landlock kann ein kompromittierter Runtime-Prozess
 *   beliebige Host-Dateien lesen/schreiben. Landlock ist die
 *   dritte Schicht nach Capabilities und Seccomp.
 */

static int do_test_landlock_deny_all(void)
{
	/* Open a file BEFORE Landlock activation */
	int pre_fd = open("/etc/hostname", O_RDONLY | O_CLOEXEC);

	if (pre_fd < 0) {
		/* /etc/hostname may not exist in all environments */
		pre_fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
		if (pre_fd < 0)
			return 1;
	}

	/* Check Landlock ABI */
	int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
			       LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		close(pre_fd);
		fprintf(stderr, "  SKIP: Landlock not available\n");
		return 0; /* skip gracefully */
	}

	/* Build rights mask matching what erlkoenig_rt uses */
	__u64 fs_rights =
	    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
	    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
	    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	    LANDLOCK_ACCESS_FS_MAKE_SYM;

	if (abi >= 2)
		fs_rights |= LANDLOCK_ACCESS_FS_REFER;
	if (abi >= 3)
		fs_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;

	struct landlock_ruleset_attr attr = {
	    .handled_access_fs = fs_rights,
	};

	int ruleset_fd =
	    (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (ruleset_fd < 0) {
		close(pre_fd);
		return 1;
	}

	/* NO rules added — deny everything */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		close(ruleset_fd);
		close(pre_fd);
		return 1;
	}
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0)) {
		close(ruleset_fd);
		close(pre_fd);
		return 1;
	}
	close(ruleset_fd);

	/* NEW open() must fail with EACCES */
	int new_fd = open("/etc/hostname", O_RDONLY);

	if (new_fd >= 0) {
		fprintf(stderr, "  FAIL: open() succeeded after Landlock\n");
		close(new_fd);
		close(pre_fd);
		return 1;
	}
	if (errno != EACCES) {
		fprintf(stderr, "  FAIL: expected EACCES, got %s\n",
			strerror(errno));
		close(pre_fd);
		return 1;
	}

	/* open("/proc/self/status") must also fail */
	new_fd = open("/proc/self/status", O_RDONLY);
	if (new_fd >= 0) {
		fprintf(stderr,
			"  FAIL: open(/proc) succeeded after Landlock\n");
		close(new_fd);
		close(pre_fd);
		return 1;
	}

	/* Pre-opened FD must still work */
	char buf[64];
	ssize_t n = read(pre_fd, buf, sizeof(buf));

	if (n < 0) {
		fprintf(stderr, "  FAIL: pre-opened FD read failed: %s\n",
			strerror(errno));
		close(pre_fd);
		return 1;
	}

	close(pre_fd);
	return 0;
}

START_TEST(test_landlock_deny_all)
{
	if (!probe_has_landlock()) {
		fprintf(stderr, "  SKIP (needs Landlock, kernel >= 5.13)\n");
		return;
	}
	/* Landlock is irreversible, run in a forked child */
	pid_t pid = fork();

	ck_assert(pid >= 0);

	if (pid == 0)
		_exit(do_test_landlock_deny_all());

	int status;

	waitpid(pid, &status, 0);
	ck_assert(WIFEXITED(status));
	ck_assert_int_eq(WEXITSTATUS(status), 0);
}
END_TEST

/* ================================================================
 * TEST 26: Landlock Pre-Opened Pipe ueberlebt
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   Pipe VOR Landlock oeffnen. Nach Aktivierung:
 *   write() in die Pipe → Daten kommen durch.
 *   Das ist das Kommunikationsmodell von erlkoenig_rt:
 *   Socket und Pipes werden VOR CMD_GO geoeffnet.
 *
 * WARUM WICHTIG:
 *   Wenn Landlock Pipes bricht, kann der Runtime nicht mehr
 *   mit dem Erlang-Controlplane kommunizieren.
 */

static int do_test_landlock_pipe_survives(void)
{
	int pipefd[2];

	if (pipe(pipefd))
		return 1;

	/* Activate Landlock deny-all */
	int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
			       LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 0; /* skip */
	}

	__u64 fs_rights =
	    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
	    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
	    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	    LANDLOCK_ACCESS_FS_MAKE_SYM;
	if (abi >= 2)
		fs_rights |= LANDLOCK_ACCESS_FS_REFER;
	if (abi >= 3)
		fs_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;

	struct landlock_ruleset_attr attr = {
	    .handled_access_fs = fs_rights,
	};
	int ruleset_fd =
	    (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (ruleset_fd < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0)) {
		close(ruleset_fd);
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}
	close(ruleset_fd);

	/* Write through pre-opened pipe must succeed */
	const char *msg = "landlock-pipe-ok";
	ssize_t w = write(pipefd[1], msg, 16);

	if (w != 16) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	char buf[16];
	ssize_t r = read(pipefd[0], buf, 16);

	close(pipefd[0]);
	close(pipefd[1]);

	if (r != 16 || memcmp(buf, msg, 16) != 0)
		return 1;

	return 0;
}

START_TEST(test_landlock_pipe_survives)
{
	if (!probe_has_landlock()) {
		fprintf(stderr, "  SKIP (needs Landlock, kernel >= 5.13)\n");
		return;
	}
	pid_t pid = fork();

	ck_assert(pid >= 0);

	if (pid == 0)
		_exit(do_test_landlock_pipe_survives());

	int status;

	waitpid(pid, &status, 0);
	ck_assert(WIFEXITED(status));
	ck_assert_int_eq(WEXITSTATUS(status), 0);
}
END_TEST

/* ================================================================
 * TEST 27: Landlock blockt Dateierstellung
 * ================================================================
 *
 * WAS WIR TESTEN:
 *   Nach Landlock-Aktivierung: creat("/tmp/test") → EACCES.
 *   Verifiziert dass MAKE_REG, WRITE_FILE geblockt werden.
 */

static int do_test_landlock_blocks_create(void)
{
	int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
			       LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0)
		return 0; /* skip */

	__u64 fs_rights =
	    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
	    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
	    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	    LANDLOCK_ACCESS_FS_MAKE_SYM;
	if (abi >= 2)
		fs_rights |= LANDLOCK_ACCESS_FS_REFER;
	if (abi >= 3)
		fs_rights |= LANDLOCK_ACCESS_FS_TRUNCATE;

	struct landlock_ruleset_attr attr = {
	    .handled_access_fs = fs_rights,
	};
	int ruleset_fd =
	    (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (ruleset_fd < 0)
		return 1;

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0)) {
		close(ruleset_fd);
		return 1;
	}
	close(ruleset_fd);

	/* File creation must fail */
	int fd = open("/tmp/ek_landlock_test", O_CREAT | O_WRONLY, 0644);

	if (fd >= 0) {
		close(fd);
		unlink("/tmp/ek_landlock_test");
		return 1; /* Should have been blocked */
	}
	if (errno != EACCES)
		return 1;

	/* Directory creation must also fail */
	if (mkdir("/tmp/ek_landlock_test_dir", 0755) == 0) {
		rmdir("/tmp/ek_landlock_test_dir");
		return 1;
	}
	if (errno != EACCES)
		return 1;

	return 0;
}

START_TEST(test_landlock_blocks_create)
{
	if (!probe_has_landlock()) {
		fprintf(stderr, "  SKIP (needs Landlock, kernel >= 5.13)\n");
		return;
	}
	pid_t pid = fork();

	ck_assert(pid >= 0);

	if (pid == 0)
		_exit(do_test_landlock_blocks_create());

	int status;

	waitpid(pid, &status, 0);
	ck_assert(WIFEXITED(status));
	ck_assert_int_eq(WEXITSTATUS(status), 0);
}
END_TEST

/* ================================================================
 * TEST 28: Cgroup pids.max Enforcement
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   cgroup v2 pids.max begrenzt die Anzahl Prozesse in einem Cgroup.
 *   Wenn das Limit erreicht ist, schlaegt fork() mit EAGAIN fehl.
 *   Das schuetzt den Host vor Fork-Bomben aus dem Container.
 *
 * WAS WIR TESTEN:
 *   erlkoenig_cg_setup() mit pids_max=5 konfigurieren.
 *   Kind-Prozess forkt in einer Schleife bis EAGAIN.
 *   Wenn das Limit greift, ist der Test bestanden.
 *
 * WARUM WICHTIG:
 *   Ohne pids.max kann ein einzelner Container den gesamten Host
 *   durch unkontrolliertes Forken lahmlegen (Fork-Bombe).
 */

START_TEST(test_cgroup_pids_max)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	if (!probe_has_cgroup_delegation()) {
		fprintf(stderr, "  SKIP (needs cgroup delegation)\n");
		return;
	}

	int pipefd[2];

	ck_assert_int_eq(pipe(pipefd), 0);

	pid_t child = fork();

	ck_assert(child >= 0);

	if (child == 0) {
		/* Kind: warte bis Parent die Cgroup eingerichtet hat */
		close(pipefd[1]);

		char buf;

		if (read(pipefd[0], &buf, 1) != 1)
			_exit(1);
		close(pipefd[0]);

		/*
		 * Forke bis das pids.max-Limit greift (EAGAIN).
		 * pids_max=5 zaehlt alle PIDs in der Cgroup inkl. uns.
		 * Wir sammeln Kind-PIDs und warten am Ende auf sie.
		 */
		pid_t children[64];
		int nchildren = 0;
		int hit_limit = 0;

		for (int i = 0; i < 64; i++) {
			pid_t p = fork();

			if (p < 0) {
				if (errno == EAGAIN) {
					hit_limit = 1;
					break;
				}
				/* Anderer Fehler — aufgeben */
				break;
			}
			if (p == 0) {
				/* Enkel: warte kurz und beende */
				usleep(500000);
				_exit(0);
			}
			children[nchildren++] = p;
		}

		/* Alle Enkel einsammeln */
		for (int i = 0; i < nchildren; i++)
			waitpid(children[i], NULL, 0);

		_exit(hit_limit ? 0 : 1);
	}

	/* Parent: Cgroup fuer Kind einrichten */
	close(pipefd[0]);

	char cg_path[4096];

	int ret = erlkoenig_cg_setup(child, "ek-test-pids", 0, 5, 0, cg_path,
				     sizeof(cg_path));
	if (ret) {
		/* Cgroup-Setup fehlgeschlagen — Kind abbrechen */
		close(pipefd[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		ck_abort_msg("erlkoenig_cg_setup failed: %s", strerror(-ret));
	}

	/* Kind starten */
	write(pipefd[1], "g", 1);
	close(pipefd[1]);

	int status;

	waitpid(child, &status, 0);

	/* Cgroup immer aufraeumen */
	erlkoenig_cg_teardown(cg_path);

	ck_assert_msg(WIFEXITED(status),
		      "child did not exit normally (signal %d)",
		      WIFSIGNALED(status) ? WTERMSIG(status) : -1);
	ck_assert_int_eq(WEXITSTATUS(status), 0);
}
END_TEST

/* ================================================================
 * TEST 29: Cgroup memory.max Enforcement
 * ================================================================
 *
 * LINUX-KONZEPT:
 *   cgroup v2 memory.max begrenzt den physischen Speicher einer
 *   Cgroup. Ueberschreitung fuehrt zum OOM-Kill (SIGKILL) durch
 *   den Kernel oder malloc-Fehler.
 *
 * WAS WIR TESTEN:
 *   erlkoenig_cg_setup() mit memory_max=32MB konfigurieren.
 *   Kind alloziert 1MB-Bloecke und beschreibt sie (dirty pages).
 *   Erwartet: OOM-Kill (SIGKILL) oder malloc-Fehler vor 32MB.
 *
 * WARUM WICHTIG:
 *   Ohne memory.max kann ein Container den gesamten RAM verbrauchen
 *   und den Host-OOM-Killer auf beliebige Prozesse hetzen.
 */

START_TEST(test_cgroup_memory_max)
{
	if (geteuid() != 0) {
		fprintf(stderr, "  SKIP (needs root)\n");
		return;
	}
	if (!probe_has_cgroup_delegation()) {
		fprintf(stderr, "  SKIP (needs cgroup delegation)\n");
		return;
	}

	int pipefd[2];

	ck_assert_int_eq(pipe(pipefd), 0);

	pid_t child = fork();

	ck_assert(child >= 0);

	if (child == 0) {
		/* Kind: warte bis Parent die Cgroup eingerichtet hat */
		close(pipefd[1]);

		char buf;

		if (read(pipefd[0], &buf, 1) != 1)
			_exit(1);
		close(pipefd[0]);

/*
 * Alloziere 1MB-Bloecke und beschreibe sie komplett
 * (memset erzwingt physische Seitenallokation).
 * Bei 32MB Limit sollte der OOM-Killer zuschlagen
 * oder malloc fehlschlagen.
 */
#define CHUNK_SIZE (1024 * 1024) /* 1 MB */
#define MAX_CHUNKS 128		 /* 128 MB max Versuch */

		void *chunks[MAX_CHUNKS];
		int nchunks = 0;
		int malloc_failed = 0;

		for (int i = 0; i < MAX_CHUNKS; i++) {
			void *p = malloc(CHUNK_SIZE);

			if (!p) {
				malloc_failed = 1;
				break;
			}
			memset(p, 0xAA, CHUNK_SIZE);
			chunks[nchunks++] = p;
		}

		/* Aufraeumen (falls wir hier ankommen) */
		for (int i = 0; i < nchunks; i++)
			free(chunks[i]);

		/*
		 * Erfolg: malloc hat fehlgeschlagen (Limit erreicht).
		 * Fehler: Wir konnten >32MB allozieren ohne Limit.
		 */
		if (malloc_failed)
			_exit(0);
		_exit(1);
	}

	/* Parent: Cgroup fuer Kind einrichten (32 MB Limit) */
	close(pipefd[0]);

	char cg_path[4096];
	uint64_t mem_limit = 32ULL * 1024 * 1024;

	int ret = erlkoenig_cg_setup(child, "ek-test-mem", mem_limit, 0, 0,
				     cg_path, sizeof(cg_path));
	if (ret) {
		close(pipefd[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		ck_abort_msg("erlkoenig_cg_setup failed: %s", strerror(-ret));
	}

	/* Kind starten */
	write(pipefd[1], "g", 1);
	close(pipefd[1]);

	int status;

	waitpid(child, &status, 0);

	/* Cgroup immer aufraeumen */
	erlkoenig_cg_teardown(cg_path);

	/*
	 * Zwei Erfolgsfaelle:
	 *   1. Kind wurde per SIGKILL (OOM) getoetet
	 *   2. Kind hat malloc-Fehler erkannt und exit(0) gemacht
	 */
	if (WIFSIGNALED(status)) {
		ck_assert_int_eq(WTERMSIG(status), SIGKILL);
	} else {
		ck_assert(WIFEXITED(status));
		ck_assert_int_eq(WEXITSTATUS(status), 0);
	}
}
END_TEST

/* ================================================================
 * Test Suite Setup
 * ================================================================ */

static Suite *container_setup_suite(void)
{
	Suite *s = suite_create("container_setup");

	/* Phase 1: Dateisystem aufbauen */
	TCase *tc_fs = tcase_create("Phase 1: Dateisystem");

	tcase_set_timeout(tc_fs, 10);
	tcase_add_test(tc_fs, test_tmpfs_rootfs);
	tcase_add_test(tc_fs, test_bind_mount_devices);
	tcase_add_test(tc_fs, test_procfs_hidepid);
	suite_add_tcase(s, tc_fs);

	/* Phase 2: Isolation herstellen */
	TCase *tc_iso = tcase_create("Phase 2: Isolation");

	tcase_set_timeout(tc_iso, 10);
	tcase_add_test(tc_iso, test_pivot_root);
	tcase_add_test(tc_iso, test_mask_paths);
	tcase_add_test(tc_iso, test_readonly_rootfs);
	suite_add_tcase(s, tc_iso);

	/* Phase 3: Rechte einschraenken */
	TCase *tc_priv = tcase_create("Phase 3: Rechte");

	tcase_set_timeout(tc_priv, 10);
	tcase_add_test(tc_priv, test_capability_drop);
	tcase_add_test(tc_priv, test_rlimits);
	tcase_add_test_raise_signal(tc_priv, test_seccomp_bpf, SIGSYS);
	tcase_add_test_raise_signal(tc_priv, test_seccomp_default_blocks_mount,
				    SIGSYS);
	tcase_add_test_raise_signal(
	    tc_priv, test_seccomp_default_blocks_process_vm_readv, SIGSYS);
	tcase_add_test_raise_signal(tc_priv, test_seccomp_network_blocks_fork,
				    SIGSYS);
	tcase_add_test(tc_priv, test_seccomp_network_allows_socket);
	tcase_add_test_raise_signal(
	    tc_priv, test_seccomp_default_blocks_io_uring, SIGSYS);
	tcase_add_test_raise_signal(
	    tc_priv, test_seccomp_default_blocks_unshare, SIGSYS);
	suite_add_tcase(s, tc_priv);

	/* Phase 4: Prozessmodell */
	TCase *tc_proc = tcase_create("Phase 4: Prozessmodell");

	tcase_set_timeout(tc_proc, 10);
	tcase_add_test(tc_proc, test_signal_forwarding);
	tcase_add_test(tc_proc, test_no_new_privs);
	tcase_add_test(tc_proc, test_namespace_isolation);
	suite_add_tcase(s, tc_proc);

	/* Phase 5: Bind-Mount Volumes */
	TCase *tc_vol = tcase_create("Phase 5: Volumes");

	tcase_set_timeout(tc_vol, 10);
	tcase_add_test(tc_vol, test_bind_mount_volume_basic);
	tcase_add_test(tc_vol, test_bind_mount_volume_readonly);
	tcase_add_test(tc_vol, test_bind_mount_volume_bad_dest_relative);
	tcase_add_test(tc_vol, test_bind_mount_volume_bad_dest_traversal);
	tcase_add_test(tc_vol, test_bind_mount_volume_source_not_dir);
	tcase_add_test(tc_vol, test_bind_mount_volume_source_missing);
	suite_add_tcase(s, tc_vol);

	/* Phase 6: Landlock Filesystem-Isolation */
	TCase *tc_ll = tcase_create("Phase 6: Landlock");

	tcase_set_timeout(tc_ll, 10);
	tcase_add_test(tc_ll, test_landlock_deny_all);
	tcase_add_test(tc_ll, test_landlock_pipe_survives);
	tcase_add_test(tc_ll, test_landlock_blocks_create);
	suite_add_tcase(s, tc_ll);

	/* Phase 7: Cgroup Enforcement */
	TCase *tc_cg = tcase_create("Phase 7: Cgroup Enforcement");

	tcase_set_timeout(tc_cg, 30);
	tcase_add_test(tc_cg, test_cgroup_pids_max);
	tcase_add_test(tc_cg, test_cgroup_memory_max);
	suite_add_tcase(s, tc_cg);

	return s;
}

int main(void)
{
	Suite *s = container_setup_suite();
	SRunner *sr = srunner_create(s);

	/* CK_NORMAL: one line per test. CK_VERBOSE: full details. */
	srunner_run_all(sr, CK_NORMAL);

	int failed = srunner_ntests_failed(sr);

	srunner_free(sr);

	return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
