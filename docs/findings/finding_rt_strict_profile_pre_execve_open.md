# finding_rt_strict_profile_pre_execve_open

## Trigger

`erlkoenig_ns.c:1599` installs the seccomp filter
(`erlkoenig_apply_seccomp(opts->seccomp_profile)`).
`erlkoenig_ns.c:1607` then calls
`open("/app", O_PATH | O_CLOEXEC)` and
`erlkoenig_ns.c:1612` calls `apply_landlock_container()` which itself
calls `syscall(SYS_landlock_create_ruleset, ...)` and `open("/app",
O_PATH | O_CLOEXEC)` (ns.c:1339).
`erlkoenig_ns.c:1663` calls `syscall(SYS_execveat, ...)`.

The `STRICT` seccomp profile (`erlkoenig_seccomp.h:133`) is an allow-
list whose contents are: `execve, arch_prctl, set_tid_address,
set_robust_list, rseq, prlimit64, readlinkat, read, write, readv,
writev, close, exit, exit_group, rt_sigreturn, rt_sigaction,
rt_sigprocmask, brk, mmap, munmap, mprotect, clock_gettime,
clock_nanosleep, nanosleep, getrandom, futex, getpid`.

`open`, `openat`, `landlock_create_ruleset`, `landlock_add_rule`,
`landlock_restrict_self`, and `execveat` are **not** in this allow-
list. The default action is `SECCOMP_RET_KILL_PROCESS`.

Reproduction without escape code:

1. Build the runtime with `ERLKOENIG_BUILD_BOUNDARY=ON`.
2. Spawn any container with `seccomp_profile = SECCOMP_PROFILE_STRICT`
   (e.g. `ek_rtctl spawn --path /tmp/hello --seccomp 2`).
3. Observe the runtime emits `child killed by signal 31` and the
   `REPLY_EXITED` carries `exit_code=-1 term_signal=31`. The container
   binary's `main()` is never reached.

The boundary probe `probe_seccomp_strict__positive_control.c` (a
no-op `int main(void) { PROBE_OK(...) }` static-musl binary) reproduces
the issue identically — it cannot even reach `_start`, because the
*runtime's* `open("/app")` between seccomp install and `execveat` is
killed first.

`strace` of the same probe binary outside the container confirms the
binary itself only uses `execve, arch_prctl, set_tid_address, writev,
exit_group` — all five present in the STRICT allowlist.

## Impact

The STRICT seccomp profile is the SPEC-EK-021 "compute" tier and the
strongest defence-in-depth boundary erlkoenig offers. As implemented
today, **no container can be spawned with the STRICT profile**. The
boundary is intact in the trivial sense that the container is killed
before it can do anything — but the operator-facing contract that
SPEC-EK-021 §3 promises (compute workloads run with ~15-syscall
attack surface) cannot actually be exercised.

Practical effect:

- Operators selecting `sandbox: :compute` (or its raw equivalent
  `seccomp_profile = 2`) will see the container fail to start with
  exit code -1 / signal SIGSYS. No useful work happens.
- Anyone reading SPEC-EK-021 acceptance criteria
  ("seccomp compute: socket() → SIGSYS") cannot demonstrate that
  exact behaviour, because the container never reaches `socket()`.
- `DEFAULT` (denylist) and `NETWORK` (broader allowlist) profiles
  are unaffected — both allow `open`/`openat`/`execveat`/Landlock
  syscalls, so the runtime's pre-execve setup completes.

## Fix

Two minimally-invasive options, in increasing scope:

### Option A: extend the STRICT allowlist

Add `open`, `openat`, `landlock_create_ruleset`, `landlock_add_rule`,
`landlock_restrict_self`, and `execveat` to the STRICT allowlist —
but ONLY for the duration of the runtime's pre-execve setup, not for
the container workload.

This is hard with classic seccomp BPF: filters are installed once and
cannot be tightened. SECCOMP_FILTER_FLAG_TSYNC + per-thread filters
exist but don't help here because we want to *narrow* the filter,
not widen it.

### Option B: install seccomp AFTER the open + landlock setup

The current ordering is:

```
drop_caps()
apply_seccomp(STRICT)        ← installs filter
open("/app", O_PATH)         ← KILLED under STRICT
apply_landlock_container()   ← KILLED under STRICT
execveat(app_fd, ...)        ← KILLED under STRICT
```

The fix is to reorder:

```
drop_caps()
open("/app", O_PATH)              ← needs no filter; cap-drop has set NNP
apply_landlock_container()        ← Landlock needs NNP, set already
apply_seccomp(STRICT)             ← install filter LAST
execveat(app_fd, "", AT_EMPTY_PATH)   ← still allowed (execve is in STRICT)
```

Concerns to verify:

- `execveat` is currently NOT in the STRICT allowlist; only `execve`
  is (seccomp.h:137). Either add `execveat` or fall through to the
  path-based `execve` at ns.c:1677. Path-based execve under Landlock
  re-opens the binary by path, which Landlock may deny (depending on
  whether `/app` is added as a permitted-execute path beneath rule).
  The current `apply_landlock_container` at ns.c:1342 grants
  `LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE` on
  `/app`, so path-based exec should work — but the seccomp filter
  must allow `execve`.
- The post-execve in-binary syscalls (libc init) must all be in
  STRICT. The `probe_seccomp_strict__positive_control` test
  (run outside the container via strace) confirms statically-linked
  musl `main()` uses only `execve, arch_prctl, set_tid_address,
  writev, exit_group` for a no-op program — all present in STRICT.

### Option C: add `execveat` and the Landlock syscalls to STRICT

Less ideal because it widens the contract beyond "pure compute, 15
syscalls". The point of STRICT is the small attack surface; adding
6 more syscalls erodes that. Option B is preferred.

### Recommended

Option B — reorder so seccomp install happens after open + Landlock
setup. Plus: confirm `execveat` is reached via the AT_EMPTY_PATH
path, OR ensure path-based `execve("/app", ...)` works under
Landlock (the rule at ns.c:1342 should permit it).

## Regression

```sh
make boundary-probes
```

The `probe_seccomp_strict__positive_control` probe must report PASS
(probe exits 0). Currently it FAILs with `term_signal=31`.

Also: any of the four other `probe_seccomp_strict__*` probes (which
test individual denied syscalls) will pass as "killed by SIGSYS"
under the current bug, but only because the runtime kills the
process before it reaches the probe's syscall — they're confounded.
After the fix they will only pass if the probe binary's syscall is
actually denied by STRICT, not the runtime's setup.

## Notes

This finding does not constitute a security regression — STRICT being
"too strict" is more conservative than the spec promises. But it does
constitute a usability regression: a documented profile cannot be
used in production. The spec's acceptance criteria
(SPEC-EK-021 §"Akzeptanzkriterien": "seccomp compute: socket() → SIGSYS")
cannot be demonstrated end-to-end until this is fixed.
