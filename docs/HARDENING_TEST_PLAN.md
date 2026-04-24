# Hardening Test Plan

This document turns the current sanitizer and fault-injection work into a
repeatable workflow. The goal is not to add more security features first. The
goal is to prove that the existing privileged runtime fails safely under
compiler sanitizers, parser fuzzing, syscall failures, and root integration
paths.

## Current State

`erlkoenig_rt` already has the important foundation:

- `ERLKOENIG_SANITIZE=ON` enables ASan + UBSan and switches to a dynamic glibc
  build, because static musl is not suitable for sanitizer runs.
- `make debug` already configures and builds `build-san` with sanitizers.
- `erlkoenig_rt`, `ek_rtctl`, and `gateway` receive sanitizer flags in sanitize
  mode.
- `test_container_setup` also receives sanitizer flags when
  `ERLKOENIG_BUILD_TESTS=ON`.
- `test/fault/` contains a syscall fault-injection shim and sweep scripts.
- `test/fuzz/` contains parser fuzz harnesses for the command TLV parsers.

The missing part is productization: one-command targets that developers and CI
can run without remembering the right CMake flags, build directory, sanitizer
environment, root requirements, or fault-sweep paths.

## Target Workflow

After this plan is implemented, these commands should exist and be meaningful:

```sh
make
make test
make debug
make debug-test
make fault-smoke
make path-sweep
make fuzz-smoke
```

Expected meaning:

- `make`: release-style static musl build.
- `make test`: normal unit/integration-oriented test path.
- `make debug`: sanitizer build of runtime binaries.
- `make debug-test`: sanitizer build plus `test_container_setup`.
- `make fault-smoke`: short syscall-fault sweep under sanitizers.
- `make path-sweep`: path-filtered open fault sweep under sanitizers.
- `make fuzz-smoke`: short libFuzzer runs for parser harnesses.

## Makefile Targets

Two build directories on purpose:

- `build-san` — ASan+UBSan + tests + fault-shim, using the default compiler
  (typically gcc). Drives `debug-test`, `fault-shim`, `fault-smoke`,
  `path-sweep`.
- `build-fuzz` — libFuzzer harnesses, Clang-only. Drives `fuzz-smoke`.

The split exists because `ERLKOENIG_BUILD_FUZZ` requires Clang and errors out
on gcc. Mixing both into one build dir would break `make debug-test` on a
gcc-only runner. Separate dirs keep each tier's dependencies clear.

```make
.PHONY: configure-san configure-fuzz debug-test fault-shim \
        fault-smoke path-sweep fuzz-smoke

configure-san:         ## Configure sanitizer+tests+fault-shim build (once)
	@test -f build-san/CMakeCache.txt || cmake -B build-san \
		-DCMAKE_BUILD_TYPE=Debug \
		-DERLKOENIG_SANITIZE=ON \
		-DERLKOENIG_BUILD_TESTS=ON \
		-DERLKOENIG_BUILD_TESTBIN=ON \
		-DERLKOENIG_BUILD_FAULT_SHIM=ON

configure-fuzz:        ## Configure clang-only fuzz build (once)
	@command -v clang >/dev/null 2>&1 || \
		{ echo "ERROR: clang is required for fuzz-smoke." >&2; exit 1; }
	@test -f build-fuzz/CMakeCache.txt || cmake -B build-fuzz \
		-DCMAKE_C_COMPILER=clang \
		-DCMAKE_BUILD_TYPE=Debug \
		-DERLKOENIG_BUILD_FUZZ=ON \
		-DERLKOENIG_BUILD_GATEWAY=OFF \
		-DERLKOENIG_BUILD_TESTBIN=OFF

debug-test: configure-san  ## Build + run sanitizer C tests (sudo)
	cmake --build build-san -j$$(nproc)
	sudo ./build-san/test/test_container_setup

fault-shim: configure-san  ## Build LD_PRELOAD fault injector
	cmake --build build-san --target ek_fault_shim -j$$(nproc)

fault-smoke: fault-shim    ## Short syscall fault-injection sweep (sudo)
	BUILD=$$(pwd)/build-san \
	OUT=/tmp/erlkoenig_rt_fault_smoke \
	NTHS="1 2" \
	ERRNOS="12" \
	test/fault/ek_fault_sweep.sh mount setns open openat sendto recv

path-sweep: fault-shim     ## Path-filtered open fault sweep (sudo)
	BUILD=$$(pwd)/build-san \
	OUT=/tmp/erlkoenig_rt_path_sweep \
	NTHS="1 2" \
	ERRNOS="1 12 13 28" \
	test/fault/ek_path_sweep.sh

fuzz-smoke: configure-fuzz ## Short parser fuzz runs under libFuzzer
	cmake --build build-fuzz --target fuzz_spawn fuzz_kill fuzz_net_setup fuzz_resize -j$$(nproc)
	mkdir -p build-fuzz/fuzz-crashes
	cd build-fuzz/fuzz-crashes && ../fuzz_spawn     -max_total_time=20 -max_len=65536 ../../test/fuzz/corpus
	cd build-fuzz/fuzz-crashes && ../fuzz_kill      -max_total_time=10 -max_len=1024  ../../test/fuzz/corpus
	cd build-fuzz/fuzz-crashes && ../fuzz_net_setup -max_total_time=10 -max_len=1024  ../../test/fuzz/corpus
	cd build-fuzz/fuzz-crashes && ../fuzz_resize    -max_total_time=10 -max_len=128   ../../test/fuzz/corpus
```

Notes:

- Both `configure-*` targets are idempotent — the cache check skips the
  reconfigure step when already done. If CMake options need to change, run
  `make clean` or delete the relevant `CMakeCache.txt` and re-run.
- `debug-test`, `fault-smoke`, and `path-sweep` may need root because
  `test_container_setup` exercises namespaces, cgroups, mounts, and delegated
  cgroup setup.
- `fault-smoke` is intentionally short. Keep the full sweep as a manual or
  nightly job.
- `fuzz-smoke` requires `clang` because libFuzzer is Clang-native. The
  `configure-fuzz` target fails loudly with a clear error if `clang` is
  missing — never silently skipped.

## CMake Targets

Two guarded options keep the fault shim and fuzzers out of the main build
unless explicitly asked for. They live in `CMakeLists.txt` next to the
sanitizer option.

```cmake
option(ERLKOENIG_BUILD_FAULT_SHIM "Build LD_PRELOAD fault injector" OFF)
option(ERLKOENIG_BUILD_FUZZ      "Build libFuzzer parser harnesses (Clang only)" OFF)

if(ERLKOENIG_BUILD_FAULT_SHIM)
    add_library(ek_fault_shim SHARED test/fault/ek_fault_shim.c)
    target_compile_definitions(ek_fault_shim PRIVATE _GNU_SOURCE)
    target_compile_options(ek_fault_shim PRIVATE
        -Wall -Wextra -g -O0 -fPIC
    )
    target_link_libraries(ek_fault_shim dl)
    set_target_properties(ek_fault_shim PROPERTIES
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endif()

if(ERLKOENIG_BUILD_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "ERLKOENIG_BUILD_FUZZ requires Clang (libFuzzer). "
            "Configure with -DCMAKE_C_COMPILER=clang.")
    endif()

    foreach(fz spawn kill net_setup resize)
        add_executable(fuzz_${fz}
            test/fuzz/fuzz_${fz}_parser.c
            src/ek_protocol.c
        )
        target_include_directories(fuzz_${fz} PRIVATE include)
        target_compile_definitions(fuzz_${fz} PRIVATE _GNU_SOURCE)
        target_compile_options(fuzz_${fz} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -g -O1 -fno-omit-frame-pointer
        )
        target_link_options(fuzz_${fz} PRIVATE
            -fsanitize=fuzzer,address,undefined
        )
        set_target_properties(fuzz_${fz} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        )
    endforeach()
endif()
```

Do NOT add `ERLKOENIG_BUILD_FUZZ=ON` to the sanitizer build dir. The fuzz
targets are built in `build-fuzz` against `clang`; the sanitizer build uses
the default compiler (typically gcc). A single build dir with both options
fails to configure when `clang` is not the default compiler.

## Acceptance Criteria

A hardening change is acceptable when all applicable checks pass:

```sh
make
make debug-test
make fault-smoke
make fuzz-smoke
```

Expected outcomes:

- No new compiler warnings on supported toolchains. (gcc 13 / clang 18 are the
  current reference compilers; a handful of pre-existing `-Wformat-truncation`
  noise from `snprintf` estimates is tolerated and tracked separately.)
- No ASan findings.
- No UBSan findings.
- No LeakSanitizer findings in the sanitizer test path, unless documented as a
  known external library leak.
- No fault-sweep hangs.
- No unexpected runtime crashes.
- Faults in security-critical paths either produce a controlled test failure or
  a clear runtime error. Silent success after a fault fires must be treated as a
  finding until explained.

## Security-Critical Failure Policy

The runtime should fail closed for security boundaries:

- `memory.max` cannot be applied: fail spawn.
- `pids.max` cannot be applied: fail spawn.
- Runtime capability drop fails after `GO`: exit runtime.
- `NO_NEW_PRIVS` fails before seccomp: exit runtime.
- Seccomp install fails: exit runtime.
- Restoring the host network namespace fails: exit runtime.
- Rootfs cannot be restored read-only after `WRITE_FILE`: return protocol error.

The runtime may remain best-effort for non-security QoS:

- `cpu.weight` failure: log warning and continue.
- Optional metrics setup failure: log warning and continue.
- Optional BPF metrics attachment failure: log warning and continue.

This distinction should be visible in code comments and tests. If a future
change moves a field from best-effort to security-critical, update this section
in the same commit.

## Suggested Commit Split

Split the current hardening work into small, reviewable commits:

```text
hardening(cgroup): fail closed on memory and pids limit errors
hardening(net): bound rtnetlink waits
hardening(net): exit on netns restore loss
hardening(nft): surface socket timeout setup failures
hardening(nft): exit on netns restore loss
hardening(runtime): exit if post-go cap or seccomp hardening fails
hardening(rootfs): report writable-rootfs restore failures
test(fault): add syscall fault-injection shim and sweeps
build(test): add sanitizer test and fault smoke targets
docs(test): document hardening validation workflow
```

Each commit should build independently with:

```sh
make
```

Commits touching runtime safety paths should additionally pass:

```sh
make debug-test
```

Commits touching cleanup or syscall failure paths should additionally pass:

```sh
make fault-smoke
```

Commits touching `ek_protocol.c` or `erlkoenig_tlv.h` should additionally pass:

```sh
make fuzz-smoke
```

Keep failure-policy categories separate. Timeout bounding and better error
surfacing are robustness changes. Losing the host namespace after `setns` is a
security-critical invariant and should be committed separately.

## Fuzz Corpus Policy

`test/fuzz/corpus/` is a seed corpus and should be committed. It keeps fuzz
smoke tests useful and reproducible.

Policy:

- Commit small, meaningful seeds and minimized regressions.
- Do not commit unbounded libFuzzer growth after every local run.
- Periodically minimize with `llvm-cmin` / `llvm-profdata` tooling or an
  equivalent `-merge=1` workflow.
- If a crash is found, keep the crashing input as a regression seed after it is
  minimized and the bug is fixed.

Recommended manual minimization pattern:

```sh
mkdir -p /tmp/ek-corpus-min
build-san/fuzz_spawn -merge=1 /tmp/ek-corpus-min test/fuzz/corpus /tmp/new-corpus
```

Review minimized corpus changes like source code: small, intentional, and tied
to a parser behavior or a fixed crash.

## Fuzzer Crash Artifacts

Run fuzzers from `build-san/fuzz-crashes/` so libFuzzer writes crash artifacts
there instead of polluting the repository root.

Reproduce a crash with:

```sh
build-san/fuzz_spawn build-san/fuzz-crashes/crash-<sha>
build-san/fuzz_kill build-san/fuzz-crashes/crash-<sha>
build-san/fuzz_net_setup build-san/fuzz-crashes/crash-<sha>
build-san/fuzz_resize build-san/fuzz-crashes/crash-<sha>
```

After triage:

- Keep the crash file in `build-san/fuzz-crashes/` while debugging.
- Minimize it before committing.
- Commit the minimized reproducer into `test/fuzz/corpus/` only after the fix.
- Do not commit `build-san/fuzz-crashes/`.

## Finding Records

Runtime hardening findings should use the same finding pattern as the main
`erlkoenig` repository: one small Markdown record per issue, with a stable title,
trigger, impact, fix, and regression test.

Suggested location:

```text
docs/findings/finding_rt_<short_name>.md
```

Suggested shape:

```md
# finding_rt_<short_name>

## Trigger

What fault, fuzz input, or integration path exposed the issue.

## Impact

Why this mattered: host resource leak, fail-open limit, wrong netns, writable
rootfs, parser crash, hang, etc.

## Fix

What changed.

## Regression

The exact command or test that now catches it.
```

If `fault-smoke`, `path-sweep`, or `fuzz-smoke` finds a real issue, create the
finding record in the same commit series as the fix.

## CI Recommendation

Use three levels:

1. Per-push:

```sh
make
make fuzz-smoke
```

This tier requires `clang`. If a runner cannot guarantee Clang/libFuzzer, move
`make fuzz-smoke` to tier 2 and make the missing dependency explicit in CI
configuration. Do not silently skip fuzz smoke tests.

2. Privileged CI runner, per-push or per-merge:

```sh
make debug-test
make fault-smoke
```

3. Nightly:

```sh
make path-sweep
NTHS="1 2 3 4 5" ERRNOS="1 4 5 12 13 28" test/fault/ek_fault_sweep.sh
```

The privileged runner must support:

- user namespaces / mount namespaces as required by tests
- cgroup v2
- `systemd-run --scope -p Delegate=yes`
- ASan/UBSan runtime libraries
- `clang` for fuzz smoke tests

## Manual Review Checklist

Before marking the runtime as hardened enough for controlled edge deployments,
verify these manually at least once:

- A container with requested `memory.max` fails to spawn if `memory.max` cannot
  be written.
- A container with requested `pids.max` fails to spawn if `pids.max` cannot be
  written.
- A forced `setns` restore failure terminates the runtime instead of leaving it
  serving from the child netns.
- A forced `capset` failure after `GO` terminates the runtime.
- A forced seccomp install failure after `GO` terminates the runtime.
- A forced read-only remount failure after `WRITE_FILE` returns a protocol
  error to the control plane.
- Erlang control plane handles each runtime failure as a container/runtime
  failure, not as a successful spawn.

## Definition of Done

This hardening phase is done when:

- The Makefile exposes `debug-test`, `fault-smoke`, `path-sweep`, and
  `fuzz-smoke`.
- The current hardening changes are split into focused commits.
- All acceptance commands pass on a developer machine.
- At least `make` and `make fuzz-smoke` run in regular CI.
- At least `make debug-test` and `make fault-smoke` run on a privileged CI
  runner or are documented as required pre-release checks.
- Any intentional fail-open behavior is documented next to the code and in this
  document.
