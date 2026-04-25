# erlkoenig_rt — Privileged C runtime for erlkoenig containers.
#
# Build:  make
# Test:   make test
# Clean:  make clean

.PHONY: all test test-rt clean install uninstall help \
        configure-san configure-fuzz debug-test fault-shim \
        fault-smoke path-sweep fuzz-smoke \
        configure-boundary boundary-probes

# ── Build ────────────────────────────────────────────────

all:                   ## Build runtime + gateway (static musl)
	@cmake -B build -DCMAKE_C_COMPILER=musl-gcc -DCMAKE_BUILD_TYPE=Release \
		-DERLKOENIG_BUILD_TESTBIN=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		2>&1 | tail -1
	@cmake --build build -j$$(nproc)
	@printf "=> build/erlkoenig_rt (%s)  ek_rtctl (%s)  gateway (%s)  static musl\n" \
		"$$(du -h build/erlkoenig_rt | cut -f1)" \
		"$$(du -h build/ek_rtctl | cut -f1)" \
		"$$(du -h build/gateway | cut -f1)"

debug:                 ## Build with ASan + UBSan (dynamic)
	cmake -B build-san -DCMAKE_BUILD_TYPE=Debug -DERLKOENIG_SANITIZE=ON
	cmake --build build-san -j$$(nproc)

# ── Test ─────────────────────────────────────────────────

test: test-rt          ## Run all tests

test-rt: all           ## Run C unit tests
	cmake -B build-test -DCMAKE_BUILD_TYPE=Debug -DERLKOENIG_BUILD_TESTS=ON
	cmake --build build-test -j$$(nproc)
	./build-test/test/test_container_setup

# ── Hardening workflow (sanitizer + fault + fuzz) ─────────
#
# Two build directories on purpose:
#   build-san   — ASan+UBSan + tests + fault-shim (default compiler)
#   build-fuzz  — libFuzzer harnesses (clang only)
#
# Rationale: ERLKOENIG_BUILD_FUZZ is a hard error without Clang. Mixing
# both into one build dir means `make debug-test` on a gcc-only runner
# fails to configure. Separate dirs keep each tier's dependency clear.

configure-san:         ## Configure sanitizer+tests+fault-shim build (once)
	@test -f build-san/CMakeCache.txt || cmake -B build-san \
		-DCMAKE_BUILD_TYPE=Debug \
		-DERLKOENIG_SANITIZE=ON \
		-DERLKOENIG_BUILD_TESTS=ON \
		-DERLKOENIG_BUILD_TESTBIN=ON \
		-DERLKOENIG_BUILD_FAULT_SHIM=ON

configure-fuzz:        ## Configure clang-only fuzz build (once)
	@command -v clang >/dev/null 2>&1 || \
		{ echo "ERROR: clang is required for fuzz-smoke. Install clang or run on a Clang-capable runner." >&2; exit 1; }
	@test -f build-fuzz/CMakeCache.txt || cmake -B build-fuzz \
		-DCMAKE_C_COMPILER=clang \
		-DCMAKE_BUILD_TYPE=Debug \
		-DERLKOENIG_BUILD_FUZZ=ON \
		-DERLKOENIG_BUILD_GATEWAY=OFF \
		-DERLKOENIG_BUILD_TESTBIN=OFF

debug-test: configure-san  ## Build + run sanitizer-enabled C tests (sudo)
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

path-sweep: fault-shim     ## Path-filtered open fault sweep (sudo, slower)
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

# ── Boundary probes (defensive container-escape verification) ─
#
# A separate build dir (build-boundary) is used so the static-musl
# release build (build/) is not contaminated with the probe targets.
# The probes themselves are statically linked, like testbins.

configure-boundary:    ## Configure boundary-probe build (once)
	@test -f build-boundary/CMakeCache.txt || cmake -B build-boundary \
		-DCMAKE_C_COMPILER=musl-gcc \
		-DCMAKE_BUILD_TYPE=Release \
		-DERLKOENIG_BUILD_BOUNDARY=ON \
		-DERLKOENIG_BUILD_TESTBIN=ON

boundary-probes: configure-boundary  ## Build + run defensive boundary probes (sudo)
	cmake --build build-boundary -j$$(nproc)
	sudo ./test/boundary/run_boundary_probes.sh build-boundary

# ── Static Analysis ──────────────────────────────────────

lint: fmt-check        ## Static analysis

fmt-check:             ## Check code formatting
	clang-format --dry-run --Werror src/*.c include/*.h demo/*.c

# ── Install ──────────────────────────────────────────────

install: all           ## Install to system
	./scripts/install.sh

uninstall:             ## Remove installation
	./scripts/install.sh --uninstall

# ── Benchmark ────────────────────────────────────────────

bench: all             ## Benchmark container startup
	sudo ./scripts/bench-startup.sh

# ── Clean ────────────────────────────────────────────────

clean:                 ## Remove build artifacts
	rm -rf build/ build-san/ build-fuzz/ build-test/ build-tidy/ build-boundary/

# ── Help ─────────────────────────────────────────────────

help:                  ## Show targets
	@echo ""
	@awk -F ':|##' '/^[a-zA-Z_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$NF}' $(MAKEFILE_LIST)
	@echo ""

.DEFAULT_GOAL := all
