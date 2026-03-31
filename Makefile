# erlkoenig_rt — Privileged C runtime for erlkoenig containers.
#
# Build:  make
# Test:   make test
# Clean:  make clean

.PHONY: all test test-rt clean install uninstall help

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
	rm -rf build/ build-san/ build-test/ build-tidy/

# ── Help ─────────────────────────────────────────────────

help:                  ## Show targets
	@echo ""
	@awk -F ':|##' '/^[a-zA-Z_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$NF}' $(MAKEFILE_LIST)
	@echo ""

.DEFAULT_GOAL := all
