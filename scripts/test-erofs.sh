#!/bin/bash
# ---------------------------------------------------------------
# test-erofs.sh — Manual smoke tests for the EROFS mount stack.
#
# Run as root:  sudo ./test-erofs.sh
#
# Purpose:
#   Verify that the EROFS + OverlayFS rootfs path works end-to-end
#   before we remove the old tmpfs codepath. Each test restarts the
#   runtime (one erlkoenig_rt per container, no reuse after exit).
#
# What it does:
#   1. Builds three EROFS images from existing demo binaries
#   2. Spawns containers from those images via ek_rtctl
#   3. Checks output to verify the mount stack is correct
#
# Expected results:
#   Test 3 (hello_output):     stdout + stderr lines from container
#   Test 4 (rootfs read-only): write to / fails, write to /tmp works
#   Test 5 (spawn no image):   still works (tmpfs fallback, pre-refactor)
#                               → after refactor this MUST fail
#   Test 6 (stdin_echo):       container starts, prints "ready"
# ---------------------------------------------------------------
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$REPO/build}"
RT="$BUILD/erlkoenig_rt"
CTL="$BUILD/ek_rtctl"
SOCK="/tmp/ek-test.sock"
IMG="/tmp/test-hello.erofs"
IMG_STDIN="/tmp/test-stdin-echo.erofs"
IMG_ROOTFS="/tmp/test-rootfs-write.erofs"
TMPROOT="/tmp/ek-test-root"

# --- helpers ---------------------------------------------------

cleanup() {
    echo ""
    echo "--- cleanup ---"
    [ -S "$SOCK" ] && rm -f "$SOCK"
    [ -n "${RT_PID:-}" ] && kill "$RT_PID" 2>/dev/null && wait "$RT_PID" 2>/dev/null
    rm -rf "$TMPROOT"
    echo "done."
}
trap cleanup EXIT

# build_image <demo-binary-name> <output.erofs>
#
# Creates a minimal EROFS image with a single /app binary.
# EROFS is a read-only compressed filesystem (lz4). The image
# is later mounted as the lower layer of an OverlayFS stack
# inside the container namespace.
build_image() {
    local binary_name="$1"
    local output="$2"
    local src="$BUILD/testbin/test-erlkoenig-${binary_name}"

    if [ ! -f "$src" ]; then
        echo "SKIP: $src not found (run 'make' first)"
        return 1
    fi

    rm -rf "$TMPROOT" && mkdir -p "$TMPROOT"
    cp "$src" "$TMPROOT/app"
    chmod 555 "$TMPROOT/app"

    # Remove existing image — mkfs.erofs refuses to overwrite
    rm -f "$output"

    if ! mkfs.erofs -zlz4 "$output" "$TMPROOT/" 2>&1; then
        echo "FAIL: mkfs.erofs failed for $binary_name"
        return 1
    fi
    echo "  built: $output (from $binary_name)"
}

# start_runtime
#
# Starts a fresh erlkoenig_rt process with a unix socket.
# One runtime = one container. We restart between tests because
# after a container exits, the runtime returns to IDLE but some
# kernel state (loop devices, mounts) may linger.
start_runtime() {
    rm -f "$SOCK"
    "$RT" --socket "$SOCK" &
    RT_PID=$!

    # Poll for socket (max 5s)
    for i in $(seq 1 50); do
        [ -S "$SOCK" ] && break
        sleep 0.1
    done
    if [ ! -S "$SOCK" ]; then
        echo "FAIL: socket not created after 5s"
        exit 1
    fi
    echo "  runtime PID=$RT_PID, socket=$SOCK"
}

# stop_runtime
#
# Kills the current runtime and waits for it to exit.
stop_runtime() {
    kill "$RT_PID" 2>/dev/null && wait "$RT_PID" 2>/dev/null
    sleep 0.5
}

# ---------------------------------------------------------------
# 1. Build EROFS images
#
# Each image contains one static binary as /app. The runtime
# mounts it via:
#   loop device → EROFS (ro) → OverlayFS lower
#   tmpfs → OverlayFS upper (rw)
#   merged view → pivot_root → container sees single filesystem
# ---------------------------------------------------------------
echo "=== 1. Building EROFS images ==="
echo ""
echo "  Each image is a compressed read-only filesystem containing"
echo "  a single /app binary. The runtime mounts it as the immutable"
echo "  lower layer of an OverlayFS stack."
echo ""

build_image "hello_output"          "$IMG"
build_image "stdin_echo"            "$IMG_STDIN"
build_image "syscall_write_rootfs"  "$IMG_ROOTFS"

# ---------------------------------------------------------------
# 2. Test: basic lifecycle (EROFS → spawn → go → watch → exit)
#
# hello_output writes 3 lines to stdout, 1 to stderr, then exits.
# This verifies:
#   - EROFS image mounts correctly via loop device
#   - OverlayFS merges lower (EROFS) + upper (tmpfs)
#   - pivot_root into the merged view works
#   - execveat finds /app in the EROFS lower layer
#   - stdout/stderr forwarding through the runtime works
#   - container exit is reported via REPLY_EXITED
# ---------------------------------------------------------------
echo ""
echo "=== 2. Test: hello_output via EROFS ==="
echo ""
echo "  Expect: 3 stdout lines, 1 stderr line, then EXITED code=0"
echo ""

start_runtime
"$CTL" "$SOCK" spawn --path /app --image "$IMG"
"$CTL" "$SOCK" status
"$CTL" "$SOCK" go
echo ""
echo "  --- container output (5s timeout) ---"
timeout 5 "$CTL" "$SOCK" watch || true
stop_runtime

# ---------------------------------------------------------------
# 3. Test: read-only rootfs enforcement
#
# syscall_write_rootfs tries two writes:
#   1. open("/testfile", O_CREAT)  → MUST fail (EROFS lower is ro,
#      OverlayFS creates a whiteout but the file lands in upper —
#      however the rootfs is remounted ro after pivot_root, so
#      this should fail with EROFS or EACCES)
#   2. open("/tmp/testfile", O_CREAT) → MUST succeed (/tmp is on
#      the tmpfs upper layer, always writable)
#
# This verifies the two-layer separation:
#   lower (EROFS) = immutable, verified, compressed
#   upper (tmpfs) = writable scratch space
# ---------------------------------------------------------------
echo ""
echo "=== 3. Test: rootfs read-only (EROFS lower) ==="
echo ""
echo "  Expect: write to / FAILS, write to /tmp SUCCEEDS"
echo ""

start_runtime
"$CTL" "$SOCK" spawn --path /app --image "$IMG_ROOTFS"
"$CTL" "$SOCK" go
echo ""
echo "  --- container output (5s timeout) ---"
timeout 5 "$CTL" "$SOCK" watch || true
stop_runtime

# ---------------------------------------------------------------
# 4. Test: spawn WITHOUT --image (baseline before refactor)
#
# Current behavior: falls back to tmpfs + binary copy (old path).
# This test documents the pre-refactor state.
#
# AFTER the refactor (remove tmpfs path):
#   This MUST return REPLY_ERROR. If it still succeeds, the
#   refactor is incomplete — the old codepath is still active.
# ---------------------------------------------------------------
echo ""
echo "=== 4. Test: spawn WITHOUT --image (pre-refactor baseline) ==="
echo ""
echo "  Current: succeeds via tmpfs fallback"
echo "  After refactor: MUST fail with error"
echo ""

start_runtime
"$CTL" "$SOCK" spawn --path /bin/whatever || echo "  → got error (expected after refactor)"
stop_runtime

# ---------------------------------------------------------------
# 5. Test: stdin/stdout roundtrip via EROFS + PTY
#
# stdin_echo reads from stdin, prefixes each line with "echo: ",
# writes to stdout. Uses --pty for terminal mode.
#
# This verifies:
#   - PTY allocation works with EROFS rootfs
#   - stdin forwarding (CMD_STDIN) reaches the container
#   - stdout forwarding (REPLY_STDOUT) comes back
#
# Note: full stdin roundtrip needs interactive ek_rtctl shell mode.
# Here we only check that the container starts and prints "ready".
# A proper roundtrip test will be in the integration tests.
# ---------------------------------------------------------------
echo ""
echo "=== 5. Test: stdin_echo via EROFS + PTY ==="
echo ""
echo "  Expect: 'stdin_echo: ready' on stdout"
echo "  (full stdin roundtrip needs interactive mode → future tests)"
echo ""

start_runtime
"$CTL" "$SOCK" spawn --path /app --image "$IMG_STDIN" --pty
"$CTL" "$SOCK" go
echo ""
echo "  --- container output (3s timeout) ---"
timeout 3 "$CTL" "$SOCK" watch || true
stop_runtime

echo ""
echo "=== ALL TESTS COMPLETE ==="
