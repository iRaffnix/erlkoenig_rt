#!/bin/bash
# bench-startup.sh — Measure container startup time.
#
# Measures three phases:
#   1. SPAWN: clone + rootfs setup + pivot_root + ready_pipe
#   2. GO:    execve + first output
#   3. TOTAL: spawn → container exit
#
# Uses hello_output which prints to stdout and exits immediately.
# Runs N iterations and reports min/avg/max/p50/p99.
#
# Run as root:  sudo ./scripts/bench-startup.sh [iterations]

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RT="$REPO/build/erlkoenig_rt"
CTL="$REPO/build/ek_rtctl"
IMG="/tmp/bench-hello.erofs"
ITERATIONS="${1:-20}"

# Find demo binary
HELLO=""
for p in "$REPO/build/testbin/test-erlkoenig-hello_output" \
         "$REPO/build/demo/test-erlkoenig-hello_output"; do
    [ -f "$p" ] && HELLO="$p" && break
done
[ -z "$HELLO" ] && { echo "error: hello_output not found (run 'make')"; exit 1; }

# Build image if needed
if [ ! -f "$IMG" ]; then
    TMPROOT=$(mktemp -d)
    cp "$HELLO" "$TMPROOT/app"
    chmod 555 "$TMPROOT/app"
    mkfs.erofs -zlz4 "$IMG" "$TMPROOT/" 2>/dev/null
    rm -rf "$TMPROOT"
    echo "built: $IMG"
fi

# Verify binaries exist
[ -f "$RT" ] || { echo "error: $RT not found (run 'make')"; exit 1; }
[ -f "$CTL" ] || { echo "error: $CTL not found (run 'make')"; exit 1; }

# Results arrays
declare -a SPAWN_TIMES GO_TIMES TOTAL_TIMES

echo "=== erlkoenig_rt startup benchmark ==="
echo ""
echo "  runtime:    $RT"
echo "  ctl:        $CTL"
echo "  image:      $IMG ($(stat -c%s "$IMG") bytes)"
echo "  container:  hello_output (3 stdout lines, exits immediately)"
echo "  iterations: $ITERATIONS"
echo ""

for i in $(seq 1 "$ITERATIONS"); do
    SOCK=$(mktemp -u /tmp/ek-bench-XXXXXX.sock)

    # Start runtime
    "$RT" --socket "$SOCK" 2>/dev/null &
    RT_PID=$!

    # Wait for socket
    for _ in $(seq 1 100); do
        [ -S "$SOCK" ] && break
        sleep 0.01
    done
    if [ ! -S "$SOCK" ]; then
        echo "  [$i] FAIL: socket not ready"
        kill "$RT_PID" 2>/dev/null; wait "$RT_PID" 2>/dev/null
        continue
    fi

    # --- Measure SPAWN ---
    T0=$(date +%s%N)

    SPAWN_OUT=$("$CTL" "$SOCK" spawn --path /app --image "$IMG" 2>&1)
    SPAWN_RC=$?

    T1=$(date +%s%N)

    if [ $SPAWN_RC -ne 0 ]; then
        echo "  [$i] FAIL: spawn: $SPAWN_OUT"
        kill "$RT_PID" 2>/dev/null; wait "$RT_PID" 2>/dev/null
        rm -f "$SOCK"
        continue
    fi

    SPAWN_NS=$((T1 - T0))
    SPAWN_MS=$((SPAWN_NS / 1000000))

    # --- Measure GO + first output + exit ---
    T2=$(date +%s%N)

    "$CTL" "$SOCK" go >/dev/null 2>&1
    "$CTL" "$SOCK" watch >/dev/null 2>&1 || true

    T3=$(date +%s%N)

    GO_NS=$((T3 - T2))
    GO_MS=$((GO_NS / 1000000))

    TOTAL_NS=$((T3 - T0))
    TOTAL_MS=$((TOTAL_NS / 1000000))

    SPAWN_TIMES+=("$SPAWN_MS")
    GO_TIMES+=("$GO_MS")
    TOTAL_TIMES+=("$TOTAL_MS")

    printf "  [%2d] spawn=%3dms  go+exit=%3dms  total=%3dms\n" \
        "$i" "$SPAWN_MS" "$GO_MS" "$TOTAL_MS"

    # Cleanup
    kill "$RT_PID" 2>/dev/null; wait "$RT_PID" 2>/dev/null
    rm -f "$SOCK"
done

echo ""

# --- Statistics ---
calc_stats() {
    local name="$1"
    shift
    local -a vals=("$@")
    local n=${#vals[@]}

    if [ "$n" -eq 0 ]; then
        echo "  $name: no data"
        return
    fi

    IFS=$'\n' sorted=($(sort -n <<<"${vals[*]}")); unset IFS

    local min=${sorted[0]}
    local max=${sorted[$((n-1))]}
    local p50=${sorted[$((n/2))]}
    local p99_idx=$(( (n * 99 + 99) / 100 - 1 ))
    [ "$p99_idx" -ge "$n" ] && p99_idx=$((n-1))
    local p99=${sorted[$p99_idx]}

    local sum=0
    for v in "${vals[@]}"; do
        sum=$((sum + v))
    done
    local avg=$((sum / n))

    printf "  %-12s  min=%3dms  avg=%3dms  p50=%3dms  p99=%3dms  max=%3dms  (n=%d)\n" \
        "$name" "$min" "$avg" "$p50" "$p99" "$max" "$n"
}

echo "=== Results ==="
echo ""
calc_stats "spawn" "${SPAWN_TIMES[@]}"
calc_stats "go+exit" "${GO_TIMES[@]}"
calc_stats "total" "${TOTAL_TIMES[@]}"
echo ""
echo "spawn:    clone + EROFS mount + OverlayFS + pivot_root + ready_pipe"
echo "go+exit:  execve + container runs + stdout + exit + reap"
echo "total:    spawn + go+exit (full lifecycle)"
