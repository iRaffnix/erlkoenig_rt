#!/bin/bash
#
# run_boundary_probes.sh — defensive boundary probe harness
#
# For each probe binary under build-boundary/test/boundary/probe_*,
# spawn it as an erlkoenig container under the appropriate seccomp
# profile via the single-connection driver run_probe_one (which
# avoids the buffered-REPLY_EXITED race that plagues the 3-call
# ek_rtctl flow).
#
# Profile mapping by filename:
#   probe_seccomp_strict__*    → 2 (STRICT, allowlist)
#   probe_seccomp_network__*   → 3 (NETWORK)
#   anything else              → 1 (DEFAULT, denylist)
#
# Expected outcome by filename:
#   probe_*__*_killed.c         → expects SIGSYS kill (signal=31)
#   probe_*__positive_control.c → expects exit=0
#   anything else               → expects exit=0
#
# Usage:
#   sudo ./run_boundary_probes.sh [BUILD_DIR]
#   BUILD_DIR defaults to ./build-boundary
#
# Exit code: 0 if all probes PASS or SKIP, 1 if any FAIL.

set -u

BUILD_DIR="${1:-build-boundary}"
RT_BIN="${BUILD_DIR}/erlkoenig_rt"
DRV_BIN="${BUILD_DIR}/test/boundary/run_probe_one"
PROBE_DIR="${BUILD_DIR}/test/boundary"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo $0 ...)" >&2
    exit 2
fi

for f in "$RT_BIN" "$DRV_BIN"; do
    if [ ! -x "$f" ]; then
        echo "ERROR: $f not found or not executable" >&2
        echo "       Build with: cmake -B $BUILD_DIR -DERLKOENIG_BUILD_BOUNDARY=ON" >&2
        exit 2
    fi
done

if [ -z "$(ls "$PROBE_DIR"/probe_* 2>/dev/null)" ]; then
    echo "ERROR: no probes in $PROBE_DIR" >&2
    exit 2
fi

profile_for() {
    case "$1" in
        probe_seccomp_strict__*)  echo 2 ;;
        probe_seccomp_network__*) echo 3 ;;
        *)                        echo 1 ;;
    esac
}

expected_for() {
    case "$1" in
        *_killed) echo killed ;;
        *)        echo exit ;;
    esac
}

PASS=0
FAIL=0
SKIP=0
FAIL_NAMES=()

run_one() {
    local probe
    probe="$(readlink -f "$1")"
    local name
    name="$(basename "$probe")"
    local profile expected
    profile="$(profile_for "$name")"
    expected="$(expected_for "$name")"

    local sock="/run/ek_probe_$$_$RANDOM.sock"
    local rtlog="/tmp/ek_probe_rt_$$_$RANDOM.log"
    rm -f "$sock"

    "$RT_BIN" --socket "$sock" --id "$name" >"$rtlog" 2>&1 &
    local rt_pid=$!

    # Wait for socket (≤ 2 s).
    local i=0
    while [ ! -S "$sock" ] && [ $i -lt 40 ]; do
        sleep 0.05
        i=$((i + 1))
    done
    if [ ! -S "$sock" ]; then
        echo "FAIL  $name :: runtime socket never appeared"
        echo "---- runtime stderr ----"
        cat "$rtlog" 2>/dev/null | sed 's/^/    /'
        echo "---- end ----"
        kill -KILL "$rt_pid" 2>/dev/null
        rm -f "$rtlog" "$sock"
        FAIL=$((FAIL + 1))
        FAIL_NAMES+=("$name")
        return
    fi

    # Single-connection driver. Captures stdout (parseable result) and
    # stderr (probe FINDING/OK/SKIP text + driver errors).
    local out err drv_rc
    out="$("$DRV_BIN" --socket "$sock" --probe "$probe" \
                       --profile "$profile" --timeout-ms 15000 2>/tmp/.ekprobe_err.$$)"
    drv_rc=$?
    err="$(cat /tmp/.ekprobe_err.$$ 2>/dev/null)"
    rm -f /tmp/.ekprobe_err.$$

    # Tear down runtime — KILL only, don't wait().
    kill -KILL "$rt_pid" 2>/dev/null
    rm -f "$rtlog" "$sock"

    local exit_code signal
    exit_code="$(echo "$out" | grep -oE 'exit_code=-?[0-9]+' | head -1 | sed 's/exit_code=//')"
    signal="$(echo "$out" | grep -oE 'term_signal=[0-9]+' | head -1 | sed 's/term_signal=//')"

    local verdict reason
    if [ "$drv_rc" -eq 3 ]; then
        verdict=FAIL
        reason="probe never delivered REPLY_EXITED within 15 s"
    elif [ "$drv_rc" -ne 0 ]; then
        verdict=FAIL
        reason="driver error rc=$drv_rc: $err"
    elif [ -z "${exit_code:-}" ]; then
        verdict=FAIL
        reason="driver did not report exit_code"
    elif [ "$expected" = killed ]; then
        if [ "${signal:-0}" = "31" ]; then
            verdict=PASS
            reason="killed by SIGSYS as expected"
        elif [ "${exit_code:-0}" = "77" ]; then
            verdict=SKIP
            reason="$(echo "$err" | grep -m1 SKIP || echo 'probe SKIP')"
        else
            verdict=FAIL
            reason="expected SIGSYS kill, got exit_code=$exit_code term_signal=$signal"
        fi
    else
        if [ "${exit_code:-99}" = "0" ]; then
            verdict=PASS
            reason="$(echo "$err" | grep -m1 ^OK | head -1 || echo 'exit_code=0')"
        elif [ "${exit_code:-0}" = "77" ]; then
            verdict=SKIP
            reason="$(echo "$err" | grep -m1 SKIP || echo 'probe SKIP')"
        else
            verdict=FAIL
            reason="exit_code=$exit_code term_signal=$signal"
        fi
    fi

    case "$verdict" in
        PASS) PASS=$((PASS + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)); FAIL_NAMES+=("$name") ;;
    esac

    printf '%-5s %s :: %s\n' "$verdict" "$name" "$reason"

    if [ "$verdict" = FAIL ]; then
        echo "---- driver stderr ----"
        echo "$err" | sed 's/^/    /'
        echo "---- driver stdout ----"
        echo "$out" | sed 's/^/    /'
        echo "---- end ----"
    fi
}

echo "=== boundary probes (build=$BUILD_DIR, kernel=$(uname -r)) ==="

for probe in $(ls "$PROBE_DIR"/probe_* | sort); do
    [ -x "$probe" ] || continue
    run_one "$probe"
done

echo
echo "=== summary ==="
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if [ $FAIL -gt 0 ]; then
    echo "FAILED probes:"
    for n in "${FAIL_NAMES[@]}"; do
        echo "  - $n"
    done
fi

exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
