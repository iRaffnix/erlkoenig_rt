#!/bin/bash
#
# ek_path_sweep.sh — open() fault injection filtered by path substring.
# For each critical path, fire errno=12/13/28 on first open match and check
# for sanitizer findings, silent passes, hangs.

set -u

BUILD=${BUILD:-/root/rt-san/build/san}
ASAN_LIB=${ASAN_LIB:-/usr/lib/x86_64-linux-gnu/libasan.so.8}
SHIM=$BUILD/ek_fault_shim.so
TEST_BIN=$BUILD/test/test_container_setup

OUT=${OUT:-/tmp/path_sweep}
rm -rf "$OUT"
mkdir -p "$OUT"

PATHS="${*:-subtree_control cgroup.procs pids.max memory.max cpu.weight mountinfo ns/mnt ns/net}"
ERRNOS="${ERRNOS:-1 5 12 13 28}"
NTHS="${NTHS:-1 2 3}"

findings=0
silent=0
runs=0

for path in $PATHS; do
    for nth in $NTHS; do
        for er in $ERRNOS; do
            runs=$((runs + 1))
            sanitized=$(echo "$path" | tr -c '[:alnum:]' '_')
            log=$OUT/${sanitized}_n${nth}_e${er}.log

            timeout 30 systemd-run --scope --quiet -p Delegate=yes bash -c "
                scope=/sys/fs/cgroup\$(cat /proc/self/cgroup | sed 's|0::||')
                mkdir -p \$scope/ek.service/beam
                echo \$\$ > \$scope/ek.service/beam/cgroup.procs
                echo '+pids +memory +cpu' > \$scope/cgroup.subtree_control 2>/dev/null
                echo '+pids +memory +cpu' > \$scope/ek.service/cgroup.subtree_control 2>/dev/null
                EK_FAULT_SYSCALL=open EK_FAULT_NTH=$nth EK_FAULT_ERRNO=$er EK_FAULT_PATH=$path EK_FAULT_LOG=1 \
                LD_PRELOAD=$ASAN_LIB:$SHIM \
                ASAN_OPTIONS='abort_on_error=0:halt_on_error=0:detect_leaks=1:print_stacktrace=1' \
                exec $TEST_BIN
            " > "$log" 2>&1

            hits=$(grep -c '^\[FAULT\]' "$log")
            fails=$(grep -oE 'Failures: [0-9]+' "$log" | head -1 | grep -oE '[0-9]+')
            [ -z "$fails" ] && fails=?

            tag="$(printf 'path=%-20s n=%d e=%-3d' "$path" "$nth" "$er")"

            if grep -qE '==[0-9]+==ERROR: (Address|Undefined|Leak)Sanitizer' "$log"; then
                echo "  [BUG] $tag  hits=$hits fails=$fails  SANITIZER"
                findings=$((findings + 1))
            elif [ "$hits" = 0 ]; then
                : # path never opened — skip silently
            elif [ "$fails" = 0 ]; then
                echo "  [SILENT] $tag  hits=$hits fails=0 — fault fired, all tests passed"
                silent=$((silent + 1))
            else
                : # expected failure
            fi
        done
    done
done

echo
echo "=== summary ==="
echo "runs:          $runs"
echo "findings:      $findings   (sanitizer)"
echo "silent-passes: $silent"
echo "logs:          $OUT"
