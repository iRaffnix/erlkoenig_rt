#!/bin/bash
#
# ek_fault_sweep.sh — drive test_container_setup under systematic fault injection.
#
# For each (syscall, nth, errno) combo we run the whole test suite with the
# shim preloaded. Only sanitizer / crash signals are counted as findings;
# check-library assertion failures are expected when a syscall gets injected.
#
# Usage:
#   ./ek_fault_sweep.sh             # default sweep (~10 minutes)
#   ./ek_fault_sweep.sh <syscalls>  # restrict to named syscalls

set -u

BUILD=${BUILD:-/root/rt-san/build/san}
ASAN_LIB=${ASAN_LIB:-/usr/lib/x86_64-linux-gnu/libasan.so.8}
UBSAN_LIB=${UBSAN_LIB:-/usr/lib/x86_64-linux-gnu/libubsan.so.1}
SHIM=$BUILD/ek_fault_shim.so
TEST_BIN=$BUILD/test/test_container_setup

OUT=${OUT:-/tmp/fault_sweep}
rm -rf "$OUT"
mkdir -p "$OUT"

SYSCALLS="${*:-mount umount2 mkdir chdir symlink unshare rmdir pivot_root setns}"
NTHS="${NTHS:-1 2 3 4 5}"
ERRNOS="${ERRNOS:-12}"      # 12=ENOMEM. expand: 1=EPERM 28=ENOSPC 4=EINTR

findings=0
expected_fail=0
expected_ok=0
runs=0

echo "=== ek_fault_sweep — $(date -Is) ==="
echo "syscalls: $SYSCALLS"
echo "nths:     $NTHS"
echo "errnos:   $ERRNOS"
echo "output:   $OUT"
echo

for sc in $SYSCALLS; do
    for nth in $NTHS; do
        for er in $ERRNOS; do
            runs=$((runs + 1))
            tag="${sc}_n${nth}_e${er}"
            log="$OUT/$tag.log"

            # Run test inside a fresh delegated scope so cgroup tests don't skip.
            timeout 45 systemd-run --scope --quiet -p Delegate=yes bash -c "
                scope=/sys/fs/cgroup\$(cat /proc/self/cgroup | sed 's|0::||')
                mkdir -p \$scope/ek.service/beam
                echo \$\$ > \$scope/ek.service/beam/cgroup.procs
                echo '+pids +memory +cpu' > \$scope/cgroup.subtree_control 2>/dev/null
                echo '+pids +memory +cpu' > \$scope/ek.service/cgroup.subtree_control 2>/dev/null
                EK_FAULT_SYSCALL=$sc EK_FAULT_NTH=$nth EK_FAULT_ERRNO=$er EK_FAULT_LOG=1 \
                LD_PRELOAD=$ASAN_LIB:$UBSAN_LIB:$SHIM \
                ASAN_OPTIONS='abort_on_error=0:halt_on_error=0:detect_leaks=1:print_stacktrace=1:exitcode=66' \
                UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=0:exitcode=67' \
                exec $TEST_BIN
            " > "$log" 2>&1
            rc=$?

            # Classify
            san=""
            if grep -qE '==[0-9]+==ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)' "$log"; then
                san="ASAN/UBSAN"
            fi
            if grep -qE '^==[0-9]+==ABORTING|runtime error:|SUMMARY: (Address|Undefined|Leak)Sanitizer' "$log"; then
                san="${san}+SUMMARY"
            fi

            fault_hits=$(grep -c '^\[FAULT\]' "$log" || true)

            if [ -n "$san" ]; then
                echo "  [BUG] $tag  rc=$rc  $san  (hits=$fault_hits)"
                findings=$((findings + 1))
            elif [ "$rc" = 124 ]; then
                echo "  [HANG] $tag  timeout"
                findings=$((findings + 1))
            elif [ "$rc" -ge 128 ] && [ "$rc" != 143 ]; then
                # signal death that isn't SIGTERM (which we'd get on timeout kill -15)
                echo "  [CRASH] $tag  signal=$((rc - 128))"
                findings=$((findings + 1))
            elif [ "$fault_hits" = 0 ]; then
                expected_ok=$((expected_ok + 1))
            else
                expected_fail=$((expected_fail + 1))
            fi
        done
    done
done

echo
echo "=== summary ==="
echo "runs:          $runs"
echo "findings:      $findings     (sanitizer / hang / crash)"
echo "expected_fail: $expected_fail (fault fired, test failed as expected)"
echo "expected_ok:   $expected_ok   (fault never fired — nth too high)"
echo "logs:          $OUT"
