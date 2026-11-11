#!/usr/bin/env bash
#
# mayhem/test.sh — RUN zapret2's OWN Lua self-tests (lua/zapret-tests.lua) through the pre-built driver.
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

DRIVER="$SRC/mayhem/build/test_driver"
if [ ! -x "$DRIVER" ]; then
  echo "test.sh: $DRIVER is missing — mayhem/build.sh should have built it" >&2
  emit_ctrf "zapret-tests.lua" 0 1 0
  exit 1
fi

OUT="$(mktemp "${TMPDIR:-/tmp}/zapret2-test.XXXXXX")"
trap 'rm -f "$OUT"' EXIT
# The driver prints one "TEST <name> PASS|FAIL ..." line per upstream test / known-answer check
# and a final "SUMMARY" line; a program that just exits 0 produces none of them.
ZAPRET_LUA_DIR="$SRC/lua" timeout 600 "$DRIVER" > "$OUT" 2>&1
rc=$?

passed=$(grep -c '^TEST [A-Za-z0-9_]* PASS' "$OUT")
failed=$(grep -c '^TEST [A-Za-z0-9_]* FAIL' "$OUT")
grep -E '^(TEST|SUMMARY)' "$OUT"

EXPECTED=20   # 16 upstream tests + 4 known-answer checks
if [ "$rc" -ne 0 ]; then
  echo "test.sh: driver exited with $rc" >&2; tail -20 "$OUT" >&2; failed=$((failed + 1))
fi
if ! grep -q '^SUMMARY failed=0$' "$OUT"; then
  echo "test.sh: missing 'SUMMARY failed=0' marker" >&2; failed=$((failed + 1))
fi
if [ $((passed + failed)) -lt "$EXPECTED" ]; then
  echo "test.sh: only $((passed + failed)) of $EXPECTED tests reported" >&2; failed=$((failed + 1))
fi
emit_ctrf "zapret-tests.lua" "$passed" "$failed" 0
