#!/usr/bin/env bash
#
# mayhem/test.sh — RUN syslog-ng's own criterion unit tests plus a known-answer probe (both built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
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

BT="$SRC/mayhem/build-test"
passed=0; failed=0

# Each unit-test binary is a criterion runner; its final "Synthesis" line carries the counts. A binary that
# is missing, exits early (no Synthesis line) or reports failures/crashes counts as failed.
UNIT_TESTS=(
  lib/tests/test_msgparse
  lib/logmsg/tests/test_nvtable
  lib/logmsg/tests/test_log_message
  lib/logmsg/tests/test_logmsg_serialize
  lib/logproto/tests/test_logproto
  modules/syslogformat/tests/test_syslog_format
  modules/correlation/tests/test_radix
  modules/correlation/tests/test_parsers
)
for t in "${UNIT_TESTS[@]}"; do
  bin="$BT/$t"
  if [ ! -x "$bin" ]; then echo "MISSING test binary $bin (build.sh bug)" >&2; failed=$((failed + 1)); continue; fi
  out=$(cd "$(dirname "$bin")" && timeout 600 "./$(basename "$bin")" 2>&1); rc=$?
  line=$(printf '%s\n' "$out" | grep -E 'Synthesis: Tested: [0-9]+' | tail -1)
  if [ -z "$line" ]; then echo "FAIL $t: no Synthesis line (rc=$rc)" >&2; printf '%s\n' "$out" | tail -5 >&2; failed=$((failed + 1)); continue; fi
  tested=$(sed -E 's/.*Tested: ([0-9]+).*/\1/' <<<"$line")
  pass=$(sed -E 's/.*Passing: ([0-9]+).*/\1/' <<<"$line")
  fail=$(sed -E 's/.*Failing: ([0-9]+).*/\1/' <<<"$line")
  crash=$(sed -E 's/.*Crashing: ([0-9]+).*/\1/' <<<"$line")
  echo "$t: tested=$tested passing=$pass failing=$fail crashing=$crash rc=$rc"
  if [ "$tested" -gt 0 ] && [ "$pass" -eq "$tested" ] && [ "$fail" -eq 0 ] && [ "$crash" -eq 0 ] && [ "$rc" -eq 0 ]; then
    passed=$((passed + pass))
  else
    failed=$((failed + 1 + fail + crash))
  fi
done

# Known-answer probe: drives the real parser, serializer, radix tree and framed protocol and prints the results.
# stdout only (the library logs to stderr). Every expected line must be present verbatim.
KAT="$BT/kat_probe"
EXPECTED=(
  parse_ok=1 pri=165 host=mymachine.example.com program=evntslog msgid=ID47 sd_iut=3
  "message=An application event log entry"
  deserialize_ok=1 pri2=165 host2=mymachine.example.com sd_event2=Application
  "message2=An application event log entry"
  radix=rule1 radix_user=alice radix_ip=10.1.2.3 radix_port=2222
  frame0=hello "frame1=world!!!!!!" frame2_status=2
)
if [ ! -x "$KAT" ]; then
  echo "MISSING $KAT (build.sh bug)" >&2; failed=$((failed + 1))
else
  kat_out=$(timeout 120 "$KAT" 2>/dev/null) || echo "kat_probe exited non-zero" >&2
  for want in "${EXPECTED[@]}"; do
    if printf '%s\n' "$kat_out" | grep -qxF -- "$want"; then passed=$((passed + 1))
    else echo "KAT FAIL: expected line '$want'" >&2; failed=$((failed + 1)); fi
  done
fi

emit_ctrf "syslog-ng-criterion+kat" "$passed" "$failed" 0
