#!/usr/bin/env bash
# One command: run the four banked hire-gap builds, their tests, and the
# fail-when-removed mutants against a capability-gate checkout. Box-only, offline.
# Usage: demos/hire/gap/RUN-ALL.sh  [CG_ROOT defaults to this checkout; PY defaults to python3 with requirements-dev]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
CG_ROOT="${CG_ROOT:-$(cd "$HERE/../../.." && pwd)}"; PY="${PY:-python3}"; export CG_ROOT
echo "capability-gate HEAD: $(git -C "$CG_ROOT" rev-parse HEAD)"
fail=0
"$PY" -c "import jsonschema" 2>/dev/null || { echo "RESULT: FAIL (jsonschema missing; install requirements-dev.txt, the meter and its mutant need it)"; exit 1; }
for s in training_tuesday.py adversary_scoreboard.py token_ledger.py mcp_refuse_wrapper.py shadow_enforce_meter.py; do
  echo; echo "== $s"; "$PY" "$s" || fail=1
done
echo; echo "== pytest (real)"; "$PY" -m pytest -q -p no:cacheprovider tests || fail=1
echo; echo "== mutants (each must turn the suite red)"
killed=0; total=0
for m in hollow-gate may-run-always kill-noop verify-noop ledger-no-cap ledger-repeat-stepback ledger-verify-noop wrapper-backend-first meter-validate-noop meter-self-promote; do
  total=$((total+1))
  if HIRE_GAP_MUTANT=$m "$PY" -m pytest -q -p no:cacheprovider tests -x >/dev/null 2>&1; then echo "  SURVIVED $m"; fail=1
  else echo "  KILLED   $m"; killed=$((killed+1)); fi
done
echo "MUTANTS KILLED $killed of $total"
[ "$fail" = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
exit $fail
