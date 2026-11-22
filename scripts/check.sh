#!/usr/bin/env bash
# Runs the full check: tests, benchmark gate, and the three weakened-policy drills.
# Results go to reports/scratch/check (ignored by Git), so the final results stay untouched.
set -u
cd "$(dirname "$0")/.."
PY=${PYTHON:-python}
OUT=reports/scratch/check
mkdir -p "$OUT"
fail=0

echo "== 1. Unit and config tests"
$PY -m pytest -q || fail=1

echo
echo "== 2. Real policy must pass the gate"
$PY -m runner.benchmark --model-mode scripted --repeats 3 \
  --max-attack-success 0 --results-dir "$OUT" | tail -3
[ "${PIPESTATUS[0]}" -eq 0 ] || fail=1

echo
echo "== 3. Weakened policies must be detected"
for p in no_taint narrow_taint no_redaction; do
  out=$($PY -m runner.benchmark --model-mode scripted \
    --policy config/regressions/$p.yaml \
    --max-attack-success 0 --results-dir "$OUT" || true)
  if echo "$out" | grep -q "GATE: FAIL"; then
    echo "  detected:     $p"
  else
    echo "  NOT DETECTED: $p"; fail=1
  fi
done

echo
if [ "$fail" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "CHECKS FAILED"; exit 1; fi
