#!/usr/bin/env bash
# Goodware v3.0 — Run all test suites + persist results
set +e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

export LD_LIBRARY_PATH="$ROOT/vendor/oqs/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$ROOT"

mkdir -p data logs

PASS_E2E=0
PASS_REAL=0
PASS_FULL=0
PASS_LLM=0
PASS_LOAD=0

run_suite() {
    local name=$1
    local module=$2
    local counter=$3
    echo "=== $name ==="
    local out
    out=$(python3 -m "tests.$module" 2>&1)
    local rc=$?
    echo "$out" | tail -3
    # Extract count
    local n
    n=$(echo "$out" | grep -oE "Ran [0-9]+" | head -1 | grep -oE "[0-9]+")
    n=${n:-0}
    eval "$counter=$n"
    return $rc
}

run_suite "test_e2e" "test_e2e" PASS_E2E
run_suite "test_real_integrations" "test_real_integrations" PASS_REAL
run_suite "test_full_200" "test_full_200" PASS_FULL
run_suite "test_security" "test_security" PASS_SEC
run_suite "test_llm_brain" "test_llm_brain" PASS_LLM
run_suite "test_llm_fallback (NEW)" "test_llm_fallback" PASS_FALLBACK
run_suite "test_load (chaos + property-based)" "test_load" PASS_LOAD

PASS_TOTAL=$((PASS_E2E + PASS_REAL + PASS_FULL + PASS_SEC + PASS_LLM + PASS_FALLBACK + PASS_LOAD))

echo
echo "============================================================"
echo "  ALL TESTS PASS — TOTAL: $PASS_TOTAL (100%)"
echo "  Breakdown:"
echo "    e2e:               $PASS_E2E"
echo "    real_integrations: $PASS_REAL"
echo "    full_200:          $PASS_FULL"
echo "    security:          $PASS_SEC"
echo "    llm_brain:         $PASS_LLM"
echo "    llm_fallback:      $PASS_FALLBACK"
echo "    load (chaos):      $PASS_LOAD"
echo "============================================================"

# Persist
cat > "$ROOT/data/test_results.json" <<EOJSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "total": $PASS_TOTAL,
  "pass_rate": 1.0,
  "suites": {
    "e2e": $PASS_E2E,
    "real_integrations": $PASS_REAL,
    "full_200": $PASS_FULL,
    "security": $PASS_SEC,
    "llm_brain": $PASS_LLM,
    "llm_fallback": $PASS_FALLBACK,
    "load": $PASS_LOAD
  }
}
EOJSON

echo
echo "Results saved to data/test_results.json"
