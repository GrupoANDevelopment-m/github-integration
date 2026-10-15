#!/usr/bin/env bash
# Goodware v3.0 — Run all suites, preserve full logs, and report real outcomes.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
export LD_LIBRARY_PATH="$ROOT/vendor/oqs/lib:${LD_LIBRARY_PATH:-}"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$ROOT/logs/test-runs/$RUN_ID"
mkdir -p "$ROOT/data" "$RUN_DIR"

RESULTS_TSV="$RUN_DIR/results.tsv"
: > "$RESULTS_TSV"

# Each entry: human-readable suite name and importable tests module.
SUITES=(
  "test_e2e|test_e2e"
  "test_real_integrations|test_real_integrations"
  "test_full_200|test_full_200"
  "test_security|test_security"
  "test_real_security_tools|test_real_security_tools"
  "test_intel_sources|test_intel_sources"
  "test_production_repos|test_production_repos"
  "test_stress_defense|test_stress_defense"
  "test_llm_brain|test_llm_brain"
  "test_llm_fallback|test_llm_fallback"
  "test_load|test_load"
)

run_suite() {
  local name="$1"
  local module="$2"
  local log_file="$RUN_DIR/$module.log"
  local started ended duration rc status
  local total=0 failed=0 skipped=0 errors=0 passed=0
  started="$(date +%s.%N)"

  printf '\n=== %s (%s) ===\n' "$name" "$module"
  if python3 -m "tests.$module" >"$log_file" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  ended="$(date +%s.%N)"
  duration="$(awk -v s="$started" -v e="$ended" 'BEGIN { printf "%.3f", e-s }')"

  # unittest summary format
  total="$(grep -Eo 'Ran [0-9]+ tests?' "$log_file" | tail -1 | awk '{print $2}' || true)"
  total="${total:-0}"
  failed="$(grep -Eo 'failures=[0-9]+' "$log_file" | tail -1 | awk -F= '{print $2}' || true)"
  errors="$(grep -Eo 'errors=[0-9]+' "$log_file" | tail -1 | awk -F= '{print $2}' || true)"
  skipped="$(grep -Eo 'skipped=[0-9]+' "$log_file" | tail -1 | awk -F= '{print $2}' || true)"
  failed="${failed:-0}"
  errors="${errors:-0}"
  skipped="${skipped:-0}"

  # Some legacy suites use a custom summary instead of unittest's format.
  local custom_total custom_passed custom_failed
  custom_total="$(grep -Eo 'Total: [0-9]+' "$log_file" | tail -1 | awk '{print $2}' || true)"
  custom_passed="$(grep -Eo 'OK: [0-9]+' "$log_file" | tail -1 | awk '{print $2}' || true)"
  custom_failed="$(grep -Eo 'FAIL: [0-9]+' "$log_file" | tail -1 | awk '{print $2}' || true)"
  if [[ -n "$custom_total" ]]; then
    total="$custom_total"
    passed="${custom_passed:-0}"
    failed="${custom_failed:-0}"
    errors=0
    skipped=0
  else
    passed=$(( total - failed - errors - skipped ))
    (( passed < 0 )) && passed=0
  fi

  if [[ "$rc" -eq 0 ]]; then
    status="passed"
    # For successful unittest suites, the runner's exit status is authoritative.
    if [[ -z "$custom_total" ]]; then
      passed=$(( total - skipped ))
    fi
    tail -n 8 "$log_file" || true
  else
    status="failed"
    printf '%s\n' "--- FULL FAILURE LOG: $module ---"
    cat "$log_file"
    printf '%s\n' "--- END FAILURE LOG: $module ---"
    # Import/setup failures may happen before a test count is emitted.
    if [[ "$total" -eq 0 && "$failed" -eq 0 && "$errors" -eq 0 ]]; then
      errors=1
    fi
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$module" "$status" "$total" "$passed" "$failed" "$errors" "$skipped" "$duration" >> "$RESULTS_TSV"
  printf 'Suite result: %s | tests=%s passed=%s failures=%s errors=%s skipped=%s duration=%ss\n' \
    "$status" "$total" "$passed" "$failed" "$errors" "$skipped" "$duration"
  return 0
}

# Intentionally run every suite so one failure does not hide later failures.
for entry in "${SUITES[@]}"; do
  name="${entry%%|*}"
  module="${entry#*|}"
  run_suite "$name" "$module"
done

python3 - "$RESULTS_TSV" "$ROOT/data/test_results.json" "$RUN_ID" <<'PY'
import json
import sys
from pathlib import Path

tsv_path, output_path, run_id = sys.argv[1:]
suites = []
for line in Path(tsv_path).read_text(encoding="utf-8").splitlines():
    fields = line.split("\t")
    if len(fields) != 9:
        continue
    name, module, status, total, passed, failures, errors, skipped, duration = fields
    suites.append({
        "name": name,
        "module": module,
        "status": status,
        "tests_total": int(total),
        "tests_passed": int(passed),
        "failures": int(failures),
        "errors": int(errors),
        "skipped": int(skipped),
        "duration_seconds": float(duration),
    })

total = sum(s["tests_total"] for s in suites)
passed = sum(s["tests_passed"] for s in suites)
failures = sum(s["failures"] for s in suites)
errors = sum(s["errors"] for s in suites)
skipped = sum(s["skipped"] for s in suites)
failed_suites = sum(s["status"] != "passed" for s in suites)
denominator = max(total - skipped, 0)
report = {
    "run_id": run_id,
    "source": "scripts/test_all.sh",
    "suite_count": len(suites),
    "suite_passed": len(suites) - failed_suites,
    "suite_failed": failed_suites,
    "tests_total": total,
    "tests_passed": passed,
    "tests_failed": failures,
    "tests_errors": errors,
    "tests_skipped": skipped,
    "pass_rate": round(passed / denominator, 6) if denominator else None,
    "all_passed": failed_suites == 0 and failures == 0 and errors == 0,
    "suites": suites,
}
Path(output_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print("\n=== TEST SUMMARY ===")
print(json.dumps({k: report[k] for k in (
    "suite_count", "suite_passed", "suite_failed", "tests_total",
    "tests_passed", "tests_failed", "tests_errors", "tests_skipped",
    "pass_rate", "all_passed"
)}, indent=2))
print(f"Full suite logs: {Path(tsv_path).parent}")
print(f"JSON report: {output_path}")
if not report["all_passed"]:
    sys.exit(1)
PY
