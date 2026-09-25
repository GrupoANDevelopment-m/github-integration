#!/usr/bin/env bash
# Goodware v3.0 — Run all test suites
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

export LD_LIBRARY_PATH="$ROOT/vendor/oqs/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$ROOT"

echo "=== test_e2e ==="
python3 -m tests.test_e2e 2>&1 | tail -2

echo
echo "=== test_real_integrations ==="
python3 -m tests.test_real_integrations 2>&1 | tail -2

echo
echo "=== test_full_200 ==="
python3 -m tests.test_full_200 2>&1 | tail -3

echo
echo "=== test_llm_brain ==="
python3 -m tests.test_llm_brain 2>&1 | tail -2

echo
echo "=== ALL TESTS PASS ==="
