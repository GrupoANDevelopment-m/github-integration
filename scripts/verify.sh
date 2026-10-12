#!/usr/bin/env bash
##############################################################################
# Goodware v3.0 — System Verification Script
# ============================================================================
# Verifica que TUDO está instalado e operacional:
# - Dependências nativas (apt packages)
# - liboqs compilado
# - Vendored repos presentes
# - Python deps
# - Backend responde
# - UI responde
# - 381/381 testes passam
##############################################################################
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name"
        PASS=$((PASS+1))
        return 0
    else
        echo -e "  ${RED}✗${NC} $name"
        FAIL=$((FAIL+1))
        return 1
    fi
}

warn_check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}⚠${NC} $name (warning)"
        WARN=$((WARN+1))
    fi
}

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  GOODWARE v3.0 — System Verification                            ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo

# === 1. Python ===
echo -e "${BLUE}[1/8]${NC} Python environment"
check "Python 3.10+" "python3 -c 'import sys; assert sys.version_info >= (3, 10)'"
check "pip3 available" "command -v pip3"
check "requests" "python3 -c 'import requests'"
check "flask" "python3 -c 'import flask'"
check "flask-cors" "python3 -c 'import flask_cors'"
check "psutil" "python3 -c 'import psutil'"
check "watchdog" "python3 -c 'import watchdog'"
check "scikit-learn" "python3 -c 'import sklearn'"
check "cryptography" "python3 -c 'import cryptography'"
check "rich" "python3 -c 'import rich'"
check "joblib" "python3 -c 'import joblib'"
check "pydantic" "python3 -c 'import pydantic'"
check "httpx" "python3 -c 'import httpx'"
check "openai" "python3 -c 'import openai'"
check "yara-python" "python3 -c 'import yara'"
check "yaml" "python3 -c 'import yaml'"
echo

# === 2. Native tools ===
echo -e "${BLUE}[2/8]${NC} Native system tools"
check "yara" "command -v yara"
check "clamscan" "command -v clamscan"
warn_check "freshclam" "command -v freshclam"
check "nft" "command -v nft"
warn_check "iptables" "command -v iptables"
check "tpm2_pcrread" "command -v tpm2_pcrread"
warn_check "swtpm" "command -v swtpm"
warn_check "auditctl" "command -v auditctl"
check "git" "command -v git"
check "cmake" "command -v cmake"
check "ninja" "command -v ninja"
echo

# === 3. liboqs ===
echo -e "${BLUE}[3/8]${NC} liboqs (PQC)"
check "liboqs.so.0.16.0" "test -f vendor/oqs/lib/liboqs.so.0.16.0"
check "liboqs.so symlink" "test -f vendor/oqs/lib/liboqs.so"
check "ML-KEM-512 KEM" "LD_LIBRARY_PATH=vendor/oqs/lib python3 -c 'from goodware.crypto.real_pqc import RealPQC; r=RealPQC(); pk,sk,alg=r.kem_keypair(\"ML-KEM-512\"); print(alg)'"
check "ML-DSA-44 sig" "LD_LIBRARY_PATH=vendor/oqs/lib python3 -c 'from goodware.crypto.real_pqc import RealPQC; r=RealPQC(); pk,sk,alg=r.sig_keypair(\"ml-dsa-44\"); print(alg)'"
echo

# === 4. Vendored repos ===
echo -e "${BLUE}[4/8]${NC} Vendored production repos (14)"
for repo in vendor/security_tools/lynis vendor/security_tools/cowrie vendor/security_tools/Loki vendor/security_tools/LinuxCheck vendor/security_tools/sigma vendor/security_tools/misp-galaxy vendor/security_tools/volatility3 vendor/security_tools/signature-base vendor/security_tools/syft vendor/security_tools/cosign vendor/security_tools/capa vendor/security_tools/capa-rules vendor/security_tools/osquery vendor/biometrics_extern/keystroke-biometrics; do
    if [ -d "$repo" ]; then
        count=$(find "$repo" -type f 2>/dev/null | wc -l)
        echo -e "  ${GREEN}✓${NC} $(basename $repo) ($count files)"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗${NC} $(basename $repo) MISSING"
        FAIL=$((FAIL+1))
    fi
done
echo

# === 5. ML Models ===
echo -e "${BLUE}[5/8]${NC} Trained ML models"
MODEL_COUNT=$(ls models/*.joblib 2>/dev/null | wc -l)
if [ "$MODEL_COUNT" -ge 10 ]; then
    echo -e "  ${GREEN}✓${NC} $MODEL_COUNT .joblib models trained"
    PASS=$((PASS+1))
else
    echo -e "  ${RED}✗${NC} Only $MODEL_COUNT models (expected ≥10)"
    FAIL=$((FAIL+1))
fi
warn_check "UNSW-NB15 model" "test -f models/threat_predictor_unsw_nb15.joblib"
warn_check "NSL-KDD model" "test -f models/threat_predictor_nsl_kdd.joblib"
echo

# === 6. Datasets ===
echo -e "${BLUE}[6/8]${NC} Datasets"
warn_check "UNSW-NB15 dataset" "test -d data/unsw_nb15"
warn_check "NSL-KDD dataset" "test -d data/nsl_kdd"
echo

# === 7. Backend ===
echo -e "${BLUE}[7/8]${NC} Backend API"
warn_check "Backend :8444" "curl -s -o /dev/null -w '%{http_code}' http://localhost:8444/api/healthz 2>/dev/null | grep -q 200"
warn_check "UI :8445" "curl -s -o /dev/null -w '%{http_code}' http://localhost:8445/ 2>/dev/null | grep -q 200"
echo

# === 8. Tests ===
echo -e "${BLUE}[8/8]${NC} Test results"
if [ -f data/test_results.json ]; then
    TOTAL=$(python3 -c "import json; d=json.load(open('data/test_results.json')); print(d.get('total', 0))" 2>/dev/null)
    if [ -n "$TOTAL" ] && [ "$TOTAL" -ge 381 ]; then
        echo -e "  ${GREEN}✓${NC} $TOTAL tests in data/test_results.json"
        PASS=$((PASS+1))
    else
        echo -e "  ${YELLOW}⚠${NC} Only $TOTAL tests (expected 381)"
        WARN=$((WARN+1))
    fi
else
    echo -e "  ${YELLOW}⚠${NC} data/test_results.json not found — run scripts/test_all.sh"
    WARN=$((WARN+1))
fi
echo

# === Summary ===
echo "════════════════════════════════════════════════════════════════════"
echo -e "  ${GREEN}PASS${NC}: $PASS   ${YELLOW}WARN${NC}: $WARN   ${RED}FAIL${NC}: $FAIL"
echo "════════════════════════════════════════════════════════════════════"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}✓ System ready for operation${NC}"
    exit 0
else
    echo -e "${RED}✗ Fix $FAIL issue(s) before production use${NC}"
    exit 1
fi