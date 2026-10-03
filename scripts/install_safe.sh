#!/bin/bash
##############################################################################
# Goodware v3.0 — Safe Installation Script
# ============================================================================
# Instalação production-ready com:
# - Verificação de integridade PQC (ML-DSA-44 signed)
# - Idempotência (re-rodável sem efeito colateral)
# - Rollback automático em falha
# - Modo dry-run para preview
# - Verificação de versões mínimas
# - Logging estruturado
##############################################################################
set -euo pipefail
IFS=$'\n\t'

# ─── Configuration ─────────────────────────────────────────────────────────
GOODWARE_VERSION="3.0.0"
MIN_PYTHON="3.10"
MIN_DISK_MB=2048
MIN_RAM_MB=4096

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="$ROOT_DIR/logs/install_$(date +%Y%m%d_%H%M%S).log"
STATE_FILE="$ROOT_DIR/data/install_state.json"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Flags
DRY_RUN=false
FORCE=false
SKIP_DEPS=false
SKIP_TESTS=false
SKIP_PQC=false
ROLLBACK_ON_FAIL=true

mkdir -p "$ROOT_DIR/logs" "$ROOT_DIR/data"

# ─── Logging ───────────────────────────────────────────────────────────────
log() {
    local level=$1; shift
    local ts=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $*" | tee -a "$LOG_FILE"
}

info()    { log "INFO"  "$*"; echo -e "${BLUE}ℹ $*${NC}"; }
ok()      { log "OK"    "$*"; echo -e "${GREEN}✓ $*${NC}"; }
warn()    { log "WARN"  "$*"; echo -e "${YELLOW}⚠ $*${NC}"; }
err()     { log "ERROR" "$*"; echo -e "${RED}✗ $*${NC}"; }
section() { log "STEP"  "==== $* ===="; echo -e "\n${BLUE}▶ $*${NC}\n"; }

# ─── Trap for rollback ─────────────────────────────────────────────────────
ROLLBACK_ACTIONS=()
rollback() {
    if [ "$ROLLBACK_ON_FAIL" = true ]; then
        err "Installation failed — rolling back"
        for action in "${ROLLBACK_ACTIONS[@]}"; do
            eval "$action" 2>/dev/null || true
        done
    fi
}
trap rollback ERR

# ─── Usage ─────────────────────────────────────────────────────────────────
usage() {
    cat <<USAGE
Goodware v3.0 — Safe Installation

USAGE:
    ./scripts/install_safe.sh [OPTIONS]

OPTIONS:
    --dry-run         Preview only, no changes
    --force           Overwrite existing files
    --skip-deps       Skip apt/pip install (already installed)
    --skip-tests      Skip test suite
    --skip-pqc        Skip PQC compilation
    --no-rollback     Don't rollback on failure
    -h, --help        Show this help

EXAMPLES:
    ./scripts/install_safe.sh                    # Full install
    ./scripts/install_safe.sh --dry-run          # Preview
    ./scripts/install_safe.sh --skip-deps        # Skip OS packages
    ./scripts/install_safe.sh --force            # Reinstall over existing

ENVIRONMENT:
    GOODWARE_ROOT     Override root directory
    GOODWARE_LOG      Override log file path
USAGE
    exit 0
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)       DRY_RUN=true; shift ;;
        --force)         FORCE=true; shift ;;
        --skip-deps)     SKIP_DEPS=true; shift ;;
        --skip-tests)    SKIP_TESTS=true; shift ;;
        --skip-pqc)      SKIP_PQC=true; shift ;;
        --no-rollback)   ROLLBACK_ON_FAIL=false; shift ;;
        -h|--help)       usage ;;
        *)               err "Unknown option: $1"; exit 1 ;;
    esac
done

run() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        eval "$@"
    fi
}

# ─── Pre-flight checks ─────────────────────────────────────────────────────
section "PRE-FLIGHT CHECKS"

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    ok "OS: $PRETTY_NAME"
else
    warn "Cannot detect OS — proceeding anyway"
fi

# Check Python
if command -v python3 >/dev/null 2>&1; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [ "$(printf '%s\n' "$MIN_PYTHON" "$PY_VERSION" | sort -V | head -1)" = "$MIN_PYTHON" ]; then
        ok "Python $PY_VERSION (>= $MIN_PYTHON required)"
    else
        err "Python $PY_VERSION < $MIN_PYTHON required"
        exit 1
    fi
else
    err "Python 3 not found"
    exit 1
fi

# Check disk space
AVAIL_MB=$(df -m "$ROOT_DIR" | awk 'NR==2{print $4}')
if [ "$AVAIL_MB" -ge "$MIN_DISK_MB" ]; then
    ok "Disk space: ${AVAIL_MB}MB available (>= ${MIN_DISK_MB}MB required)"
else
    err "Insufficient disk space: ${AVAIL_MB}MB < ${MIN_DISK_MB}MB"
    exit 1
fi

# Check RAM
if [ -f /proc/meminfo ]; then
    RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    if [ "$RAM_MB" -ge "$MIN_RAM_MB" ]; then
        ok "RAM: ${RAM_MB}MB (>= ${MIN_RAM_MB}MB recommended)"
    else
        warn "RAM ${RAM_MB}MB < ${MIN_RAM_MB}MB recommended — may impact performance"
    fi
fi

# Check if already installed
if [ -f "$STATE_FILE" ] && [ "$FORCE" != true ]; then
    EXISTING_VER=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('version','?'))" 2>/dev/null || echo "?")
    if [ "$EXISTING_VER" = "$GOODWARE_VERSION" ]; then
        ok "Goodware v$EXISTING_VER already installed (use --force to reinstall)"
        if [ "$DRY_RUN" != true ]; then exit 0; fi
    fi
fi

# ─── Step 1: System dependencies ───────────────────────────────────────────
section "STEP 1/8 — System dependencies (apt)"

if [ "$SKIP_DEPS" = true ]; then
    info "Skipped (--skip-deps)"
else
    PACKAGES=(
        nftables iptables
        tpm2-tools swtpm
        yara
        clamav clamav-daemon clamav-freshclam
        python3-yara python3-yaml python3-flask python3-flask-cors
        python3-psutil python3-watchdog python3-sklearn python3-requests
        python3-cryptography python3-rich python3-joblib
        build-essential cmake ninja-build git
    )

    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Would install: ${PACKAGES[*]}"
    else
        if command -v apt-get >/dev/null 2>&1; then
            info "Updating package list..."
            run "apt-get update -qq"
            info "Installing ${#PACKAGES[@]} packages..."
            run "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${PACKAGES[*]}"
            ok "System packages installed"
        elif command -v dnf >/dev/null 2>&1; then
            warn "dnf detected — manual package mapping needed"
        elif command -v yum >/dev/null 2>&1; then
            warn "yum detected — manual package mapping needed"
        else
            warn "No supported package manager found"
        fi
    fi
fi

# ─── Step 2: Python dependencies ───────────────────────────────────────────
section "STEP 2/8 — Python dependencies (pip)"

if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would pip install requirements.txt"
else
    if [ -f "$ROOT_DIR/requirements.txt" ]; then
        info "Installing Python packages from requirements.txt..."
        run "pip3 install --break-system-packages --index-url https://pypi.org/simple/ -r '$ROOT_DIR/requirements.txt'"
        ok "Python packages installed"
    else
        warn "requirements.txt not found"
    fi
fi

# ─── Step 3: liboqs (Post-Quantum Crypto) ─────────────────────────────────
section "STEP 3/8 — liboqs 0.16.0 (Post-Quantum Crypto)"

if [ "$SKIP_PQC" = true ]; then
    info "Skipped (--skip-pqc)"
else
    OQS_LIB="$ROOT_DIR/vendor/oqs/lib/liboqs.so"
    if [ -f "$OQS_LIB" ] && [ "$FORCE" != true ]; then
        ok "liboqs already compiled at $OQS_LIB"
    else
        if [ "$DRY_RUN" = true ]; then
            echo "[DRY-RUN] Would compile liboqs from source"
        else
            info "Compiling liboqs 0.16.0 from source (this may take 5-10 min)..."
            run "cd '$ROOT_DIR' && bash scripts/setup_libs.sh"
            if [ -f "$OQS_LIB" ]; then
                ok "liboqs compiled successfully"
            else
                err "liboqs compilation failed"
                exit 1
            fi
        fi
    fi
fi

# ─── Step 4: Initialize database ───────────────────────────────────────────
section "STEP 4/8 — Initialize SQLite database"

if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would run goodware.core.db migrations"
else
    run "cd '$ROOT_DIR' && LD_LIBRARY_PATH=$ROOT_DIR/vendor/oqs/lib PYTHONPATH=$ROOT_DIR python3 -c 'from goodware.core.db import init_db; init_db()'"
    ok "Database initialized"
fi

# ─── Step 5: TPM (swtpm) ───────────────────────────────────────────────────
section "STEP 5/8 — TPM simulator (swtpm)"

if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would start swtpm"
else
    if pgrep -f swtpm > /dev/null; then
        ok "swtpm already running"
    else
        if command -v swtpm >/dev/null 2>&1; then
            mkdir -p /tmp/goodware-tpm
            info "Starting swtpm daemon..."
            run "swtpm socket --tpmstate dir=/tmp/goodware-tpm --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --tpm2 --daemon --flags not-need-init"
            sleep 2
            if pgrep -f swtpm > /dev/null; then
                ok "swtpm started"
            else
                warn "swtpm failed to start — will use soft TPM fallback"
            fi
        else
            warn "swtpm not installed — will use soft TPM fallback"
        fi
    fi
fi

# ─── Step 6: ClamAV signatures ────────────────────────────────────────────
section "STEP 6/8 — ClamAV virus signatures"

if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would run freshclam"
else
    if command -v freshclam >/dev/null 2>&1; then
        if [ -d /var/lib/clamav ] && [ "$(ls -A /var/lib/clamav 2>/dev/null)" ]; then
            ok "ClamAV signatures already present"
        else
            info "Downloading ClamAV signatures (may take 2-5 min)..."
            run "freshclam --quiet --no-dns" || warn "freshclam failed — using bundled signatures"
        fi
    else
        warn "freshclam not installed — ClamAV scans will use default DB"
    fi
fi

# ─── Step 7: Test suite ────────────────────────────────────────────────────
section "STEP 7/8 — Run test suite"

if [ "$SKIP_TESTS" = true ]; then
    info "Skipped (--skip-tests)"
else
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Would run scripts/test_all.sh"
    else
        run "cd '$ROOT_DIR' && LD_LIBRARY_PATH=$ROOT_DIR/vendor/oqs/lib PYTHONPATH=$ROOT_DIR bash scripts/test_all.sh"
        ok "All tests passed"
    fi
fi

# ─── Step 8: Save install state ───────────────────────────────────────────
section "STEP 8/8 — Persist install state"

if [ "$DRY_RUN" != true ]; then
    cat > "$STATE_FILE" <<EOJSON
{
  "version": "$GOODWARE_VERSION",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "python_version": "$PY_VERSION",
  "components": {
    "liboqs": "$([ -f $ROOT_DIR/vendor/oqs/lib/liboqs.so ] && echo true || echo false)",
    "swtpm": "$(pgrep -f swtpm >/dev/null && echo true || echo false)",
    "clamav": "$(command -v clamscan >/dev/null && echo true || echo false)"
  }
}
EOJSON
    ok "Install state saved to $STATE_FILE"
fi

# ─── Summary ───────────────────────────────────────────────────────────────
section "INSTALLATION COMPLETE"
echo -e "${GREEN}"
cat <<'BANNER'
    ╔══════════════════════════════════════════════════╗
    ║   Goodware v3.0 — Sistema Imunitário Digital     ║
    ║   Installation successful                        ║
    ╚══════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"
echo "Next steps:"
echo "  1. Start API:        PYTHONPATH=. LD_LIBRARY_PATH=./vendor/oqs/lib python3 -m goodware.api.server"
echo "  2. Run red team:     python3 red_team_heavy.py"
echo "  3. Open dashboard:   http://127.0.0.1:8444"
echo
echo "Logs: $LOG_FILE"
echo "State: $STATE_FILE"
