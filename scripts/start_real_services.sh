#!/bin/bash
# Goodware v3.0 — Inicia serviços REAL (TPM, firewall, etc)
set -e

echo "=== Goodware v3.0 — Iniciando serviços REAL ==="

# 1. swtpm (TPM simulator se não houver físico)
if ! pgrep -f swtpm > /dev/null; then
    if [ ! -d /tmp/goodware-tpm ]; then
        mkdir -p /tmp/goodware-tpm
    fi
    swtpm socket --tpmstate dir=/tmp/goodware-tpm \
        --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
        --tpm2 --daemon --flags not-need-init
    sleep 2
    echo "[OK] swtpm iniciado"
else
    echo "[i] swtpm já está a correr"
fi

# 2. ClamAV daemon (se disponível)
if command -v clamd >/dev/null 2>&1; then
    systemctl start clamav-daemon 2>/dev/null || clamd --daemon 2>/dev/null || true
    echo "[OK] clamav daemon (se permitiu)"
fi

# 3. nftables — criar tabela goodware em netns
# (precisa root para persistent, mas em netns funciona)
if command -v nft >/dev/null 2>&1; then
    echo "[OK] nftables disponível em $(which nft)"
fi

# 4. auditd (se disponível)
if command -v auditd >/dev/null 2>&1; then
    systemctl start auditd 2>/dev/null || true
    echo "[OK] auditd (se permitiu)"
fi

# 5. Honeypots (a correr via system service)
# (já integrado nas definições do Goodware)

echo
echo "=== Estado dos serviços REAL ==="
echo "  TPM:       $(TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321' tpm2_pcrread sha256:0 2>&1 | grep '0 :' || echo 'NOT AVAILABLE')"
echo "  nftables:  $(nft --version 2>&1 | head -1)"
echo "  ClamAV:    $(clamscan --version 2>&1 | head -1)"
echo "  tpm2-tools: $(tpm2_pcrread --version 2>&1 | head -1)"

echo
echo "=== Goodware ready ==="
