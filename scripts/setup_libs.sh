#!/usr/bin/env bash
# Goodware v3.0 — Instala APENAS a liboqs (NIST PQC) compilada do vendor/
# As outras deps (apt packages, ClamAV sigs) estão em install_deps.sh
set -e

VENDOR_DIR="$(cd "$(dirname "$0")/.." && pwd)/vendor/oqs"
LIB_DIR="$VENDOR_DIR/lib"

echo "=== Goodware v3.0 — Setup liboqs (vendor) ==="

if [ ! -f "$LIB_DIR/liboqs.so.0.16.0" ]; then
  echo "ERRO: vendor/oqs/lib/liboqs.so.0.16.0 não encontrada."
  echo "Certifica-te que o repo foi clonado com --recursive ou que os .so estão commitados."
  exit 1
fi

# Adiciona o vendor ao ldconfig se o utilizador quiser global
if [ -w /etc/ld.so.conf.d ]; then
  echo "$LIB_DIR" > /etc/ld.so.conf.d/goodware-oqs.conf
  ldconfig
  echo "✓ liboqs instalada globalmente em /etc/ld.so.conf.d/goodware-oqs.conf"
else
  echo "NOTA: para LD_LIBRARY_PATH ficar global:"
  echo "  export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:$LIB_DIR"
fi

# Verifica que funciona
echo
echo "=== Verificação ==="
python3 -c "
import ctypes, os
lib = ctypes.CDLL('$LIB_DIR/liboqs.so.0.16.0')
lib.OQS_init.restype = None
lib.OQS_init()
v = lib.OQS_version().decode()
print(f'liboqs v{v} OK')
" || {
  echo "ERRO: liboqs não conseguiu inicializar"
  echo "Tenta: export LD_LIBRARY_PATH=$LIB_DIR"
  exit 1
}

echo
echo "=== liboqs pronta ==="
echo "Vendor em: $VENDOR_DIR"
echo "Headers em: $VENDOR_DIR/include/oqs/"
