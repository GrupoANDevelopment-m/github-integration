#!/usr/bin/env bash
# Goodware v3.0 — Instala dependências reais (apt + liboqs from source)
# Requer: Debian 12+ / Ubuntu 22.04+
set -e

echo "=== Goodware v3.0 — install real dependencies ==="

# 1) Pacotes apt
echo "[1/3] Installing apt packages..."
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  yara clamav clamav-daemon tpm2-tools nftables iptables auditd \
  python3-yara python3-yaml python3-flask python3-flask-cors \
  python3-psutil python3-watchdog python3-sklearn \
  python3-requests python3-cryptography python3-rich python3-joblib \
  build-essential cmake ninja-build git wget ca-certificates pkg-config

# 2) ClamAV signatures
echo "[2/3] Updating ClamAV signatures..."
mkdir -p /var/lib/clamav
if command -v freshclam >/dev/null; then
  freshclam --quiet || echo "  (freshclam falhou — pode estar offline)"
fi

# 3) liboqs (NIST PQC) from source
echo "[3/3] Building liboqs (Open Quantum Safe) from source..."
LIBOQS_PREFIX=/usr/local
LIBOQS_VERSION=0.16.0
LIBOQS_DIR=/tmp/liboqs-src

if ! ldconfig -p | grep -q "liboqs.so.${LIBOQS_VERSION}"; then
  if [ ! -d "$LIBOQS_DIR" ]; then
    git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_DIR"
  fi
  cd "$LIBOQS_DIR"
  mkdir -p build && cd build
  cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX="${LIBOQS_PREFIX}" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_MINIMAL_BUILD="KEM_kyber_512;KEM_ml_kem_512;SIG_dilithium_2;SIG_ml_dsa_44" \
    ..
  ninja -j"$(nproc)" -k 0
  ninja install
  ldconfig
  # Relinkar liboqs.so com os wrappers que faltam (kem_kyber_512.c.o, kem_ml_kem_512.c.o, sig_ml_dsa_44.c.o)
  # O build pré-fabricado não os inclui por padrão — relink manual
  cd /tmp
  mkdir -p /tmp/liboqs_repack
  cd /tmp/liboqs_repack
  ar x "${LIBOQS_DIR}/build/lib/liboqs-internal.a"
  # Re-compilar wrappers com ENABLE flags
  cd "${LIBOQS_DIR}/build"
  for tup in \
    "kem/kyber kem_kyber_512.c KEM_kyber_512" \
    "kem/ml_kem kem_ml_kem_512.c KEM_ml_kem_512" \
    "sig/ml_dsa sig_ml_dsa_44.c SIG_ml_dsa_44"; do
    set -- $tup
    SUBDIR=$1; SRC=$2; EN=$3
    OBJ_DIR=$(find "${LIBOQS_DIR}/build/src/${SUBDIR}/CMakeFiles" -mindepth 1 -maxdepth 1 -type d | head -1)
    OBJ_FILE="${OBJ_DIR}/${SRC}.o"
    if [ -f "$OBJ_FILE" ]; then
      gcc -c -fPIC -O2 -fvisibility=default \
        -I"${LIBOQS_DIR}/build/include" -I"${LIBOQS_DIR}/src" \
        -DOQS_ENABLE_${EN}=1 \
        "${LIBOQS_DIR}/src/${SUBDIR}/${SRC}" -o "$OBJ_FILE" 2>/dev/null || true
    fi
  done
  KYBER_OBJS=$(find "${LIBOQS_DIR}/build/src/kem/kyber/CMakeFiles" -name "*.o" 2>/dev/null | grep "kyber_512" | tr '\n' ' ')
  MLKEM_OBJS=$(find "${LIBOQS_DIR}/build/src/kem/ml_kem/CMakeFiles" -name "*.o" 2>/dev/null | grep "ml_kem_512" | tr '\n' ' ')
  MLDSA_OBJS=$(find "${LIBOQS_DIR}/build/src/sig/ml_dsa/CMakeFiles" -name "*.o" 2>/dev/null | grep "ml_dsa_44" | tr '\n' ' ')
  DISPATCH_OBJS="${LIBOQS_DIR}/build/src/CMakeFiles/oqs.dir/kem/kem.c.o ${LIBOQS_DIR}/build/src/CMakeFiles/oqs.dir/sig/sig.c.o"
  COMMON_FIPS="${LIBOQS_DIR}/build/src/common/CMakeFiles/common.dir/pqclean_shims/fips202.c.o ${LIBOQS_DIR}/build/src/common/CMakeFiles/common.dir/pqclean_shims/fips202x4.c.o"
  # shim para OQS_randombytes
  cat > /tmp/oqs_randombytes.c <<'SHIM_EOF'
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
void OQS_randombytes(uint8_t *random_array, size_t n_bytes) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { size_t r = fread(random_array, 1, n_bytes, f); fclose(f); if (r == n_bytes) return; }
    for (size_t i = 0; i < n_bytes; i++) random_array[i] = (uint8_t)(rand() & 0xff);
}
SHIM_EOF
  gcc -c -fPIC /tmp/oqs_randombytes.c -o /tmp/oqs_randombytes.o
  cd /tmp/liboqs_repack
  gcc -shared -fPIC -fvisibility=default \
    -o /tmp/liboqs_final.so.${LIBOQS_VERSION} \
    -Wl,--whole-archive "${LIBOQS_DIR}/build/lib/liboqs-internal.a" -Wl,--no-whole-archive \
    $COMMON_FIPS $DISPATCH_OBJS $KYBER_OBJS $MLKEM_OBJS $MLDSA_OBJS \
    /tmp/oqs_randombytes.o \
    -lcrypto -lc -lpthread
  cp /tmp/liboqs_final.so.${LIBOQS_VERSION} "${LIBOQS_PREFIX}/lib/"
  (cd "${LIBOQS_PREFIX}/lib" && ln -sf liboqs.so.${LIBOQS_VERSION} liboqs.so && ln -sf liboqs.so.${LIBOQS_VERSION} liboqs.so.9)
  ldconfig
fi

echo ""
echo "=== Instalação completa ==="
echo ""
echo "Verificação rápida:"
LD_LIBRARY_PATH=${LIBOQS_PREFIX}/lib python3 -c "
import ctypes
lib = ctypes.CDLL('${LIBOQS_PREFIX}/lib/liboqs.so')
lib.OQS_init.restype = ctypes.c_char_p
v = lib.OQS_version()
print(f'  liboqs {v.decode() if v else \"?\"} — OK')
print('  KEM Kyber512 enabled:', 'SIM' if lib.OQS_KEM_alg_is_enabled(b'Kyber512') == 1 else 'NÃO')
print('  KEM ML-KEM-512 enabled:', 'SIM' if lib.OQS_KEM_alg_is_enabled(b'ML-KEM-512') == 1 else 'NÃO')
print('  SIG ML-DSA-44 enabled:', 'SIM' if lib.OQS_SIG_alg_is_enabled(b'ML-DSA-44') == 1 else 'NÃO')
" 2>&1
echo "  YARA:    $(yara --version 2>/dev/null || echo 'N/A')"
echo "  ClamAV:  $(clamscan --version 2>/dev/null | head -1 || echo 'N/A')"
echo "  nft:     $(nft --version 2>/dev/null | head -1 || echo 'N/A')"
echo "  tpm2:    $(tpm2_getcap --version 2>/dev/null | head -1 || echo 'N/A')"
