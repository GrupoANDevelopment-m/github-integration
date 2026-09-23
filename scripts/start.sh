#!/bin/bash
# Goodware v3.0 - Script de arranque
set -e
cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8444}"

echo "=========================================="
echo "  Goodware v3.0 — Arrancando"
echo "=========================================="

# Verificar dependências
echo "[*] A verificar dependências..."
$PYTHON -c "import yaml, psutil, sklearn, flask, requests, watchdog, cryptography" 2>/dev/null || {
  echo "[!] Faltam dependências. A instalar..."
  pip3 install --break-system-packages --index-url https://pypi.org/simple/ \
    pyyaml psutil scikit-learn flask flask-cors requests watchdog cryptography joblib numpy 2>&1 | tail -3
}

# Criar directorios necessários
mkdir -p data logs models keys quarantine signatures sbom policies

# Limpar processos anteriores
PIDFILE="data/goodware.pid"
if [ -f "$PIDFILE" ]; then
  OLD_PID=$(cat "$PIDFILE")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[*] A parar processo anterior (PID $OLD_PID)..."
    kill "$OLD_PID" || true
    sleep 1
  fi
  rm -f "$PIDFILE"
fi

# Arrancar Goodware
echo "[*] A arrancar Goodware v3.0..."
PYTHONPATH="." nohup $PYTHON -m goodware --api-port "$PORT" > logs/goodware.out 2>&1 &
PID=$!
echo $PID > "$PIDFILE"
sleep 2

if kill -0 "$PID" 2>/dev/null; then
  echo "[✓] Goodware v3.0 a correr (PID $PID)"
  echo "[✓] API:        http://127.0.0.1:$PORT/api/healthz"
  echo "[✓] Dashboard:  cd dashboard && $PYTHON -m http.server 8080"
  echo "[✓] Logs:       tail -f logs/goodware.out"
  echo ""
  echo "Para parar: ./scripts/stop.sh"
else
  echo "[!] Erro a arrancar. Últimas linhas do log:"
  tail -20 logs/goodware.out
  exit 1
fi
