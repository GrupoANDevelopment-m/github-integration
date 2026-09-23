#!/bin/bash
# Goodware v3.0 - Status check
cd "$(dirname "$0")/.."

PIDFILE="data/goodware.pid"
PORT="${PORT:-8444}"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "[✓] Goodware a correr (PID $(cat "$PIDFILE"))"
  echo "---"
  if command -v curl > /dev/null 2>&1; then
    echo "Health:    $(curl -s http://127.0.0.1:$PORT/api/healthz 2>/dev/null || echo 'sem resposta')"
    echo ""
    echo "Engine:"
    curl -s http://127.0.0.1:$PORT/api/status 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30
    echo ""
    echo "Crypto:"
    curl -s http://127.0.0.1:$PORT/api/crypto 2>/dev/null | python3 -m json.tool 2>/dev/null | head -15
    echo ""
    echo "Attestation:"
    curl -s http://127.0.0.1:$PORT/api/attestation 2>/dev/null | python3 -m json.tool 2>/dev/null | head -15
  else
    echo "(instale curl para mais detalhes)"
  fi
else
  echo "[✗] Goodware NÃO está a correr."
  echo "Para arrancar: ./scripts/start.sh"
fi
