#!/bin/bash
# Goodware v3.0 - Script de paragem
set -e
cd "$(dirname "$0")/.."

PIDFILE="data/goodware.pid"
if [ -f "$PIDFILE" ]; then
  PID=$(cat "$PIDFILE")
  if kill -0 "$PID" 2>/dev/null; then
    echo "[*] A parar Goodware (PID $PID)..."
    kill "$PID" || true
    sleep 2
    kill -9 "$PID" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
  echo "[✓] Goodware parado."
else
  echo "[i] Nenhum processo Goodware encontrado."
  pkill -f "goodware --api-port" 2>/dev/null && echo "[✓] Processos remanescentes terminados." || true
fi
