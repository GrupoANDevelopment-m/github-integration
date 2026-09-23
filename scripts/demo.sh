#!/bin/bash
# Goodware v3.0 - Demo: arranca + simula ataques
set -e
cd "$(dirname "$0")/.."

echo "=========================================="
echo "  Goodware v3.0 — DEMO"
echo "=========================================="

./scripts/start.sh
echo ""
echo "[*] A aguardar sistema inicializar..."
sleep 3

echo "[*] A correr simulação de ataques..."
PYTHONPATH="." python3 -c "
import time, requests, json
from goodware.core.engine import Engine
from goodware.core.config import GoodwareConfig

e = Engine(GoodwareConfig.load())
pm = None
for name, c in e._components.items():
    if hasattr(c, 'simulator'):
        pm = c
        break

if pm:
    print('[+] A injetar ataques sintéticos...')
    print('   ', pm.simulate(3))
    time.sleep(2)
    print('[+] Avaliação de defesa:')
    print('   ', pm.simulator.evaluate_defense())

# Evento de decisão
for name, c in e._components.items():
    if hasattr(c, 'decide'):
        print('[+] Decisão sobre evento high-severity:')
        print('   ', c.decide({'severity':'high','type':'sensor.process_anomaly','payload':{'anomaly_score':0.9}}))
        break

# Human factor
for name, c in e._components.items():
    if hasattr(c, 'evaluate') and hasattr(c, 'approve'):
        print('[+] Human Factor — ação de alto risco:')
        print('   ', c.evaluate({'action':'delete_user','user':'admin','location':'unknown','time_of_day':3,'device_id':'unknown'}))
        break

# Effector
for name, c in e._components.items():
    if hasattr(c, 'execute_action'):
        print('[+] Effector — bloquear porta SMB:')
        print('   ', c.execute_action({'type':'block_port','target':'445','reason':'ransomware_precursor'}))
        print('[+] Effector — snapshot:')
        print('   ', c.rollback.snapshot('demo', ['/etc/passwd']))
        break
"

echo ""
echo "=========================================="
echo "  DEMO completa. A abrir status..."
echo "=========================================="
./scripts/status.sh
