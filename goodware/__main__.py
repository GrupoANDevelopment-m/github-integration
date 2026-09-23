"""
Goodware v3.0 - Entry point CLI.

Uso:
  python3 -m goodware                     # arranca todos os módulos
  python3 -m goodware --demo              # corre cenário de demonstração
  python3 -m goodware --with-honeypot     # arranca também honeypots reais
"""
from __future__ import annotations

import argparse
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(prog="goodware", description="Goodware v3.0 - Sistema Imunitário Digital Autónomo")
    parser.add_argument("--config", default="config/goodware.yaml")
    parser.add_argument("--api-port", type=int, default=8444)
    parser.add_argument("--api-host", default="127.0.0.1")
    parser.add_argument("--no-api", action="store_true")
    parser.add_argument("--no-federated", action="store_true")
    parser.add_argument("--with-honeypot", action="store_true", help="arranca honeypot real (requer root)")
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    args = parser.parse_args()

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)

    from goodware.core.engine import Engine
    from goodware.core.config import GoodwareConfig
    from goodware.core.logger import get_logger

    logger = get_logger("goodware", log_dir="logs")
    config = GoodwareConfig.load(args.config)
    if args.no_api:
        config.set("api.enabled", False)
    engine = Engine(config)
    logger.info("=" * 70)
    logger.info("  Goodware v3.0 — Sistema Imunitário Digital Autónomo")
    logger.info("  (integrações reais: iptables, YARA, ClamAV, auditd, tpm2-tools)")
    logger.info("=" * 70)

    from goodware.sensors import SensorManager
    from goodware.crypto import CryptoManager
    from goodware.prediction import PredictionManager
    from goodware.human_factor import HumanFactorManager
    from goodware.physical import PhysicalSecurityManager
    from goodware.supply_chain import SupplyChainManager
    from goodware.immune import ImmuneManager
    from goodware.decision import DecisionManager
    from goodware.effector import EffectorManager
    from goodware.chainsaw import ChainsawManager

    sm = SensorManager(engine, config)
    cm = CryptoManager(engine, config); engine.register("crypto", cm)
    pm = PredictionManager(engine, config)
    hf = HumanFactorManager(engine, config); engine.register("human_factor", hf)
    pm2 = PhysicalSecurityManager(engine, config); engine.register("physical", pm2)
    sc = SupplyChainManager(engine, config); engine.register("supply_chain", sc)
    im = ImmuneManager(engine, config); engine.register("immune", im)
    chainsaw = ChainsawManager(engine, config); engine.register("chainsaw", chainsaw)
    dm = DecisionManager(engine, config); engine.register("decision", dm)
    em = EffectorManager(engine, config); engine.register("effector", em)
    fm = None
    if not args.no_federated:
        from goodware.federated import FederatedManager
        fm = FederatedManager(engine, config)

    # Honeypot real (opcional)
    honeypot = None
    if args.with_honeypot:
        try:
            from goodware.honeypot import HoneypotManager
            honeypot = HoneypotManager({"honeypot": {"enabled": True}})
            engine.register("honeypot", honeypot)
            result = honeypot.start_all()
            logger.info(f"  ✓ honeypot: {result['started']}")
        except Exception as e:
            logger.error(f"honeypot start failed: {e}")

    if not args.status_only:
        cm.start()
        sm.start_all()
        pm.start_all()
        if fm: fm.start_all()
        hf.start(); pm2.start(); sc.start(); im.start_all(); dm.start(); em.start(); chainsaw.start()

    if not args.no_api and config.get("api.enabled", True):
        from goodware.api import start_api
        start_api(engine, config, host=args.api_host, port=args.api_port)
        logger.info(f"  ✓ API REST em http://{args.api_host}:{args.api_port}/api/healthz")
        logger.info(f"  ✓ Dashboard: serve a pasta dashboard/ via HTTP static server")

    if args.demo and not args.status_only:
        time.sleep(2)
        logger.info("[DEMO] simulação...")
        sim = pm.simulator
        sim.simulate(2)
        time.sleep(2)
        logger.info(f"[DEMO] cobertura: {sim.evaluate_defense()}")
        result = hf.evaluate({"action": "delete_user", "user": "admin", "location": "unknown", "time_of_day": 3, "device_id": "unknown"})
        logger.info(f"[DEMO] human factor: {result}")
        dec = dm.decide({"severity": "high", "type": "sensor.process_anomaly", "payload": {}})
        logger.info(f"[DEMO] decision: {dec}")
        logger.info(f"[DEMO] firewall (real iptables se root): {em.firewall.block_port(445, 'tcp', 'ransomware_precursor')}")
        logger.info(f"[DEMO] chainsaw rootkit scan: {chainsaw.scan_rootkit()}")
        logger.info(f"[DEMO] CIS benchmark: {chainsaw.run_cis()['score']}% pass")

    if args.status_only:
        import json
        print(json.dumps(engine.status(), indent=2, default=str))
        return

    logger.info("=" * 70)
    logger.info(" Goodware v3.0 a correr — Ctrl-C para parar")
    logger.info("=" * 70)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("a parar...")
        sm.stop_all()
        if fm: fm.stop_all()
        if honeypot: honeypot.stop_all()
        im.stop_all()
        dm.stop()
        em.stop()
        logger.info("Goodware parado.")


if __name__ == "__main__":
    main()
