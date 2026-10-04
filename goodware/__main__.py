"""
Goodware v3.0 - Entry point CLI.

Uso:
  python3 -m goodware                        # arranca todos os módulos
  python3 -m goodware --scan-lynis            # corre Lynis CIS audit
  python3 -m goodware --scan-loki PATH        # corre Loki scan num path
  python3 -m goodware --scan-linuxcheck       # corre LinuxCheck IR
  python3 -m goodware --with-honeypot         # arranca honeypots reais
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time


def main():
    parser = argparse.ArgumentParser(
        prog="goodware",
        description="Goodware v3.0 - Sistema Imunitário Digital Autónomo"
    )
    parser.add_argument("--config", default="config/goodware.yaml")
    parser.add_argument("--api-port", type=int, default=8444)
    parser.add_argument("--api-host", default="127.0.0.1")
    parser.add_argument("--no-api", action="store_true")
    parser.add_argument("--no-federated", action="store_true")
    parser.add_argument("--with-honeypot", action="store_true")
    parser.add_argument("--status-only", action="store_true")
    # Real integration flags (replace --demo)
    parser.add_argument("--scan-lynis", action="store_true",
                        help="Run Lynis CIS benchmark audit")
    parser.add_argument("--scan-loki", metavar="PATH",
                        help="Run Loki scanner on PATH")
    parser.add_argument("--scan-linuxcheck", action="store_true",
                        help="Run LinuxCheck incident response")
    parser.add_argument("--scan-all", action="store_true",
                        help="Run all real scanners (lynis + loki + linuxcheck)")
    args = parser.parse_args()

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)

    # === Real scanner mode (no engine needed) ===
    if args.scan_lynis or args.scan_loki or args.scan_linuxcheck or args.scan_all:
        from goodware.core.logger import get_logger
        logger = get_logger("goodware.scanner", log_dir="logs")
        run_real_scanners(args, logger)
        return

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
    logger.info("  Integrações REAIS: Lynis, Loki, LinuxCheck, Cowrie, ClamAV, nftables, TPM")
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

    if args.status_only:
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


def run_real_scanners(args, logger):
    """Run REAL scanners (Lynis, Loki, LinuxCheck) — replaces --demo flag."""
    import json

    if args.scan_lynis or args.scan_all:
        logger.info("=" * 70)
        logger.info("  Running Lynis CIS Benchmark Audit (REAL)")
        logger.info("  Source: https://github.com/CISOfy/lynis")
        logger.info("=" * 70)
        try:
            from goodware.chainsaw.lynis_integration import LynisIntegration
            l = LynisIntegration()
            if not l.available:
                logger.error("Lynis not available")
            else:
                logger.info(f"Lynis version: {l.version}")
                result = l.run_audit(quick=True, timeout=180, skip_tests=["malware", "docker"])
                print(json.dumps(result, indent=2, default=str))
        except Exception as e:
            logger.error(f"Lynis audit failed: {e}")

    if args.scan_loki or args.scan_all:
        path = args.scan_loki if args.scan_loki else "/tmp"
        logger.info("=" * 70)
        logger.info(f"  Running Loki Scanner on {path} (REAL)")
        logger.info("  Source: https://github.com/Neo23x0/Loki")
        logger.info("=" * 70)
        try:
            from goodware.chainsaw.loki_integration import LokiIntegration
            lo = LokiIntegration()
            if not lo.available:
                logger.error("Loki not available")
            else:
                result = lo.scan(path=path, timeout=120)
                print(json.dumps(result, indent=2, default=str))
        except Exception as e:
            logger.error(f"Loki scan failed: {e}")

    if args.scan_linuxcheck or args.scan_all:
        logger.info("=" * 70)
        logger.info("  Running LinuxCheck Incident Response (REAL)")
        logger.info("  Source: https://github.com/al0ne/LinuxCheck")
        logger.info("=" * 70)
        try:
            from goodware.chainsaw.linuxcheck_integration import LinuxCheckIntegration
            lc = LinuxCheckIntegration()
            if not lc.available:
                logger.error("LinuxCheck not available")
            else:
                result = lc.run(timeout=120)
                print(json.dumps(result, indent=2, default=str))
        except Exception as e:
            logger.error(f"LinuxCheck failed: {e}")


if __name__ == "__main__":
    main()