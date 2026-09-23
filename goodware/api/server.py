"""
Goodware v3.0 - REST API (com endpoints para integrações reais).
"""
from __future__ import annotations
import json
import os
import threading
import time
from typing import Any, Dict

from flask import Flask, jsonify, request
from flask_cors import CORS


def create_app(engine, config) -> Flask:
    app = Flask(__name__)
    CORS(app)

    def find_component(predicate):
        for name, comp in engine._components.items():
            if predicate(comp):
                return comp
        return None

    def find_by_attr(attr):
        for name, comp in engine._components.items():
            if hasattr(comp, attr):
                return comp
        return None

    @app.get("/api/healthz")
    def healthz():
        return jsonify({"ok": True, "ts": time.time()})

    @app.get("/api/status")
    def status():
        return jsonify({"engine": engine.status(), "ts": time.time()})

    @app.get("/api/sensors")
    def sensors():
        out = [{"name": n, "running": getattr(c, "_running", False)} for n, c in engine._components.items()]
        return jsonify({"sensors": out})

    @app.get("/api/events")
    def events():
        limit = int(request.args.get("limit", 100))
        type_ = request.args.get("type")
        severity = request.args.get("severity")
        return jsonify({"events": engine.state.query_events(type_=type_, severity=severity, limit=limit)})

    @app.get("/api/threats")
    def threats():
        return jsonify({"threats": engine.state.list_threats(limit=100)})

    @app.get("/api/predictions")
    def predictions():
        return jsonify({"predictions": engine.state.list_predictions(limit=50)})

    @app.get("/api/quarantine")
    def quarantine():
        return jsonify({"quarantined": engine.state.list_quarantined()})

    @app.get("/api/rules")
    def rules():
        return jsonify({"rules": engine.state.list_rules(enabled_only=False)})

    @app.get("/api/crypto")
    def crypto():
        for name, comp in engine._components.items():
            if hasattr(comp, "pqc"):
                return jsonify(comp.status())
        return jsonify({"error": "crypto manager not found"}), 404

    @app.get("/api/supply_chain")
    def supply_chain():
        for name, comp in engine._components.items():
            if hasattr(comp, "verify_all"):
                return jsonify(comp.verify_all())
        return jsonify({"error": "supply chain not found"}), 404

    @app.get("/api/attestation")
    def attestation():
        for name, comp in engine._components.items():
            if hasattr(comp, "attest_now"):
                return jsonify(comp.attest_now())
        return jsonify({"error": "physical not found"}), 404

    @app.get("/api/immune")
    def immune():
        for name, comp in engine._components.items():
            if hasattr(comp, "evolve_now"):
                return jsonify({"status": comp.status()})
        return jsonify({"error": "immune not found"}), 404

    @app.get("/api/human_factor/status")
    def hf_status():
        for name, comp in engine._components.items():
            if hasattr(comp, "evaluate") and hasattr(comp, "approve"):
                return jsonify(comp.status())
        return jsonify({"error": "human factor not found"}), 404

    @app.post("/api/human_factor/evaluate")
    def hf_evaluate():
        action = request.get_json(force=True) or {}
        for name, comp in engine._components.items():
            if hasattr(comp, "evaluate") and hasattr(comp, "approve"):
                return jsonify(comp.evaluate(action))
        return jsonify({"error": "not found"}), 404

    @app.post("/api/human_factor/approve")
    def hf_approve():
        data = request.get_json(force=True) or {}
        rid = data.get("request_id")
        admin = data.get("admin_id", "admin")
        for name, comp in engine._components.items():
            if hasattr(comp, "evaluate") and hasattr(comp, "approve"):
                return jsonify(comp.approve(rid, admin))
        return jsonify({"error": "not found"}), 404

    @app.post("/api/decision/decide")
    def decision():
        ev = request.get_json(force=True) or {}
        for name, comp in engine._components.items():
            if hasattr(comp, "decide"):
                return jsonify(comp.decide(ev))
        return jsonify({"error": "decision not found"}), 404

    @app.post("/api/effector/execute")
    def execute():
        action = request.get_json(force=True) or {}
        for name, comp in engine._components.items():
            if hasattr(comp, "execute_action"):
                return jsonify(comp.execute_action(action))
        return jsonify({"error": "effector not found"}), 404

    @app.post("/api/chainsaw/scan")
    def chainsaw_scan():
        data = request.get_json(force=True) or {}
        path = data.get("path")
        if not path:
            return jsonify({"error": "path required"}), 400
        for name, comp in engine._components.items():
            if hasattr(comp, "process_file"):
                return jsonify(comp.process_file(path))
        return jsonify({"error": "chainsaw not found"}), 404

    # ===== NEW: real integrations =====
    @app.post("/api/chainsaw/scan_rootkit")
    def scan_rootkit():
        for name, comp in engine._components.items():
            if hasattr(comp, "scan_rootkit"):
                return jsonify(comp.scan_rootkit())
        return jsonify({"error": "not found"}), 404

    @app.get("/api/chainsaw/cis")
    def cis_benchmark():
        for name, comp in engine._components.items():
            if hasattr(comp, "run_cis"):
                return jsonify(comp.run_cis())
        return jsonify({"error": "not found"}), 404

    @app.post("/api/effector/kill")
    def kill_process():
        data = request.get_json(force=True) or {}
        pid = data.get("pid")
        if not pid:
            return jsonify({"error": "pid required"}), 400
        for name, comp in engine._components.items():
            if hasattr(comp, "quarantine") and hasattr(comp.quarantine, "kill_process"):
                return jsonify(comp.quarantine.kill_process(int(pid)))
        return jsonify({"error": "not found"}), 404

    @app.post("/api/effector/kill_tree")
    def kill_tree():
        data = request.get_json(force=True) or {}
        pid = data.get("pid")
        if not pid:
            return jsonify({"error": "pid required"}), 400
        for name, comp in engine._components.items():
            if hasattr(comp, "quarantine") and hasattr(comp.quarantine, "kill_process_tree"):
                return jsonify(comp.quarantine.kill_process_tree(int(pid)))
        return jsonify({"error": "not found"}), 404

    @app.post("/api/effector/restore")
    def restore():
        data = request.get_json(force=True) or {}
        qid = data.get("id")
        for name, comp in engine._components.items():
            if hasattr(comp, "quarantine") and hasattr(comp.quarantine, "restore"):
                return jsonify(comp.quarantine.restore(qid))
        return jsonify({"error": "not found"}), 404

    @app.get("/api/firewall/snapshot")
    def firewall_snap():
        for name, comp in engine._components.items():
            if hasattr(comp, "firewall") and hasattr(comp.firewall, "snapshot"):
                return jsonify(comp.firewall.snapshot())
        return jsonify({"error": "no firewall"}), 404

    @app.post("/api/honeypot/start")
    def honeypot_start():
        for name, comp in engine._components.items():
            if hasattr(comp, "start_all") and hasattr(comp, "captures"):
                return jsonify(comp.start_all())
        return jsonify({"error": "no honeypot"}), 404

    @app.post("/api/honeypot/stop")
    def honeypot_stop():
        for name, comp in engine._components.items():
            if hasattr(comp, "stop_all"):
                return jsonify({"ok": True})
        return jsonify({"error": "no honeypot"}), 404

    @app.get("/api/honeypot/captures")
    def honeypot_captures():
        for name, comp in engine._components.items():
            if hasattr(comp, "captures"):
                return jsonify({"captures": comp.captures()})
        return jsonify({"error": "no honeypot"}), 404

    @app.get("/api/honeypot/status")
    def honeypot_status():
        for name, comp in engine._components.items():
            if hasattr(comp, "status") and hasattr(comp, "captures"):
                return jsonify(comp.status())
        return jsonify({"error": "no honeypot"}), 404

    @app.post("/api/auditd/watch")
    def auditd_watch():
        data = request.get_json(force=True) or {}
        path = data.get("path")
        if not path:
            return jsonify({"error": "path required"}), 400
        for name, comp in engine._components.items():
            if hasattr(comp, "add_audit_watch"):
                return jsonify(comp.add_audit_watch(path))
        return jsonify({"error": "no auditd manager"}), 404

    @app.get("/api/auditd/recent")
    def auditd_recent():
        for name, comp in engine._components.items():
            if hasattr(comp, "query_audit_recent"):
                return jsonify(comp.query_audit_recent())
        return jsonify({"error": "no auditd manager"}), 404

    @app.post("/api/immune/evolve")
    def immune_evolve():
        for name, comp in engine._components.items():
            if hasattr(comp, "evolve_now"):
                return jsonify(comp.evolve_now())
        return jsonify({"error": "immune not found"}), 404

    @app.get("/api/crypto/real_pqc")
    def real_pqc_status():
        try:
            from goodware.crypto.real_pqc import RealPQC
            r = RealPQC()
            return jsonify(r.status())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # === Crypto endpoints extra ===
    @app.post("/api/crypto/real_pqc/roundtrip")
    def real_pqc_roundtrip():
        try:
            from goodware.crypto.real_pqc import RealPQC
            r = RealPQC()
            alg = (request.json or {}).get("alg")
            if alg:
                pk, sk, a = r.kem_keypair(alg)
            else:
                pk, sk, a = r.kem_keypair()
            ct, ss1 = r.kem_encaps(pk)
            ss2 = r.kem_decaps(sk, ct)
            # also sig roundtrip
            spk, ssk, sa = r.sig_keypair()
            sig = r.sig_sign(ssk, b"goodware-attest-test")
            ok = r.sig_verify(spk, b"goodware-attest-test", sig)
            return jsonify({
                "kem_alg": a,
                "kem_match": ss1 == ss2,
                "pk_bytes": len(pk),
                "ct_bytes": len(ct),
                "ss_bytes": len(ss1),
                "sig_alg": sa,
                "sig_verify": ok,
                "sig_bytes": len(sig),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # === LLM Brain (DeepSeek) ===
    try:
        from goodware.llm.api import register_llm_routes
        register_llm_routes(app)
    except Exception as _e:
        # DeepSeek não disponível, registar apenas status que devolve 503
        @app.get("/api/llm/status")
        def llm_status_unavailable():
            return jsonify({"available": False, "error": str(_e)}), 503

    @app.post("/api/crypto/seal")
    def crypto_seal():
        try:
            payload = (request.json or {}).get("data", "")
            from goodware.crypto import CryptoManager
            cm = engine._components.get("crypto")
            if not cm:
                return jsonify({"error": "crypto not started"}), 503
            blob = cm.seal(payload.encode() if isinstance(payload, str) else payload)
            return jsonify({"sealed": blob.hex() if isinstance(blob, bytes) else blob})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/crypto/open")
    def crypto_open():
        try:
            blob_hex = (request.json or {}).get("blob", "")
            blob = bytes.fromhex(blob_hex)
            from goodware.crypto import CryptoManager
            cm = engine._components.get("crypto")
            if not cm:
                return jsonify({"error": "crypto not started"}), 503
            out = cm.open(blob)
            return jsonify({"data": out.decode(errors='replace') if isinstance(out, bytes) else out})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # === Supply chain endpoints ===
    @app.get("/api/supply_chain")
    def supply_chain_list():
        for name, comp in engine._components.items():
            if hasattr(comp, "list_components"):
                return jsonify({"items": comp.list_components()})
        # fall back: scan directory
        try:
            items = []
            import os
            sbom_dir = os.path.join(engine._config.get("paths.data_dir", "data"), "sbom")
            if os.path.isdir(sbom_dir):
                for f in os.listdir(sbom_dir)[:50]:
                    items.append({"name": f, "version": "?", "license": "?", "signed": False, "verified": False})
            return jsonify({"items": items})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/supply_chain/verify")
    def supply_chain_verify():
        try:
            name = (request.json or {}).get("name", "")
            for n, c in engine._components.items():
                if hasattr(c, "verify_artifact"):
                    return jsonify(c.verify_artifact(name))
            return jsonify({"name": name, "verified": False, "reason": "no verifier component"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # === Serve frontend SPA ===
    @app.get("/")
    @app.get("/<path:path>")
    def serve_frontend(path="index.html"):
        import os
        frontend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend"))
        if not os.path.isdir(frontend_dir):
            return jsonify({"error": "frontend not built", "path": frontend_dir}), 404
        if not path or path == "/":
            path = "index.html"
        # segurança: bloquear traversal
        full = os.path.normpath(os.path.join(frontend_dir, path))
        if not full.startswith(frontend_dir):
            return jsonify({"error": "forbidden"}), 403
        if not os.path.isfile(full):
            # fallback SPA — index.html para client-side routing
            full = os.path.join(frontend_dir, "index.html")
        ext = os.path.splitext(full)[1].lower()
        ct_map = {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".mjs": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".json": "application/json",
        }
        ct = ct_map.get(ext, "application/octet-stream")
        with open(full, "rb") as f:
            return f.read(), 200, {"Content-Type": ct, "Cache-Control": "no-cache"}

    return app


def start_api(engine, config, host: str = "127.0.0.1", port: int = 8444):
    app = create_app(engine, config)
    t = threading.Thread(target=app.run, kwargs={"host": host, "port": port, "debug": False, "use_reloader": False}, daemon=True, name="api")
    t.start()
    return t
