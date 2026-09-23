"""
Goodware v3.0 - Exemplo de cliente API.
Demonstra como integrar o Goodware noutras aplicações.

Uso:
  GW_PORT=18444 python3 examples/api_client.py
"""
import json
import os
import time
import requests


API = f"http://127.0.0.1:{os.environ.get('GW_PORT', '8444')}/api"


def banner(msg):
    print()
    print("=" * 70)
    print(f"  {msg}")
    print("=" * 70)


def post(path, body):
    r = requests.post(f"{API}{path}", json=body, timeout=5)
    return r.json()


def get(path):
    r = requests.get(f"{API}{path}", timeout=5)
    return r.json()


def main():
    banner("1. HEALTH")
    print(get("/healthz"))

    banner("2. STATUS")
    st = get("/status")
    print(f"componentes: {len(st['engine']['components'])}")
    print(f"eventos no bus: {st['engine']['bus']['history_size']}")

    banner("3. SENSORES")
    for s in get("/sensors")["sensors"]:
        print(f"  {s['name']:15s} {'● running' if s['running'] else '○ stopped'}")

    banner("4. CRYPTO PQC")
    print(json.dumps(get("/crypto"), indent=2))

    banner("5. ATESTAÇÃO HW")
    a = get("/attestation")
    print(f"  TPM: {a['attestation']['tpm_present']}")
    print(f"  secure boot: {a['attestation']['secure_boot']}")
    print(f"  trust_level: {a['attestation']['trust_level']}")
    print(f"  DMA/IOMMU: {a['dma_prevention']['iommu_enabled']}")

    banner("6. SUPPLY CHAIN (SBOM)")
    sbom = get("/supply_chain")["sbom"]
    print(f"  verificados: {sbom['verified']}")
    print(f"  falhados: {sbom['failed']}")

    banner("7. PREDIÇÕES (top 3)")
    for p in get("/predictions")["predictions"][:3]:
        print(f"  {p['threat_type']:30s} risk={p['risk_score']:.2f} conf={p['confidence']:.2f}")

    banner("8. DECISÃO — evento de alta severidade")
    print(json.dumps(post("/decision/decide", {
        "severity": "critical",
        "type": "sensor.process_anomaly",
        "payload": {"cve": "CVE-2024-3094", "anomaly_score": 0.95}
    }), indent=2))

    banner("9. HUMAN FACTOR — delete_user em hora suspeita")
    res = post("/human_factor/evaluate", {
        "action": "delete_user", "user": "admin",
        "location": "unknown", "time_of_day": 3, "device_id": "unknown"
    })
    print(f"  decision: {res['decision']}")
    print(f"  risk_score: {res['risk_score']:.2f}")
    print(f"  request_id: {res.get('request_id')}")
    if res.get("request_id"):
        print("  a aprovar como admin1:", post("/human_factor/approve", {
            "request_id": res["request_id"], "admin_id": "admin1"
        }))

    banner("10. EFETOR — quarantine + block + snapshot")
    print("  block SMB:", post("/effector/execute", {
        "type": "block_port", "target": "445", "reason": "ransomware_precursor"
    }))
    print("  snapshot:", post("/effector/execute", {
        "type": "snapshot", "paths": ["/etc/passwd"], "reason": "pre-change"
    }))

    banner("11. CHAINSAW — análise de /etc/passwd")
    cs = post("/chainsaw/scan", {"path": "/etc/passwd"})
    print(f"  risk: {cs['analysis']['risk']}")
    print(f"  sha256: {cs['analysis']['hashes']['sha256']}")
    print(f"  size: {cs['analysis']['size']}")

    banner("12. IMMUNE — evolução")
    ev = post("/immune/evolve", {})
    print(f"  rules_count: {ev['rules_count']}")
    print(f"  top_patterns: {ev['top_patterns'][:3]}")

    banner("13. EVENTOS RECENTES (últimos 5)")
    for e in get("/events?limit=5")["events"]:
        ts = e['timestamp']
        from datetime import datetime
        when = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        print(f"  {when}  {e['type']:30s} {e['severity']:8s} {e['source']}")


if __name__ == "__main__":
    main()
