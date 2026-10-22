"""Real NSL-KDD inference benchmark. Run only after model training in CI."""
import json
import shutil
import tempfile
import time
from pathlib import Path
from goodware.core.config import GoodwareConfig
from goodware.prediction.training.train_nsl_kdd import load_nsl_kdd
from goodware.prediction.threat_predictor import ThreatPredictor

ROOT = Path(__file__).resolve().parents[1]
FILES = ["threat_predictor_nsl_kdd.joblib", "anomaly_detector_nsl_kdd.joblib",
         "scaler_nsl_kdd.joblib", "encoder_protocol_type.joblib", "encoder_service.joblib",
         "encoder_flag.joblib", "training_metadata_nsl_kdd.json"]

def main():
    models = ROOT / "models"
    data = ROOT / "NSL_KDD" / "KDDTest+.txt"
    if not data.is_file() or any(not (models / f).is_file() for f in FILES):
        raise SystemExit("Real NSL-KDD dataset/model artifacts are required; refusing synthetic benchmark")
    with tempfile.TemporaryDirectory() as td:
        for name in FILES:
            shutil.copy2(models / name, Path(td) / name)
        cfg = GoodwareConfig.load()
        cfg.set("prediction.model_dir", td)
        predictor = ThreatPredictor("benchmark", cfg)
        if not predictor.model_loaded or predictor.model_source != "nsl_kdd" or predictor.synthetic_fallback:
            raise SystemExit("Real NSL-KDD model did not load")
        frame = load_nsl_kdd(str(data))
        rows = frame.head(500)
        flows = []
        for _, row in rows.iterrows():
            flow = row.to_dict()
            flows.append({k: (v.item() if hasattr(v, "item") else v) for k, v in flow.items()
                          if k not in {"label", "difficulty", "is_attack", "attack_category"}})
        samples = []
        for flow in flows[:25]:
            predictor.predict_network_flow(flow)
        start_all = time.perf_counter()
        for flow in flows:
            start = time.perf_counter_ns()
            result = predictor.predict_network_flow(flow)
            samples.append((time.perf_counter_ns() - start) / 1e6)
            if result.get("threat_type") not in {"normal", "attack"}:
                raise SystemExit(f"Inference failed: {result}")
        elapsed = time.perf_counter() - start_all
        ordered = sorted(samples)
        def pct(p): return round(ordered[min(len(ordered)-1, int((p/100)*len(ordered)))], 4)
        report = {"dataset":"NSL-KDD KDDTest+", "model":"real nsl_kdd", "samples":len(samples),
                  "elapsed_seconds":round(elapsed,6), "throughput_per_second":round(len(samples)/elapsed,3),
                  "latency_ms":{"p50":pct(50),"p95":pct(95),"p99":pct(99),"max":round(max(samples),4)},
                  "synthetic_fallback":False,
                  "note":"Measurements are specific to this CI runner, not a production SLA."}
        out = ROOT / "benchmark-results" / "ml-inference.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        print(f"Benchmark saved: {out}")
if __name__ == "__main__":
    main()
