"""
Goodware v3.0 - Behavioral biometrics (keystroke + mouse dynamics).
"""
from __future__ import annotations
import json
import os


class BehavioralBiometrics:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.path = os.path.join(data_dir, "behavioral.json")
        self._baselines = self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        try:
            with open(self.path, "w") as f:
                json.dump(self._baselines, f, indent=2)
        except Exception:
            pass

    def list_users(self):
        return list(self._baselines.keys())

    def ensure_default_baseline(self, user):
        if user not in self._baselines:
            self.enroll(user, [
                {"dwell_times": [0.10, 0.12, 0.11, 0.10], "flight_times": [0.05, 0.06, 0.05], "mouse_speed_samples": [1.0, 1.1, 0.95]}
            ] * 5)

    def enroll(self, user, samples):
        feats = [self._features(s) for s in samples]
        if not feats:
            return
        n_feat = len(feats[0])
        means = [sum(f[i] for f in feats) / len(feats) for i in range(n_feat)]
        stds = [max(0.01, (sum((f[i] - means[i]) ** 2 for f in feats) / len(feats)) ** 0.5) for i in range(n_feat)]
        self._baselines[user] = {"mean": means, "std": stds, "samples": len(samples)}
        self._save()

    def _features(self, sample):
        d = sample.get("dwell_times", [])
        f = sample.get("flight_times", [])
        m = sample.get("mouse_speed_samples", [])

        def stat(xs, default=0.0):
            return (sum(xs) / len(xs) if xs else default,
                    max(xs) if xs else default,
                    min(xs) if xs else default,
                    len(xs))

        ds = stat(d, 0.1)
        fs = stat(f, 0.05)
        ms = stat(m, 1.0)
        return [ds[0], ds[1], ds[2], fs[0], fs[1], fs[2], ms[0], ms[1], ms[2], len(d) + len(f) + len(m)]

    def verify(self, user, sample):
        if user not in self._baselines:
            self.ensure_default_baseline(user)
        base = self._baselines[user]
        f = self._features(sample)
        if len(f) != len(base["mean"]):
            return {"score": 0.0, "match": False}
        dist = sum(abs(f[i] - base["mean"][i]) / max(base["std"][i], 0.01) for i in range(len(f)))
        score = max(0.0, min(1.0, 1.0 - dist / (len(f) * 2)))
        return {"score": score, "match": score > 0.5, "distance": dist}
