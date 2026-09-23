"""Secure aggregation with differential privacy."""
from __future__ import annotations
import numpy as np


class DifferentialPrivacy:
    @staticmethod
    def compute_sigma(epsilon: float, delta: float, sensitivity: float = 1.0) -> float:
        return sensitivity * np.sqrt(2 * np.log(1.25 / delta)) / epsilon

    @staticmethod
    def privatize(grad: np.ndarray, epsilon: float = 1.0, delta: float = 1e-5) -> np.ndarray:
        sigma = DifferentialPrivacy.compute_sigma(epsilon, delta)
        noise = np.random.normal(0, sigma, grad.shape)
        return grad + noise


class SecureAggregator:
    @staticmethod
    def clip(grad: np.ndarray, norm: float = 1.0) -> np.ndarray:
        n = float(np.linalg.norm(grad))
        if n > norm and n > 0:
            return grad * (norm / n)
        return grad

    @staticmethod
    def aggregate(updates: list) -> dict:
        """FedAvg: weighted by sample_count. Each update: {gradient, sample_count, node_id}"""
        if not updates:
            return {"version": 0, "model": None, "n": 0}
        total = sum(u.get("sample_count", 1) for u in updates)
        agg = None
        for u in updates:
            g = np.array(u["gradient"], dtype=float)
            w = u.get("sample_count", 1) / total
            contrib = g * w
            agg = contrib if agg is None else agg + contrib
        return {
            "version": int(max([u.get("version", 0) for u in updates]) + 1),
            "model": agg.tolist(),
            "n": len(updates),
            "total_samples": total,
        }
