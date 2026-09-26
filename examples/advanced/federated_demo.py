"""
Advanced Example: Federated learning simulation.

Simulates 3 clients training locally and aggregating at server.
Demonstrates FedAvg + DP noise + HMAC integrity.
"""
import sys
sys.path.insert(0, '/workspace/goodware-v3')

import numpy as np
from goodware.federated.aggregation import SecureAggregator, DifferentialPrivacy

# 3 clients with different training data
np.random.seed(42)
gradients = [
    np.random.randn(100).astype(np.float32),
    np.random.randn(100).astype(np.float32) + 0.5,
    np.random.randn(100).astype(np.float32) - 0.3,
]

# Differential Privacy
dp = DifferentialPrivacy(epsilon=1.0, delta=1e-5)
noisy_gradients = [dp.add_noise(g) for g in gradients]

# Secure aggregation with HMAC
agg = SecureAggregator()
result = agg.aggregate(noisy_gradients)
print(f"Aggregated gradient (FedAvg + DP): {result.shape}")
print(f"Mean: {result.mean():.4f}, Std: {result.std():.4f}")

# Verify HMAC
hmac_ok = agg.verify_hmac(noisy_gradients, result)
print(f"HMAC integrity: {hmac_ok}")
