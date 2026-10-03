"""
Goodware v3.0 — Tests for LLM Auto-Fallback Chain + Keystroke Biometrics Integration.

Verifies:
  - GPU detection (nvidia-smi, Ollama, vLLM, llama.cpp)
  - LLMFallbackChain discovers and prioritizes providers correctly
  - When cloud API is unavailable, ask_user response is returned with instructions
  - Real keystroke biometrics model (njanakiev) loads and verifies
"""
import os
import sys
import unittest

# Make repo root importable
ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, ROOT)


class TestGPUDetection(unittest.TestCase):
    def test_detect_all_returns_dict(self):
        from goodware.llm.providers import GPUDetector
        result = GPUDetector.detect_all()
        self.assertIsInstance(result, dict)
        self.assertIn("gpu", result)
        self.assertIn("ollama", result)
        self.assertIn("vllm", result)
        self.assertIn("llamacpp", result)
        self.assertIn("any_local_llm", result)
        self.assertIn("any_gpu", result)


class TestLLMFallbackChain(unittest.TestCase):
    def setUp(self):
        # Ensure no API key and no local LLM for predictable test
        self._saved_api = os.environ.pop("GOODWARE_LLM_API_KEY", None)
        self._saved_deepseek = os.environ.pop("DEEPSEEK_API_KEY", None)
        os.environ.pop("GOODWARE_OLLAMA_MODEL", None)

    def tearDown(self):
        if self._saved_api:
            os.environ["GOODWARE_LLM_API_KEY"] = self._saved_api
        if self._saved_deepseek:
            os.environ["DEEPSEEK_API_KEY"] = self._saved_deepseek

    def test_chain_discovers_providers(self):
        from goodware.llm.providers import LLMFallbackChain
        chain = LLMFallbackChain()
        status = chain.status()
        self.assertIn("providers", status)
        # Should have at least ask_user
        names = [p["name"] for p in status["providers"]]
        self.assertIn("ask_user", names)
        self.assertIn("cloud_api", names)
        self.assertIn("local_gpu", names)

    def test_chain_returns_ask_user_when_no_providers(self):
        from goodware.llm.providers import LLMFallbackChain
        chain = LLMFallbackChain()
        # Force the chain to be in "no providers" state by clearing all
        for p in chain.providers:
            p.available = False
        result = chain.invoke("test prompt")
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("needs_user_action"))
        self.assertIn("instructions", result)

    def test_chain_instructions_contain_ollama_setup(self):
        from goodware.llm.providers import LLMFallbackChain
        chain = LLMFallbackChain()
        for p in chain.providers:
            p.available = False
        result = chain.invoke("test prompt")
        instructions = result.get("instructions", "")
        self.assertIn("Ollama", instructions)
        self.assertIn("ollama", instructions.lower())
        self.assertIn("GOODWARE_LLM_API_KEY", instructions)

    def test_chain_status_includes_gpu_info(self):
        from goodware.llm.providers import LLMFallbackChain
        chain = LLMFallbackChain()
        status = chain.status()
        self.assertIn("detected_resources", status)
        self.assertIn("gpu", status["detected_resources"])

    def test_api_key_detection(self):
        os.environ["GOODWARE_LLM_API_KEY"] = "test-key-123"
        from goodware.llm.providers import LLMFallbackChain
        chain = LLMFallbackChain()
        cloud = next(p for p in chain.providers if p.name == "cloud_api")
        self.assertTrue(cloud.available)
        self.assertEqual(cloud.config["api_key"], "test-key-123")
        del os.environ["GOODWARE_LLM_API_KEY"]


class TestKeystrokeBiometricsIntegration(unittest.TestCase):
    def test_repo_bundled(self):
        from goodware.human_factor.keystroke_biometrics_integration import (
            KeystrokeBiometricsIntegration,
        )
        ki = KeystrokeBiometricsIntegration()
        self.assertTrue(ki.available)
        # Should have 36 .h5 models (after filtering)
        status = ki.status()
        self.assertGreater(status["models_bundled"], 30)

    def test_load_training_data(self):
        from goodware.human_factor.keystroke_biometrics_integration import (
            KeystrokeBiometricsIntegration,
        )
        ki = KeystrokeBiometricsIntegration()
        ok = ki.load_training_data()
        self.assertTrue(ok)
        self.assertEqual(len(ki._subjects), 51)  # 51 real subjects
        self.assertIn("total", ki._train_data)
        self.assertIn("H", ki._train_data)
        self.assertIn("DD", ki._train_data)
        self.assertIn("UD", ki._train_data)
        self.assertIn("pca3", ki._train_data)
        self.assertIn("pca10", ki._train_data)

    def test_train_baseline_real(self):
        from goodware.human_factor.keystroke_biometrics_integration import (
            KeystrokeBiometricsIntegration,
        )
        ki = KeystrokeBiometricsIntegration()
        ki.load_training_data()
        model = ki.train_baseline_model("total", n_estimators=100)
        self.assertIsNotNone(model)
        # Trained on 51 subjects
        self.assertEqual(len(model.classes_), 51)
        # 31 features in total set
        self.assertEqual(model.n_features_in_, 31)

    def test_verify_with_real_sample(self):
        from goodware.human_factor.keystroke_biometrics_integration import (
            KeystrokeBiometricsIntegration,
        )
        ki = KeystrokeBiometricsIntegration()
        ki.load_training_data()
        # Take a real sample from the dataset
        sample = ki._train_data["total"][0].tolist()
        result = ki.verify_with_keyboard("total", sample)
        self.assertTrue(result["real"])
        self.assertIn("predicted_user", result)
        self.assertIn("confidence", result)
        self.assertIn("top_3", result)
        # With 51 classes, even in-sample confidence may be modest
        # but top_3 should have a meaningful probability distribution
        self.assertGreater(len(result["top_3"]), 0)
        # Sum of top_3 probabilities should be meaningful
        top3_sum = sum(t["probability"] for t in result["top_3"])
        self.assertGreater(top3_sum, 0.1)

    def test_integration_with_behavioral_biometrics(self):
        from goodware.human_factor.behavioral_biometrics import BehavioralBiometrics
        bb = BehavioralBiometrics()
        # Switch to external model
        ok = bb.use_external_keystroke_model()
        # Returns True if repo is available
        self.assertTrue(ok)
        # Status should include external model info
        s = bb.status()
        self.assertIn("external_keystroke_model", s)
        self.assertIsNotNone(s["external_keystroke_model"])
        self.assertTrue(s["external_keystroke_model"]["available"])


class TestBrainIntegration(unittest.TestCase):
    def test_brain_has_fallback_chain(self):
        from goodware.llm.brain import GoodwareBrain
        brain = GoodwareBrain()
        # Should have fallback chain
        self.assertIsNotNone(brain.fallback_chain)
        # Should have status method
        status = brain.llm_provider_status()
        self.assertIn("providers", status)
        self.assertIn("detected_resources", status)


if __name__ == "__main__":
    unittest.main(verbosity=2)