"""
Goodware v3.0 — Testes do LLM Brain (DeepSeek Harness oficial).

Testa:
- SDK oficial (importação, classes, dataclasses)
- HarnessAdapter (config, lifecycle, erro sem runtime)
- GoodwareBrain (sem fallbacks — levanta RuntimeError se Harness não está)
- API endpoints
"""
from __future__ import annotations
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# SDK oficial
# ============================================================================
class TestOfficialSDK(unittest.TestCase):
    def test_001_sdk_imports(self):
        """SDK oficial do DeepSeek Harness importa sem erros."""
        from goodware.llm.harness import (
            DeepSeekHarness, DeepSeekHarnessConfig, RunResult, Session,
            HarnessClient, HarnessConfig, SdkProtocolError,
        )
        self.assertIsNotNone(DeepSeekHarness)
        self.assertIsNotNone(DeepSeekHarnessConfig)
        self.assertIsNotNone(RunResult)
        self.assertIsNotNone(HarnessClient)
        self.assertIsNotNone(SdkProtocolError)

    def test_002_config_defaults(self):
        from goodware.llm.harness import DeepSeekHarnessConfig
        c = DeepSeekHarnessConfig()
        self.assertEqual(c.provider, "deepseek-official")
        self.assertEqual(c.model, "deepseek-v4-flash")
        self.assertIsNone(c.api_key)
        self.assertIsNone(c.base_url)

    def test_003_config_custom(self):
        from goodware.llm.harness import DeepSeekHarnessConfig
        c = DeepSeekHarnessConfig(provider="x", model="y", max_tokens=4096)
        self.assertEqual(c.provider, "x")
        self.assertEqual(c.model, "y")
        self.assertEqual(c.max_tokens, 4096)

    def test_004_runresult_dataclass(self):
        from goodware.llm.harness import RunResult
        r = RunResult(session_id="s1", final_response="hi", finish_reason="completed",
                      events=[], notifications=[], session_root=None)
        self.assertEqual(r.session_id, "s1")
        self.assertEqual(r.final_response, "hi")
        self.assertEqual(r.finish_reason, "completed")

    def test_005_harness_config_dataclass(self):
        from goodware.llm.harness import HarnessConfig
        c = HarnessConfig(cwd="/tmp")
        self.assertEqual(c.cwd, "/tmp")

    def test_006_module_paths(self):
        """Garantir que o SDK tem a estrutura de módulos esperada."""
        import goodware.llm.harness as h
        self.assertTrue(hasattr(h, "DeepSeekHarness"))
        self.assertTrue(hasattr(h, "DeepSeekHarnessConfig"))
        self.assertTrue(hasattr(h, "RunResult"))


# ============================================================================
# HarnessAdapter
# ============================================================================
class TestHarnessAdapter(unittest.TestCase):
    def setUp(self):
        # garantir que não há env vars (para testar o caso "sem API key")
        self._saved_keys = {}
        for k in ("DEEPSEEK_API_KEY", "NVIDIA_API_KEY"):
            if k in os.environ:
                self._saved_keys[k] = os.environ[k]
                del os.environ[k]

    def tearDown(self):
        for k, v in self._saved_keys.items():
            os.environ[k] = v

    def test_010_adapter_instantiates_without_key(self):
        """Adapter pode ser criado sem API key (mas não inicia)."""
        from goodware.llm.harness_adapter import HarnessAdapter
        a = HarnessAdapter()
        self.assertIsNotNone(a)
        self.assertFalse(a.is_available())

    def test_011_init_error_when_no_key(self):
        from goodware.llm.harness_adapter import HarnessAdapter
        a = HarnessAdapter()
        ok = a.start()
        self.assertFalse(ok)
        self.assertIsNotNone(a.init_error())

    def test_012_get_harness_returns_none_without_key(self):
        from goodware.llm.harness_adapter import get_harness
        self.assertIsNone(get_harness())

    def test_013_init_harness_returns_none_without_key(self):
        from goodware.llm.harness_adapter import init_harness
        self.assertIsNone(init_harness())

    def test_014_adapter_with_key_attempts_init(self):
        from goodware.llm.harness_adapter import HarnessAdapter
        os.environ["DEEPSEEK_API_KEY"] = "test-key"
        a = HarnessAdapter()
        # vai tentar iniciar mas o runtime não existe no sandbox
        ok = a.start()
        # não crashar mesmo se falhar
        self.assertIsNotNone(a)
        # se falhou, init_error tem mensagem
        if not ok:
            self.assertIsNotNone(a.init_error())
        else:
            # ou sucesso (em ambiente com runtime)
            self.assertTrue(a.is_available())
        # cleanup
        a.close()

    def test_015_adapter_stats(self):
        from goodware.llm.harness_adapter import HarnessAdapter
        a = HarnessAdapter()
        s = a.stats()
        self.assertIn("runs", s)
        self.assertIn("errors", s)
        self.assertEqual(s["runs"], 0)

    def test_016_adapter_close_safe_when_not_started(self):
        from goodware.llm.harness_adapter import HarnessAdapter
        a = HarnessAdapter()
        a.close()  # não deve crashar
        a.close()  # idempotente

    def test_017_adapter_context_manager(self):
        from goodware.llm.harness_adapter import HarnessAdapter
        # sem key, vai falhar a start, mas context manager não deve crashar
        with HarnessAdapter() as a:
            pass
        self.assertIsNotNone(a)


# ============================================================================
# GoodwareBrain — SEM FALLBACKS
# ============================================================================
class TestGoodwareBrain(unittest.TestCase):
    def setUp(self):
        # reset de tudo
        import goodware.llm.brain as b_mod
        import goodware.llm.harness_adapter as h_mod
        b_mod._brain = None
        h_mod._singleton = None
        self._saved_keys = {}
        for k in ("DEEPSEEK_API_KEY", "NVIDIA_API_KEY"):
            if k in os.environ:
                self._saved_keys[k] = os.environ[k]
                del os.environ[k]

    def tearDown(self):
        for k, v in self._saved_keys.items():
            os.environ[k] = v

    def test_020_brain_get_returns_none_without_key(self):
        from goodware.llm.brain import get_brain
        self.assertIsNone(get_brain())

    def test_021_brain_explain_raises_without_harness(self):
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        self.assertFalse(b.available)
        with self.assertRaises(RuntimeError):
            b.explain_event({"type": "x"})

    def test_022_brain_triage_raises_without_harness(self):
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        with self.assertRaises(RuntimeError):
            b.triage({"type": "x"})

    def test_023_brain_decide_raises_without_harness(self):
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        with self.assertRaises(RuntimeError):
            b.decide({"type": "x"})

    def test_024_brain_summarise_empty_works(self):
        """summarise com lista vazia não chama o LLM — devolve sem erro."""
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        # com lista vazia, devolve sem chamar o LLM
        r = b.summarise_incidents([])
        self.assertEqual(r["incident_count"], 0)

    def test_025_brain_summarise_raises_without_harness(self):
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        with self.assertRaises(RuntimeError):
            b.summarise_incidents([{"type": "x"}])

    def test_026_brain_yara_raises_without_harness(self):
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        with self.assertRaises(RuntimeError):
            b.generate_yara_rule({"hash": "abc"})

    def test_027_brain_close_safe(self):
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        b.close()  # não deve crashar
        b.close()

    def test_028_system_prompts_defined(self):
        from goodware.llm import brain
        self.assertIn("português", brain.SYSTEM_EXPLAIN.lower())
        self.assertIn("severity", brain.SYSTEM_TRIAGE.lower())
        self.assertIn("action", brain.SYSTEM_DECIDE.lower())
        self.assertIn("sumário", brain.SYSTEM_SUMMARISE.lower())
        self.assertIn("yara", brain.SYSTEM_YARA.lower())

    def test_029_shutdown_brain_safe(self):
        from goodware.llm import brain
        brain.shutdown_brain()  # não crashar mesmo sem brain


# ============================================================================
# API REST
# ============================================================================
class TestLLMAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from goodware.core.engine import Engine
        from goodware.core.config import GoodwareConfig
        from goodware.api.server import create_app
        cls.eng = Engine(GoodwareConfig())
        app = create_app(cls.eng, GoodwareConfig())
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        try: cls.eng.stop()
        except: pass

    def setUp(self):
        # resetar singletons
        import goodware.llm.brain as b_mod
        import goodware.llm.harness_adapter as h_mod
        b_mod._brain = None
        h_mod._singleton = None
        self._saved_keys = {}
        for k in ("DEEPSEEK_API_KEY", "NVIDIA_API_KEY"):
            if k in os.environ:
                self._saved_keys[k] = os.environ[k]
                del os.environ[k]

    def tearDown(self):
        for k, v in self._saved_keys.items():
            os.environ[k] = v

    def test_030_status_503_without_key(self):
        r = self.client.get("/api/llm/status")
        # sem API key, deve dar 503 com erro claro
        self.assertEqual(r.status_code, 503)
        body = r.get_json()
        self.assertFalse(body["available"])
        self.assertIn("Harness", body["error"])

    def test_031_explain_503_without_key(self):
        r = self.client.post("/api/llm/explain", json={"type": "x"})
        self.assertEqual(r.status_code, 503)

    def test_032_triage_503_without_key(self):
        r = self.client.post("/api/llm/triage", json={"type": "x"})
        self.assertEqual(r.status_code, 503)

    def test_033_decide_503_without_key(self):
        r = self.client.post("/api/llm/decide", json={"type": "x"})
        self.assertEqual(r.status_code, 503)

    def test_034_summarise_503_without_key(self):
        r = self.client.post("/api/llm/summarise", json={"incidents": [{"type": "x"}]})
        self.assertEqual(r.status_code, 503)

    def test_035_yara_503_without_key(self):
        r = self.client.post("/api/llm/generate-yara", json={"sample": {"hash": "abc"}})
        self.assertEqual(r.status_code, 503)

    def test_036_shutdown_endpoint(self):
        r = self.client.post("/api/llm/shutdown")
        self.assertEqual(r.status_code, 200)


# ============================================================================
# Integração com engine (eventos do Goodware → LLM)
# ============================================================================
class TestEngineIntegration(unittest.TestCase):
    """Comprova que o LLM brain pode ser plugado no engine e reagir a eventos."""

    def setUp(self):
        import goodware.llm.brain as b_mod
        import goodware.llm.harness_adapter as h_mod
        b_mod._brain = None
        h_mod._singleton = None
        self._saved_keys = {}
        for k in ("DEEPSEEK_API_KEY", "NVIDIA_API_KEY"):
            if k in os.environ:
                self._saved_keys[k] = os.environ[k]
                del os.environ[k]

    def tearDown(self):
        for k, v in self._saved_keys.items():
            os.environ[k] = v

    def test_040_brain_can_be_passed_to_anything(self):
        """O brain é um objecto que pode ser passado a outros componentes."""
        from goodware.llm.brain import GoodwareBrain
        b = GoodwareBrain(adapter=None)
        self.assertIsNotNone(b)

    def test_041_brain_list_methods(self):
        from goodware.llm.brain import GoodwareBrain
        methods = [m for m in dir(GoodwareBrain) if not m.startswith("_")]
        for m in ("explain_event", "triage", "decide", "summarise_incidents", "generate_yara_rule", "close"):
            self.assertIn(m, methods)

    def test_042_brain_with_available_adapter(self):
        """Se passarmos um adapter marked-available, brain.available=True."""
        from goodware.llm.brain import GoodwareBrain
        from goodware.llm.harness_adapter import HarnessAdapter

        # adapter mock que diz estar available
        class FakeAdapter:
            config = type("C", (), {"model": "fake", "provider": "fake"})()
            def is_available(self): return True
            def run(self, *a, **kw): raise NotImplementedError
            def run_json(self, *a, **kw): raise NotImplementedError
            def stats(self): return {}
            def close(self): pass

        b = GoodwareBrain(adapter=FakeAdapter())
        self.assertTrue(b.available)


if __name__ == "__main__":
    unittest.main()
