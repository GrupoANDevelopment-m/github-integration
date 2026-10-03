"""
Goodware v3.0 — LLM Provider with Auto-Fallback Chain.

Resolves the rate limit issue with DeepSeek by automatically cascading
through providers in this priority order:

  1. CLOUD API (NVIDIA-hosted DeepSeek via GOODWARE_LLM_API_KEY)
  2. LOCAL GPU (Ollama, vLLM, llama.cpp — if a GPU is detected)
  3. Ask the user to add a new API key (with rate-limit backoff)
  4. Local stub (last resort, returns clear "NO-LLM" message — never lies)

The chain is monitored: when the cloud API rate-limits, we automatically
switch to local GPU. When local GPU is unavailable, we ask the user.
"""
from __future__ import annotations
import logging
import os
import time
import subprocess
import threading
import json
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("goodware.llm.providers.fallback_chain")


class ProviderStatus(Enum):
    HEALTHY = "HEALTHY"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ProviderInfo:
    name: str
    priority: int             # lower = higher priority
    available: bool = False
    status: ProviderStatus = ProviderStatus.UNKNOWN
    last_check_ts: float = 0.0
    error_count: int = 0
    success_count: int = 0
    last_error: str = ""
    cooldown_until: float = 0.0   # if rate-limited, when to retry
    config: Dict[str, Any] = field(default_factory=dict)


class GPUDetector:
    """Detects available local GPU + LLM runtimes."""

    @staticmethod
    def detect_nvidia_gpu() -> Optional[Dict[str, Any]]:
        """Try nvidia-smi. Returns GPU info dict or None."""
        try:
            r = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total,memory.free,utilization.gpu",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                lines = r.stdout.strip().split("\n")
                gpus = []
                for line in lines:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 4:
                        gpus.append({
                            "name": parts[0],
                            "memory_total_mb": int(parts[1]) if parts[1].isdigit() else 0,
                            "memory_free_mb": int(parts[2]) if parts[2].isdigit() else 0,
                            "utilization_pct": int(parts[3]) if parts[3].isdigit() else 0,
                        })
                return {"count": len(gpus), "gpus": gpus}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def detect_ollama() -> Optional[Dict[str, Any]]:
        """Check if Ollama is running and list models."""
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "2",
                 "http://127.0.0.1:11434/api/tags"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                models = [m.get("name") for m in data.get("models", [])]
                return {"running": True, "models": models, "endpoint": "http://127.0.0.1:11434"}
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return None

    @staticmethod
    def detect_vllm() -> Optional[Dict[str, Any]]:
        """Check if vLLM is running."""
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "2",
                 "http://127.0.0.1:8000/v1/models"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                data = json.loads(r.stdout)
                models = [m.get("id") for m in data.get("data", [])]
                return {"running": True, "models": models, "endpoint": "http://127.0.0.1:8000"}
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return None

    @staticmethod
    def detect_llamacpp() -> Optional[Dict[str, Any]]:
        """Check if llama.cpp server is available on standard port."""
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "2",
                 "http://127.0.0.1:8080/health"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                return {"running": True, "endpoint": "http://127.0.0.1:8080"}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @classmethod
    def detect_all(cls) -> Dict[str, Any]:
        """Detect all LLM-capable resources."""
        result = {
            "gpu": cls.detect_nvidia_gpu(),
            "ollama": cls.detect_ollama(),
            "vllm": cls.detect_vllm(),
            "llamacpp": cls.detect_llamacpp(),
        }
        result["any_local_llm"] = bool(
            result["ollama"] or result["vllm"] or result["llamacpp"]
        )
        result["any_gpu"] = bool(result["gpu"])
        return result


class LLMFallbackChain:
    """Provider chain with auto-fallback.

    Usage:
        chain = LLMFallbackChain()
        # detects on init
        result = chain.invoke("Analyse this threat event...")
        if result["provider"] == "ask_user":
            # prompt the user to add a new key
            ...
    """

    # Backoff times (seconds) for rate-limited providers
    BACKOFF_SCHEDULE = [60, 300, 900, 3600]  # 1min, 5min, 15min, 1h

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.providers: List[ProviderInfo] = []
        self.lock = threading.Lock()
        self._discover_providers()

    def _discover_providers(self) -> None:
        """Detect all available providers and prioritize."""
        self.providers = []
        # 1. Cloud API (highest priority if available)
        api_key = os.environ.get("GOODWARE_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
        if api_key:
            base_url = os.environ.get(
                "GOODWARE_LLM_BASE_URL",
                "https://integrate.api.nvidia.com/v1"
            )
            model = os.environ.get("GOODWARE_LLM_MODEL", "deepseek-ai/deepseek-v3.1")
            self.providers.append(ProviderInfo(
                name="cloud_api",
                priority=1,
                available=True,
                status=ProviderStatus.HEALTHY,
                config={
                    "api_key": api_key,
                    "base_url": base_url,
                    "model": model,
                    "type": "openai_compatible",
                },
            ))
        else:
            self.providers.append(ProviderInfo(
                name="cloud_api",
                priority=1,
                available=False,
                status=ProviderStatus.UNAVAILABLE,
                last_error="GOODWARE_LLM_API_KEY not set",
            ))

        # 2. Local GPU detection
        gpu_info = GPUDetector.detect_all()
        # Ollama
        if gpu_info.get("ollama"):
            ollama = gpu_info["ollama"]
            model = os.environ.get("GOODWARE_OLLAMA_MODEL", "deepseek-r1:7b")
            if not model and ollama.get("models"):
                model = ollama["models"][0]
            self.providers.append(ProviderInfo(
                name="ollama",
                priority=2,
                available=True,
                status=ProviderStatus.HEALTHY,
                config={
                    "endpoint": ollama["endpoint"],
                    "model": model,
                    "models_available": ollama["models"],
                    "type": "ollama",
                },
            ))
        elif gpu_info.get("vllm"):
            vllm = gpu_info["vllm"]
            self.providers.append(ProviderInfo(
                name="vllm",
                priority=2,
                available=True,
                status=ProviderStatus.HEALTHY,
                config={
                    "endpoint": vllm["endpoint"],
                    "models_available": vllm["models"],
                    "type": "openai_compatible",
                },
            ))
        elif gpu_info.get("llamacpp"):
            llamacpp = gpu_info["llamacpp"]
            self.providers.append(ProviderInfo(
                name="llamacpp",
                priority=2,
                available=True,
                status=ProviderStatus.HEALTHY,
                config={
                    "endpoint": llamacpp["endpoint"],
                    "type": "openai_compatible",
                },
            ))
        else:
            self.providers.append(ProviderInfo(
                name="local_gpu",
                priority=2,
                available=False,
                status=ProviderStatus.UNAVAILABLE,
                last_error="no Ollama/vLLM/llama.cpp server detected",
                config={"gpu_info": gpu_info},
            ))

        # 3. Ask user (always available as last resort)
        self.providers.append(ProviderInfo(
            name="ask_user",
            priority=99,
            available=True,
            status=ProviderStatus.HEALTHY,
            config={"type": "interactive"},
        ))

        log.info(f"Provider chain initialized: {[p.name for p in self.providers if p.available]}")

    def _is_in_cooldown(self, provider: ProviderInfo) -> bool:
        return provider.cooldown_until > time.time()

    def _mark_rate_limited(self, provider: ProviderInfo) -> None:
        """Mark provider as rate-limited with exponential backoff."""
        provider.status = ProviderStatus.RATE_LIMITED
        provider.error_count += 1
        # Exponential backoff: 1min, 5min, 15min, 1h
        idx = min(provider.error_count - 1, len(self.BACKOFF_SCHEDULE) - 1)
        backoff = self.BACKOFF_SCHEDULE[idx]
        provider.cooldown_until = time.time() + backoff
        log.warning(
            f"Provider '{provider.name}' rate-limited. Cooldown {backoff}s "
            f"(until {time.strftime('%H:%M:%S', time.localtime(provider.cooldown_until))})"
        )

    def _mark_healthy(self, provider: ProviderInfo) -> None:
        provider.status = ProviderStatus.HEALTHY
        provider.success_count += 1
        provider.cooldown_until = 0.0

    def _mark_unavailable(self, provider: ProviderInfo, error: str) -> None:
        provider.status = ProviderStatus.UNAVAILABLE
        provider.error_count += 1
        provider.last_error = error
        log.error(f"Provider '{provider.name}' unavailable: {error}")

    def _call_cloud_api(self, provider: ProviderInfo, prompt: str,
                         system: Optional[str] = None,
                         **kwargs) -> Dict[str, Any]:
        """Call cloud API (OpenAI-compatible)."""
        import requests
        url = f"{provider.config['base_url']}/chat/completions"
        headers = {
            "Authorization": f"Bearer {provider.config['api_key']}",
            "Content-Type": "application/json",
        }
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body = {
            "model": provider.config["model"],
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 2048),
            "temperature": kwargs.get("temperature", 0.3),
        }
        try:
            r = requests.post(url, json=body, headers=headers, timeout=60)
            if r.status_code == 429:
                # Rate limited
                return {"_rate_limited": True, "_retry_after": r.headers.get("Retry-After")}
            if r.status_code == 401 or r.status_code == 403:
                return {"_auth_error": True, "status": r.status_code, "body": r.text[:200]}
            if r.status_code != 200:
                return {"_http_error": True, "status": r.status_code, "body": r.text[:200]}
            data = r.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {"_ok": True, "content": content, "model": data.get("model"),
                    "usage": data.get("usage", {})}
        except requests.exceptions.Timeout:
            return {"_timeout": True}
        except Exception as e:
            return {"_error": str(e)}

    def _call_ollama(self, provider: ProviderInfo, prompt: str,
                      system: Optional[str] = None,
                      **kwargs) -> Dict[str, Any]:
        """Call Ollama local API."""
        import requests
        url = f"{provider.config['endpoint']}/api/chat"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body = {
            "model": provider.config["model"],
            "messages": messages,
            "stream": False,
        }
        try:
            r = requests.post(url, json=body, timeout=120)
            if r.status_code != 200:
                return {"_http_error": True, "status": r.status_code, "body": r.text[:200]}
            data = r.json()
            content = data.get("message", {}).get("content", "")
            return {"_ok": True, "content": content, "model": provider.config["model"]}
        except requests.exceptions.ConnectionError:
            return {"_connection_error": True}
        except Exception as e:
            return {"_error": str(e)}

    def _call_openai_compatible(self, provider: ProviderInfo, prompt: str,
                                 system: Optional[str] = None,
                                 **kwargs) -> Dict[str, Any]:
        """Call OpenAI-compatible local API (vLLM, llama.cpp)."""
        import requests
        url = f"{provider.config['endpoint']}/chat/completions"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body = {
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", 2048),
            "temperature": kwargs.get("temperature", 0.3),
        }
        try:
            r = requests.post(url, json=body, timeout=120)
            if r.status_code != 200:
                return {"_http_error": True, "status": r.status_code, "body": r.text[:200]}
            data = r.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {"_ok": True, "content": content}
        except Exception as e:
            return {"_error": str(e)}

    def _call_provider(self, provider: ProviderInfo, prompt: str,
                       system: Optional[str] = None,
                       **kwargs) -> Dict[str, Any]:
        """Call a specific provider based on its type."""
        ctype = provider.config.get("type", "openai_compatible")
        if ctype == "ollama":
            return self._call_ollama(provider, prompt, system, **kwargs)
        if ctype in ("openai_compatible", "vllm", "llamacpp"):
            return self._call_openai_compatible(provider, prompt, system, **kwargs)
        if ctype == "interactive":
            return {"_interactive": True}
        return {"_unsupported_type": ctype}

    def invoke(self, prompt: str, system: Optional[str] = None,
               max_retries: int = 2, **kwargs) -> Dict[str, Any]:
        """Invoke the chain. Returns the first healthy provider's response.

        Behaviour:
          1. Try providers in priority order, skipping rate-limited ones in cooldown
          2. If provider rate-limits (429), mark cooldown + try next
          3. If provider errors, mark unavailable + try next
          4. If all fail, return 'ask_user' response with clear instructions
        """
        last_error = None
        attempted = []
        with self.lock:
            for attempt in range(max_retries + 1):
                for provider in self.providers:
                    if not provider.available:
                        continue
                    if self._is_in_cooldown(provider):
                        log.debug(f"Skipping {provider.name} (in cooldown)")
                        continue
                    attempted.append(provider.name)
                    log.info(f"Invoking provider: {provider.name} (attempt {attempt + 1})")
                    result = self._call_provider(provider, prompt, system, **kwargs)
                    if result.get("_ok"):
                        self._mark_healthy(provider)
                        return {
                            "ok": True,
                            "provider": provider.name,
                            "content": result["content"],
                            "model": result.get("model"),
                            "attempts": attempted,
                        }
                    if result.get("_rate_limited"):
                        self._mark_rate_limited(provider)
                        last_error = f"{provider.name}: rate-limited"
                        continue
                    if result.get("_auth_error"):
                        self._mark_unavailable(
                            provider,
                            f"auth error {result.get('status')}: invalid API key",
                        )
                        last_error = f"{provider.name}: invalid API key"
                        continue
                    if result.get("_http_error"):
                        self._mark_unavailable(
                            provider,
                            f"HTTP {result.get('status')}: {result.get('body', '')[:100]}",
                        )
                        last_error = f"{provider.name}: HTTP {result.get('status')}"
                        continue
                    if result.get("_timeout"):
                        last_error = f"{provider.name}: timeout"
                        continue
                    if result.get("_connection_error"):
                        self._mark_unavailable(provider, "connection error")
                        last_error = f"{provider.name}: connection error"
                        continue
                    if result.get("_error"):
                        last_error = f"{provider.name}: {result.get('_error')}"
                        continue
                    if result.get("_interactive"):
                        # Ask user provider — generate instructions
                        return self._ask_user_response(prompt, last_error)
                    if result.get("_unsupported_type"):
                        last_error = f"{provider.name}: unsupported type"
                        continue
                # All providers tried in this attempt; if any was rate-limited
                # and now in cooldown, wait briefly and retry
                if any(self._is_in_cooldown(p) for p in self.providers):
                    time.sleep(2)
                    continue
                break

        # All providers failed
        return self._ask_user_response(prompt, last_error or "all providers failed")

    def _ask_user_response(self, prompt: str, error: str) -> Dict[str, Any]:
        """Generate instructions for the user to add a new API key or enable local GPU."""
        # Find shortest cooldown
        next_retry = None
        for p in self.providers:
            if p.cooldown_until > time.time():
                if next_retry is None or p.cooldown_until < next_retry:
                    next_retry = p.cooldown_until
        instructions = [
            "All LLM providers are unavailable. To restore LLM capabilities:",
            "",
            "OPTION 1: Wait for cooldown and retry",
        ]
        if next_retry:
            wait_min = int((next_retry - time.time()) / 60)
            instructions.append(f"  Cloud API cooldown ends in ~{wait_min} minutes")
        instructions.extend([
            "",
            "OPTION 2: Start a local LLM (GPU recommended)",
            "  • Ollama (easiest):  curl -fsSL https://ollama.com/install.sh | sh && ollama serve &",
            "                    ollama pull deepseek-r1:7b",
            "  • vLLM:             pip install vllm && vllm serve deepseek-ai/DeepSeek-V3",
            "  • llama.cpp:        https://github.com/ggerganov/llama.cpp",
            "",
            "OPTION 3: Add a new API key",
            "  export GOODWARE_LLM_API_KEY='your-new-key'",
            "  export GOODWARE_LLM_BASE_URL='https://integrate.api.nvidia.com/v1'",
            "  export GOODWARE_LLM_MODEL='deepseek-ai/deepseek-v3.1'",
            "",
            f"Last error: {error}",
        ])
        return {
            "ok": False,
            "provider": "ask_user",
            "needs_user_action": True,
            "instructions": "\n".join(instructions),
            "error": error,
            "prompt_preview": prompt[:200] + ("..." if len(prompt) > 200 else ""),
            "next_retry_at": next_retry,
        }

    def status(self) -> Dict[str, Any]:
        """Return detailed status of all providers."""
        gpu_info = GPUDetector.detect_all()
        providers_info = []
        for p in self.providers:
            info = {
                "name": p.name,
                "priority": p.priority,
                "available": p.available,
                "status": p.status.value,
                "success_count": p.success_count,
                "error_count": p.error_count,
                "in_cooldown": self._is_in_cooldown(p),
                "last_error": p.last_error,
            }
            if p.cooldown_until > time.time():
                info["cooldown_until"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(p.cooldown_until),
                )
            providers_info.append(info)
        return {
            "providers": providers_info,
            "detected_resources": gpu_info,
        }

    def refresh(self) -> None:
        """Re-detect providers (e.g., after user starts Ollama)."""
        log.info("Refreshing LLM provider chain...")
        self._discover_providers()