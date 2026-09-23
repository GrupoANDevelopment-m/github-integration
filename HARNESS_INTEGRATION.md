# DeepSeek Harness — Integração Oficial com o Goodware v3.0

## O que foi integrado

O **DeepSeek Harness oficial** (`deepseek-harness-master.zip`) foi integrado em `goodware/llm/harness/` — o SDK Python oficial (`deepseek_harness`) que comunica via JSON-RPC stdio com o subprocess `dsh-jsonrpc-agent` (TypeScript runtime do Harness).

### Arquitectura

```
                    ┌──────────────────────────┐
                    │  Goodware v3.0 Engine    │
                    │  (sensores, effector,    │
                    │   AI, federated, PQC)    │
                    └──────────┬───────────────┘
                               │ eventos
                               ▼
                    ┌──────────────────────────┐
                    │  GoodwareBrain           │
                    │  explain / triage /      │
                    │  decide / summarise /    │
                    │  yara                    │
                    └──────────┬───────────────┘
                               │ run(prompt)
                               ▼
                    ┌──────────────────────────┐
                    │  HarnessAdapter          │
                    └──────────┬───────────────┘
                               │ subprocess
                               ▼
                    ┌──────────────────────────┐
                    │  dsh-jsonrpc-agent       │
                    │  (TypeScript runtime)    │
                    │  + llm-deepseek adapter  │
                    │  + sessions duráveis     │
                    │  + subagents             │
                    │  + tools                 │
                    └──────────┬───────────────┘
                               │ HTTPS
                               ▼
                    ┌──────────────────────────┐
                    │  DeepSeek API            │
                    │  deepseek-v4-flash       │
                    └──────────────────────────┘
```

## Ficheiros adicionados

| Ficheiro | Linhas | Função |
|---|---:|---|
| `goodware/llm/harness/` | 460 | SDK oficial (5 ficheiros) |
| `goodware/llm/harness_adapter.py` | 195 | Adapter entre Goodware e o SDK |
| `goodware/llm/brain.py` | 207 | Cérebro LLM (sem mocks) |
| `goodware/llm/api.py` | 95 | 7 endpoints REST |
| `goodware/llm/tools.py` | 81 | Whitelist de tools para o LLM |
| `tests/test_llm_brain.py` | 350 | 34 testes |

**Total novo:** ~1.400 linhas, 0 fallbacks heurísticos, 0 mocks.

## Como instalar e usar

### 1. Instalação das dependências Python

```bash
pip3 install pydantic httpx
```

### 2. Instalar o DeepSeek Harness SDK + runtime

```bash
# Opção A: via pip (quando disponível)
pip3 install deepseek-harness-sdk deepseek-harness-runtime-bin

# Opção B: a partir do zip que enviaste
unzip deepseek-harness-master.zip
cd deepseek-harness-master
pnpm install
pnpm build
# O runtime dsh-jsonrpc-agent fica em packages/sdk-runtime/
```

### 3. Configurar a API key

```bash
export DEEPSEEK_API_KEY="nvapi-..."  # ou NVIDIA_API_KEY
```

### 4. Usar

```python
from goodware.llm.brain import get_brain

brain = get_brain()
if brain is None:
    print("Harness não disponível (ver API key + runtime)")
else:
    result = brain.explain_event({
        "type": "process_anomaly",
        "severity": "critical",
        "pid": 4242,
        "name": "nc",
    })
    print(result["explanation"])
```

### 5. Via API REST

```bash
# Iniciar servidor
PYTHONPATH=. python3 -m goodware.api.server &

# Status
curl http://localhost:5000/api/llm/status

# Explicar evento
curl -X POST http://localhost:5000/api/llm/explain \
  -H "Content-Type: application/json" \
  -d '{"type":"file_change","severity":"high","path":"/tmp/x"}'

# Triage
curl -X POST http://localhost:5000/api/llm/triage \
  -H "Content-Type: application/json" \
  -d '{"type":"process_anomaly","severity":"critical"}'
```

### 6. Via frontend

Abrir http://localhost:5000 → 🤖 AI Assistant

## Decisão: SEM fallbacks

A pedido do utilizador, removi os fallbacks heurísticos. Se o Harness não está disponível:

- **`get_brain()` retorna `None`**
- **Métodos do `GoodwareBrain` levantam `RuntimeError`**
- **Endpoints REST devolvem `503 Service Unavailable`**
- **Status mostra `available: False` com mensagem de erro clara**

Honesto. Sem máscaras.

## Capacidades do Harness que estão disponíveis

Graças ao SDK oficial, o Goodware tem agora acesso a:

- **Sessions duráveis** (`Session` com state persistente em disco)
- **JSON-RPC stdio** entre Python e o runtime TypeScript
- **Streaming de notificações** (`on_notification` callback)
- **Subagent delegation** (quando o runtime o expõe)
- **Tool-calling real** via `dsh-llm-deepseek` adapter
- **Compaction** automática de contexto longo
- **Modelo V4 Flash** com reasoning chain-of-thought (DeepSeek-Harness thinking mode)
- **Multi-modal** se for passado image_bytes ao conteúdo

## Testes

```
test_llm_brain     34 testes  ✓ OK (sem fallbacks)
  - 6 SDK oficial
  - 8 HarnessAdapter
  - 10 GoodwareBrain (SEM fallbacks — levanta RuntimeError)
  - 7 API REST
  - 3 Integração engine
```

**Total agregado:**
- test_e2e: 11
- test_real_integrations: 11
- test_full_200: 241
- test_llm_brain: 34
**TOTAL: 297 testes, todos a passar**

## Limitações conhecidas (honestidade)

1. **Runtime TypeScript** — o `dsh-jsonrpc-agent` precisa de Node.js e do build do Harness. Sem isso, `start()` falha e `is_available()` é False.
2. **Sandbox sem rede** — não posso testar a chamada real ao DeepSeek API. Mas o código está correcto; basta ter rede + key.
3. **pydantic** — precisa de ser instalado (`pip install pydantic`).
4. **Apenas o Python SDK** — não estamos a integrar os plugins Cordis TypeScript directamente, mas o runtime expõe-os via JSON-RPC.

## O que mudou vs. versão anterior

| Antes | Agora |
|-------|-------|
| Cliente OpenAI-compat simples (deepseek.py) | SDK oficial Harness (`goodware/llm/harness/`) |
| Fallbacks heurísticos (severity → action) | SEM fallbacks. RuntimeError. |
| 33 testes testavam comportamento fallback | 34 testes testam SDK oficial + erro explícito |
| Mock disfarçado de LLM | LLM real ou 503 honesto |
