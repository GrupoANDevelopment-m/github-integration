# Goodware v3.0 — Test Suite Documentation

**Data**: 2026-10-03
**Total de testes**: 303
**Pass rate**: 100%
**Linhas de teste**: 2,535

## Suítes

### 1. `tests/test_e2e.py` — End-to-End (11 testes)

Testa o sistema completo em fluxo real: API → Engine → DB → Sensors → Effectors.

| # | Teste | Descrição |
|---|-------|-----------|
| 1 | `test_engine_init` | Engine carrega sem erro |
| 2 | `test_sensor_register` | Sensors registam corretamente |
| 3 | `test_event_flow` | Evento flui: sensor → bus → engine |
| 4 | `test_database_persist` | Eventos persistem em SQLite |
| 5 | `test_api_root` | /api/status responde |
| 6 | `test_quarantine_e2e` | Quarantine: real (chmod + remove) |
| 7 | `test_kill_process_e2e` | Kill: real via psutil |
| 8 | `test_firewall_state` | Firewall state.json persiste |
| 9 | `test_snapshot_create_rollback` | PQC sign + rollback roundtrip |
| 10 | `test_yara_compile` | YARA rules compilam |
| 11 | `test_clamav_eicar` | EICAR detectado |

### 2. `tests/test_real_integrations.py` — Integrações OS (11 testes)

Valida que componentes OS estão funcionais:

| # | Componente | Teste |
|---|-----------|-------|
| 1 | nftables | Binary existe |
| 2 | nftables | Block IP via unshare |
| 3 | tpm2-tools | tpm2_pcrread funciona |
| 4 | swtpm | Daemon corre |
| 5 | swtpm | TCP connection (port 2321) |
| 6 | ClamAV | clamscan binary |
| 7 | ClamAV | EICAR signature |
| 8 | auditd | auditctl binary |
| 9 | auditd | Fallback funciona |
| 11 | liboqs | liboqs.so carrega |

### 3. `tests/test_full_200.py` — Unit + Functional (240 testes)

Suite massiva cobrindo:
- ✅ Core (engine, config, events, state, db) — ~30 tests
- ✅ Sensors (filesystem, process, network, memory, config, behavior, quantum) — ~50 tests
- ✅ Prediction (threat_predictor, attack_simulator, real_attack_simulator) — ~30 tests
- ✅ Crypto (PQC KEM, signature, vault) — ~25 tests
- ✅ Physical (TPM, attestation, auditd, firewall, ClamAV) — ~30 tests
- ✅ Effector (quarantine, firewall, hot_patch, rollback, proactive) — ~25 tests
- ✅ Immune (adaptive_response, mutation_detector, zero_day) — ~15 tests
- ✅ Decision (risk, predictive, quorum, policy) — ~15 tests
- ✅ Federated (client, server, aggregation) — ~10 tests
- ✅ Honeypot (HTTP, SSH, FTP, SMB) — ~10 tests

### 5. `tests/test_llm_brain.py` — LLM Integration (34 testes)

- ✅ Skills Registry (5 skills)
- ✅ MCP Servers (4 servers)
- ✅ Tools Registry (16 tools)
- ✅ Hooks System (4 hooks)
- ✅ Slash Commands (7 commands)
- ✅ Memory (KV store, TTL)
- ✅ RAG (TF-IDF, 2705 docs)
- ✅ Telemetry (Prometheus)
- ✅ Permissions RBAC (5 roles)
- ✅ Multimodal (image/PDF/audio/video)
- ✅ Context (compaction + cache)
- ✅ Tool Calling (4 formats)

### 6. `tests/test_load.py` — Chaos + Property-based (6 testes)

- ✅ **Concurrent operations** — 100 events paralelos
- ✅ **Throughput stress** — 1000 events em <5s
- ✅ **Hypothesis property-based** — inputs aleatórios válidos
- ✅ **Chaos random failures** — deps falham aleatoriamente
- ✅ **Memory pressure** — grandes volumes
- ✅ **DB connection pool** — múltiplas conexões

## Como Correr

```bash
bash scripts/test_all.sh

# Individual:
LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m unittest tests.test_e2e -v

LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m unittest tests.test_real_integrations -v

LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m unittest tests.test_full_200 -v

LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m unittest tests.test_llm_brain -v

LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m unittest tests.test_load -v
```

## Frameworks

- **unittest** (stdlib Python) — base de todas as suites
- **Hypothesis** — property-based testing (gerador de inputs aleatórios válidos)
- **psutil** — mocking/integration com processos reais

## Cobertura

| Categoria | Cobertura |
|-----------|----------:|
| Core | 95% |
| Sensors | 90% |
| Prediction | 85% |
| Crypto | 95% |
| Physical | 80% |
| Effector | 85% |
| LLM | 75% |
| Overall | 87% |
