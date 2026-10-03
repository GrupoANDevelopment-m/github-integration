# Goodware v3.0 — Production Readiness Checklist

**Data**: 2026-10-03
**Versão**: 3.0.0 (post-audit)

Documento vivo que separa **PRODUÇÃO** (funcionalidade verificada), **EXPERIMENTAL** (implementado mas com limitações conhecidas), e **ROADMAP** (planeado mas não implementado). Correlaciona com a **Definition of Done** do audit técnico (Secção 6).

---

## Estado Atual por Secção

### ✅ Secção 1 — Núcleo sem modo demo

| # | Critério | Status | Evidência |
|---|----------|:------:|-----------|
| 1.1 | Threat Predictor carrega modelos reais por defeito | ✅ PRODUÇÃO | `goodware/prediction/threat_predictor.py` carrega `threat_predictor_unsw_nb15.joblib` (96.00%); sintético só com `GOODWARE_DEV_SYNTHETIC_OK=1` |
| 1.2 | Federated não gera updates sintéticos | ✅ PRODUÇÃO | `goodware/federated/client.py` — `push_update()` é no-op se não há gradientes reais; secret via env |
| 1.3 | Biometria usa captura real | ✅ PRODUÇÃO | `goodware/human_factor/behavioral_biometrics.py` — `start_capture()` usa pynput real-time; manual via `submit_sample()`; legacy `ensure_default_baseline` marcado claramente como legacy |
| 1.4 | Tools do LLM sem stubs | ✅ PRODUÇÃO | `goodware/llm/tools.py` — `rollback_snapshot` (rollback real PQC-verified), `isolate_machine` (iptables/nftables reais) |
| 1.5 | Dashboard mostra estado real | ✅ PRODUÇÃO | `goodware/api/health.py` — `check_all()` retorna 13 checks com `mode` REAL/DEGRADED explícito |

### ✅ Secção 2 — Segurança do defensor

| # | Critério | Status | Evidência |
|---|----------|:------:|-----------|
| 2.1 | Ações destrutivas exigem OOB/multi-party | ✅ PRODUÇÃO | `goodware/security/tool_authorization.py` — `require_oob()` e `require_multiparty()`; wrapper `@guarded_tool()` |
| 2.2 | Proteção de processo, snapshots, modelos e chaves | ✅ PRODUÇÃO | `goodware/security/artifact_protection.py` — `lock_all()`, `verify_integrity()`, `save_manifest()`, `check_against_manifest()` |
| 2.3 | Sandbox para código/skills gerados pelo LLM | ⚠️ EXPERIMENTAL | Estrutura conceptual existe; implementação concreta é roadmap (Fase 2 do cognitive loop) |
| 2.4 | Constitutional Guard com invariantes | ✅ PRODUÇÃO | `goodware/security/constitutional_guard.py` — 10 invariantes (I1-I10) com testes em `tests/test_security.py` (10 testes passam) |
| 2.5 | Secrets e config fora do código | ✅ PRODUÇÃO | `goodware/federated/{client,server}.py` lêem secret de env var `GOODWARE_FEDERATED_SECRET` ou ficheiro; nunca aceitam placeholder |

### ✅ Secção 3 — Decision Engine

| # | Critério | Status | Evidência |
|---|----------|:------:|-----------|
| 3.1 | Risk score com contexto real | ✅ PRODUÇÃO | `goodware/decision/risk_assessment.py` — 7 fatores: severity, event_type, temporal, historical, behavior, network, asset |
| 3.2 | Policies expressivas e testadas | ✅ PRODUÇÃO | `goodware/decision/policy_engine.py` — 12 operadores (eq/ne/gt/gte/lt/lte/in/nin/contains/regex/exists/starts_with/ends_with); testes em `tests/test_security.py` |
| 3.3 | Quorum só com validadores reais | ⚠️ DOCUMENTADO | Single-node = não-BFT (honesto no `status()`); multi-node requer deployment adicional (roadmap) |

### ⚠️ Secção 4 — Testes e evidência

| # | Critério | Status | Evidência |
|---|----------|:------:|-----------|
| 4.1 | Red team independente | ✅ PRODUÇÃO | `red_team_external.py` (atacante externo) + `red_team_orchestrator.py` (correlação TTD) |
| 4.2 | Taxa de falsos positivos medida | ⚠️ EXPERIMENTAL | UNSW-NB15 test acc 96.00% em dataset; FP rate em tráfego real não medido |
| 4.3 | Cenário de snapshot sob ataque | ✅ PRODUÇÃO | Snapshots PQC-signed; rollback em <2s verificado |
| 4.4 | Testes de carga e falha | ✅ PRODUÇÃO | `tests/test_load.py` — 6 testes (chaos, concurrency, throughput, memory pressure) |
| 4.5 | Suite regressão automatizada | ⚠️ EXPERIMENTAL | `scripts/test_all.sh` corre localmente; GitHub Actions configurado mas não testado em CI real |

### ✅ Secção 5 — Operação e deploy

| # | Critério | Status | Evidência |
|---|----------|:------:|-----------|
| 5.1 | Deploy reprodutível | ✅ PRODUÇÃO | `scripts/install_safe.sh` (230 linhas, idempotente, dry-run, skip-tests/error-rollback), Dockerfile, docker-compose |
| 5.2 | Health-checks honestos | ✅ PRODUÇÃO | 13 checks com `mode` REAL/DEGRADED/NONE; `ok` global só True se todos os críticos OK |
| 5.3 | Logging e auditoria | ✅ PRODUÇÃO | SQLite DB com 12 tabelas; cognitive audit journal |
| 5.4 | Rollback de skills/configs | ✅ PRODUÇÃO | `SnapshotManager` + PQC verify |
| 5.5 | Documentação prod vs experimental | ✅ PRODUÇÃO | Este documento |

### ✅ Secção 6 — Comunicação e claims

| # | Critério | Status | Evidência |
|---|----------|:------:|-----------|
| 6.1 | Claims alinhadas com evidência | ✅ PRODUÇÃO | Este documento qualifica cada claim |
| 6.2 | Separação prod/experimental/roadmap | ✅ PRODUÇÃO | Secção abaixo |

---

## 🟢 PRODUÇÃO (verificado, em uso)

- PQC liboqs 0.16.0 (Kyber512 + ML-DSA-44) — roundtrip verificado
- 2 modelos ML treinados em datasets REAIS (UNSW-NB15 96.00%, NSL-KDD 77.66%)
- IsolationForest anomaly detector
- 7 sensors (filesystem, process, network, memory, config, behavior, quantum)
- Firewall nftables via user namespace wrapper
- ClamAV com 3,628,100 signatures
- TPM via swtpm + soft TPM PQC fallback
- auditd com fallback inotify
- DeepSeek Harness SDK (oficial)
- 5 Skills + 4 MCP Servers + 16 Tools
- RAG (2,705 docs) + Memory persistente
- Snapshot PQC-signed + auto-rollback <2s
- RealAttackSimulator (8 CVEs + 500 DB)
- Honeypots HTTP/SSH/FTP/SMB
- Constitutional Guard (10 invariantes)
- OOB + Multi-party authorization
- Risk Assessor multi-factor
- Policy Engine expressivo
- Artifact protection com integridade manifest
- Cognitive Loop Fase 1 (gap detector, lesson extraction, audit journal)
- 330 testes em 6 suites (100% pass rate)

---

## 🟡 EXPERIMENTAL (implementado mas com limitações conhecidas)

- **Fraud rate measurement** — apenas test_acc do dataset; FP em tráfego real não medido
- **Multi-node BFT quorum** — single-node deployment atual; multi-node requer setup adicional
- **Sandbox para skills LLM** — estrutura conceptual; implementação concreta em roadmap
- **Auto-snapshot hooks em TODAS operações destrutivas** — parcialmente implementado (em quarantine e rollback manual)
- **pynput biometria** — só funciona em desktop com display; em headless fica em manual mode
- **GitHub Actions CI** — workflow definido mas não testado em produção real

---

## 🔵 ROADMAP (planeado, NÃO pronto)

- Ollama como cérebro secundário fine-tuned (Phase 4 do cognitive loop)
- Multi-organização federated real (Phase 2)
- Auto-modificação de skills via Constitutional Guard (Phase 3)
- HSM (Hardware Security Module) integration
- Mobile agents (iOS/Android)
- SIEM integration (Wazuh, Splunk)

---

## ⚠️ Claims qualificadas (audit §6.1)

Em vez de "100% deteção", "RTO 2s em APT", "zero data loss":

| Claim original | Qualificação honesta |
|----------------|---------------------|
| "100% deteção" | Em APT-style simulation interna (8 fases, 33 eventos): 33/33 detetados (100%). Em teste independente externo: ver `data/red_team/orchestrator_report.json` para medição real |
| "RTO ~2s" | Rollback PQC-signed: ~2s em teste local. Em produção depende do tamanho dos snapshots e I/O |
| "Zero data loss" | Quando existe snapshot PQC válido criado antes do evento destrutivo. Sem snapshot, não há recovery |
| "Zero FP/FN" | UNSW-NB15 test acc 96.00% (FP+FN=4% em dataset). Em tráfego real não medido |
| "0 falhas em 297 testes" | 330 testes em 6 suites (100% pass) — mas cobertura é só 87% do código |

---

## Métricas Honestas

- **Codebase**: 97 ficheiros Python, 12,656 linhas
- **Tests**: 330 testes (e2e 11, real_integrations 11, full_200 241, security 27, llm_brain 34, load 6)
- **ML accuracy**: UNSW-NB15 96.00% / NSL-KDD 77.66%
- **PQC**: liboqs 0.16.0 com Kyber512 + ML-DSA-44
- **Snapshots**: 25+ criados, recovery <2s com PQC verify
- **Threat intel**: 500 CVEs + 2,150 IOCs
- **Recovery**: Auto-snapshot + PQC rollback
- **Components**: 19/19 REAL (zero mocks em runtime)

---

## Como validar este checklist

```bash
# 1. Correr todos os testes
bash scripts/test_all.sh

# 2. Verificar health
PYTHONPATH=. LD_LIBRARY_PATH=./vendor/oqs/lib \
  python3 -c "from goodware.api.health import check_all; import json; print(json.dumps(check_all(), indent=2))"

# 3. Verificar Constitutional Guard
PYTHONPATH=. python3 -c "
from goodware.security.constitutional_guard import ConstitutionalGuard
g = ConstitutionalGuard(role='admin')
print('Test I1 (snapshot):', g.check('quarantine_file', {'path': 'data/snapshots/x'}))
print('Test safe:', g.check('search_iocs', {'indicator': 'x'}))
"

# 4. Red team independente
python3 red_team_orchestrator.py
```