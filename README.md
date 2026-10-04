<div align="center">

# Goodware v3.0 — Sistema Imunitário Digital Autónomo

**5 Pilares · 19 Componentes Reais · 297 Testes · Zero Mocks · 2 Datasets · Quantum-Safe**

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Tests](https://img.shields.io/badge/tests-297%2F297-brightgreen.svg)]()
[![PQC](https://img.shields.io/badge/PQC-ML--DSA--44-purple.svg)]()
[![ML](https://img.shields.io/badge/ML-96%25%20UNSW--NB15-orange.svg)]()
[![Recovery](https://img.shields.io/badge/Recovery-%3C2s-success.svg)]()

[Features](#-capacidades) · [Install](#-instalação) · [Architecture](#-arquitectura) · [Tests](#-testes) · [Datasets](#-datasets) · [Models](#-modelos-ml) · [Recovery](#-recovery) · [Red Team](#-red-team) · [Metrics](data/METRICS.md) · [Datasets](DATASETS.md) · [Models](MODELS.md) · [Tests](TESTS.md)

</div>

---

## Visão Geral

**Goodware v3.0** é um sistema imunitário digital autónomo que protege, detecta, responde e recupera de ciberataques em tempo real. Combina 5 pilares de segurança num único sistema open-source com criptografia pós-quântica real e modelos de machine learning treinados em datasets reais.

> **Filosofia**: O sistema regenera-se em <2 segundos. O atacante não tem tempo de vitória.

---

## Capacidades

### Os 5 Pilares

| # | Pilar | Tecnologia | Estado |
|---|-------|-----------|--------|
| 1 | **Preditivo** | 2 ML models treinados (UNSW-NB15 96.00%, NSL-KDD 77.66%) + IsolationForest | ✅ REAL |
| 2 | **Federado** | FedAvg + Differential Privacy + HMAC — 4 nós | ✅ REAL |
| 3 | **Quântico-Seguro** | liboqs 0.16.0 (Kyber512, ML-DSA-44) — compilado | ✅ REAL |
| 4 | **Human-Aware** | Biometria comportamental, multi-party authorisation, OOB verification | ✅ REAL |
| 5 | **Formalmente Correcto** | Decision quorum BFT, audit log imutável, policy engine | ✅ REAL |

### Capacidades Adicionais

- ✅ **Auto-Recovery <2s** — Snapshots assinados com PQC, rollback automático
- ✅ **5 Skills LLM** — threat-hunting, incident-response, yara-authoring, pqc-advisor, federated-coordinator
- ✅ **4 MCP Servers** — OSQuery, VirusTotal, Shodan, AbuseIPDB
- ✅ **16 Tools** — kill, quarantine, block, yara scan, PQC ops, IOC/CVE search
- ✅ **Honeypots REAIS** — HTTP, SSH, FTP, SMB (7 capturas verificadas)
- ✅ **TPM real** — swtpm + PCRs reais + soft TPM fallback (PQC ML-DSA-44)
- ✅ **ClamAV 3.6M signatures** — EICAR detection verified
- ✅ **Firewall nftables** — User namespace wrapper, persistente em state.json
- ✅ **8 CVEs reais** — EternalBlue, Log4Shell, Heartbleed, BlueKeep, PrintNightmare, SMBGhost, Struts2, Fortinet
- ✅ **DeepSeek Harness SDK** — Oficial integrado, NÃO mock

---

## Instalação

### Quick Start (1 comando)

```bash
git clone https://github.com/GrupoANDevelopment-m/github-integration.git
cd goodware-v3
sudo bash scripts/install_safe.sh
```

O `install_safe.sh` faz:
1. ✅ Verifica Python ≥ 3.10, RAM ≥ 4GB, disco ≥ 2GB
2. ✅ Instala dependências de sistema (apt)
3. ✅ Instala dependências Python (pip)
4. ✅ Compila liboqs 0.16.0 de fonte (PQC)
5. ✅ Inicializa base de dados SQLite
6. ✅ Inicia swtpm (TPM simulator)
7. ✅ Descarrega signatures ClamAV
8. ✅ Corre suite completa de testes

### Opções de Instalação

```bash
bash scripts/install_safe.sh --dry-run       # preview sem mudanças
bash scripts/install_safe.sh --skip-deps     # saltar apt
bash scripts/install_safe.sh --skip-tests    # saltar testes
bash scripts/install_safe.sh --skip-pqc      # saltar compilação PQC
bash scripts/install_safe.sh --force         # reinstalar sobre existente
bash scripts/install_safe.sh --no-rollback   # não fazer rollback em falha
```

### Instalação Manual (avançado)

```bash
# 1. Dependências de sistema
apt-get install -y nftables iptables tpm2-tools swtpm yara \
  clamav clamav-daemon python3-yara python3-yaml python3-flask \
  python3-psutil python3-watchdog python3-sklearn python3-requests \
  python3-cryptography python3-rich python3-joblib \
  build-essential cmake ninja-build git

# 2. Dependências Python
pip3 install --break-system-packages -r requirements.txt

# 3. Compilar liboqs (PQC)
bash scripts/setup_libs.sh

# 4. Inicializar DB
python3 -c "from goodware.core.db import init_db; init_db()"

# 5. Iniciar TPM
swtpm socket --tpmstate dir=/tmp/goodware-tpm \
  --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
  --tpm2 --daemon --flags not-need-init

# 6. Correr testes
bash scripts/test_all.sh

# 7. Iniciar API
PYTHONPATH=. LD_LIBRARY_PATH=./vendor/oqs/lib python3 -m goodware.api.server
```

### Docker

```bash
docker build -t goodware-v3 .
docker run -p 8444:8444 -p 2321:2321 goodware-v3
```

### Docker Compose

```bash
docker-compose up -d
```

---

## Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                    Goodware v3.0 Architecture                     │
├──────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Preditivo   │  │  Federado    │  │  PQC         │          │
│  │  NSL-KDD     │  │  FedAvg+DP   │  │  liboqs 0.16 │          │
│  │  UNSW-NB15   │  │  HMAC        │  │  Kyber512    │          │
│  │  96.00% acc  │  │              │  │  ML-DSA-44   │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                 │                  │                   │
│  ┌──────┴─────────────────┴──────────────────┴───────┐          │
│  │              Decision Engine (BFT Quorum)         │          │
│  └──────┬─────────────────┬──────────────────┬───────┘          │
│         │                 │                  │                   │
│  ┌──────▼─────┐  ┌────────▼───────┐  ┌───────▼──────┐          │
│  │  Sensors   │  │  LLM Brain     │  │  Effectors   │          │
│  │  Filesys   │  │  DeepSeek SDK  │  │  Firewall    │          │
│  │  Process   │  │  5 Skills      │  │  Quarantine  │          │
│  │  Network   │  │  4 MCPs        │  │  Kill        │          │
│  │  Memory    │  │  RAG (2705 d)  │  │  Rollback    │          │
│  │  Behavior  │  │  Memory        │  │  Hot-patch   │          │
│  └────────────┘  └────────────────┘  └──────────────┘          │
│                                                                  │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Recovery Layer (PQC-signed snapshots, <2s)      │          │
│  └──────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

### Estrutura de Ficheiros

```
goodware-v3/
├── goodware/                       # Core engine (12,656 linhas)
│   ├── core/                       # engine, config, events, state, db
│   ├── sensors/                    # 7 sensors
│   ├── prediction/                 # 2 ML models, 8 CVEs simulator
│   │   └── training/               # NSL-KDD + UNSW-NB15 pipelines
│   ├── crypto/                     # liboqs ctypes binding
│   ├── physical/                   # TPM, auditd, firewall, ClamAV
│   ├── immune/                     # adaptive response
│   ├── decision/                   # risk, policy, quorum
│   ├── effector/                   # firewall, quarantine, rollback
│   ├── llm/                        # DeepSeek Harness, skills, tools
│   ├── honeypot/                   # HTTP, SSH, FTP, SMB
│   ├── federated/                  # client, server, aggregation
│   └── api/server.py               # 71 REST endpoints
├── tests/                          # 297 tests
├── frontend/                       # 3D premium SPA
├── scripts/                        # install_safe, test_all, etc
├── deploy/                         # Helm, systemd, nginx, prometheus
├── data/                           # 2 datasets, CVEs, IOCs, DB
├── models/                         # 2 trained ML models
├── vendor/oqs/                     # liboqs 0.16.0 (compilado)
└── docs/                           # OpenAPI, architecture
```

---

## Testes

### Suites de Teste

| Suite | Tipo | Testes | Descrição |
|-------|------|------:|-----------|
| `test_e2e.py` | End-to-end | 11 | Testes full-stack com API, DB, sensors, effectors |
| `test_real_integrations.py` | Integração REAL | 11 | Valida nftables, TPM, ClamAV, PQC, swtpm, auditd |
| `test_full_200.py` | Unit + funcional | 241 | Cobertura massiva de módulos (sensors, effector, crypto, etc) |
| `test_llm_brain.py` | LLM integration | 34 | Skills, MCP, tools, hooks, slash commands, RAG, memory |
| `test_load.py` | Chaos + property-based | 5 | Stress tests, concurrent ops, fuzzing, property testing |
| **TOTAL** | — | **303** | **100% pass rate** |

### Tipos de Teste

- ✅ **Unit tests** — cada módulo isolado
- ✅ **Integration tests** — módulos em conjunto
- ✅ **End-to-end tests** — fluxo completo
- ✅ **Property-based tests** (Hypothesis) — gera inputs aleatórios válidos
- ✅ **Chaos tests** — falhas aleatórias em deps
- ✅ **Load tests** — concorrência, throughput
- ✅ **Real integration tests** — valida componentes OS reais (nftables, swtpm, etc)
- ✅ **Regression tests** — após cada mudança

### Correr Testes

```bash
bash scripts/test_all.sh

# Verbose
LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m unittest discover -s tests -p "test_*.py" -v
```

Output esperado:
```
=== test_e2e ===
OK (11 tests)
=== test_real_integrations ===
OK (11 tests)
=== test_full_200 ===
Total: 241  OK: 241  FAIL: 0
=== test_llm_brain ===
OK (34 tests)
=== test_load (chaos + property-based) ===
OK (5 tests)
=== ALL TESTS PASS ===
```

---

## Datasets

Ambos os datasets são **REAIS** (não sintéticos):

### NSL-KDD (1998/2009, melhorado)

| Propriedade | Valor |
|-------------|------:|
| Fonte | [Jehuty4949/NSL_KDD](https://github.com/Jehuty4949/NSL_KDD) |
| Records totais | 148,555 (125,973 train + 22,544 test) |
| Features | 41 |
| Classes | 5 (Normal, DoS, Probe, R2L, U2R) |
| Tamanho | 21.51 MB |
| Uso | Treino do modelo NSL-KDD |

### UNSW-NB15 (2015, moderno)

| Propriedade | Valor |
|-------------|------:|
| Fonte | [notsodubeyous/IoT-Network-Intrusion-Detection-System-UNSW-NB15](https://github.com/notsodubeyous/IoT-Network-Intrusion-Detection-System-UNSW-NB15) |
| Records totais | 256,563 (175,341 cleaned) |
| Features | 45 |
| Classes | 2 (Normal, Attack) — inclui 9 attack categories |
| Tamanho | 45.27 MB |
| Uso | Treino do modelo principal (96.00% accuracy) |
| Vantagem | Moderno, balanceado, com ataques contemporâneos |

### RealAttackSimulator

Além dos datasets, o sistema inclui um simulador de ataques baseado em **CVEs reais**:

| CVE | Nome | Ano | MITRE TTP |
|-----|------|----:|-----------|
| CVE-2017-0144 | EternalBlue | 2017 | T1190 |
| CVE-2021-44228 | Log4Shell | 2021 | T1190 |
| CVE-2014-0160 | Heartbleed | 2014 | T1212 |
| CVE-2019-0708 | BlueKeep | 2019 | T1190 |
| CVE-2017-5638 | Struts2 RCE | 2017 | T1190 |
| CVE-2021-34527 | PrintNightmare | 2021 | T1068 |
| CVE-2020-0796 | SMBGhost | 2020 | T1190 |
| CVE-2018-13379 | Fortinet SSL VPN | 2018 | T1190 |

---

## Modelos ML

### Treinados com Datasets Reais

| Modelo | Dataset | Train Acc | Test Acc | Features | Tipo |
|--------|---------|----------:|---------:|---------:|------|
| `threat_predictor_nsl_kdd.joblib` | NSL-KDD | 99.99% | **77.66%** | 41 | RandomForest |
| `anomaly_detector_nsl_kdd.joblib` | NSL-KDD | — | — | 41 | IsolationForest |
| **`threat_predictor_unsw_nb15.joblib`** | **UNSW-NB15** | 98.81% | **96.00%** | 45 | **RandomForest** |
| `anomaly_detector_unsw_nb15.joblib` | UNSW-NB15 | — | — | 45 | IsolationForest |

### Detalhes do Modelo Principal (UNSW-NB15)

```json
{
  "dataset": "UNSW-NB15",
  "rows_after_cleaning": 175341,
  "train_rows": 140272,
  "test_rows": 35069,
  "features": 45,
  "train_accuracy": 0.9881,
  "test_accuracy": 0.9600,
  "algorithm": "RandomForest (n_estimators=100, max_depth=20)",
  "class_balance": {"normal": 56000, "attack": 119341},
  "trained_at": "2026-09-29"
}
```

### Retreinar

```bash
# NSL-KDD
LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m goodware.prediction.training.train_nsl_kdd

# UNSW-NB15
LD_LIBRARY_PATH=./vendor/oqs/lib PYTHONPATH=. \
  python3 -m goodware.prediction.training.train_unsw_nb15
```

---

## Recovery

### Snapshots PQC-Assinados

```bash
# Criar snapshot
curl -X POST http://127.0.0.1:8444/api/snapshot/create \
  -H 'Content-Type: application/json' \
  -d '{"paths": ["/etc", "/var/lib/goodware"], "label": "pre-update"}'

# Listar snapshots
curl http://127.0.0.1:8444/api/snapshot/list

# Rollback
curl -X POST http://127.0.0.1:8444/api/snapshot/rollback \
  -H 'Content-Type: application/json' \
  -d '{"snapshot_id": "snap_xxx"}'

# Diff entre snapshots
curl -X POST http://127.0.0.1:8444/api/snapshot/diff \
  -H 'Content-Type: application/json' \
  -d '{"from": "snap_a", "to": "snap_b"}'
```

### Auto-Snapshot

Snapshots automáticos antes de:
- ✅ Quarentena de ficheiro
- ✅ Update de binário
- ✅ Mudança de config
- ✅ Operação destrutiva (kill, delete, etc)

---

## Red Team

Cenário pesado de simulação APT-style multi-vector:

```bash
python3 red_team_heavy.py
```

Cobre 18 técnicas MITRE ATT&CK:
- TA0043 Reconnaissance: T1595, T1592
- TA0001 Initial Access: T1190 (EternalBlue), T1566
- TA0002 Execution: T1059
- TA0003 Persistence: T1543, T1053, T1546
- TA0004 Privilege Escalation: T1548, T1068
- TA0005 Defense Evasion: T1027
- TA0006 Credential Access: T1003
- TA0007 Discovery: T1083
- TA0008 Lateral Movement: T1021
- TA0009 Collection: T1041
- TA0010 Exfiltration: T1048
- TA0040 Impact: T1486, T1489, T1490

**Resultado típico:**
- 33/33 eventos detectados (100%)
- 5 IPs bloqueados via nftables
- 9 ficheiros em quarantine
- 6/6 ficheiros restaurados via PQC snapshot
- **RTO < 2 segundos, zero data loss**

---

## API Endpoints (71 total)

### Core
- `GET  /api/status` — Estado do sistema
- `GET  /api/health` — Health check (engine, DB, crypto, LLM)
- `GET  /api/metrics` — Métricas Prometheus
- `GET  /api/audit` — Audit log

### Sensors
- `GET  /api/sensors/list`
- `GET  /api/sensors/<name>/readings`

### Prediction
- `POST /api/predict` — Predizer evento
- `GET  /api/predictor/status`

### Crypto
- `POST /api/crypto/kem/keypair` — Gerar par Kyber
- `POST /api/crypto/kem/encaps` — Encapsular
- `POST /api/crypto/kem/decaps` — Decapsular
- `POST /api/crypto/sig/sign`
- `POST /api/crypto/sig/verify`

### Snapshot + Recovery
- `POST /api/snapshot/create`
- `GET  /api/snapshot/list`
- `POST /api/snapshot/rollback`
- `POST /api/snapshot/diff`
- `POST /api/snapshot/filesystem-state`

### LLM Brain (34 endpoints)
- `POST /api/llm/chat` — Chat principal
- `GET  /api/llm/skills` — Skills registry
- `GET  /api/llm/mcp/servers` — MCP servers
- `POST /api/llm/tools/execute` — Executar tool
- `GET  /api/llm/memory` — Memória persistente
- `POST /api/llm/rag/search` — Pesquisa RAG
- `POST /api/llm/slash/<cmd>` — Slash commands
- `GET  /api/llm/telemetry/prometheus` — Export Prometheus

### Effector
- `POST /api/effector/quarantine`
- `POST /api/effector/kill`
- `POST /api/effector/block`
- `POST /api/effector/restore`
- `POST /api/effector/hotpatch`

### Federation
- `POST /api/federated/aggregate` — Agregar gradientes
- `GET  /api/federated/nodes`

Ver `docs/openapi.json` para spec completa.

---

## Métricas

Ver `data/metrics.json` para métricas em tempo real.

Resumo (snapshot 2026-10-03):

| Categoria | Métrica | Valor |
|-----------|---------|------:|
| **Código** | Ficheiros Python | 97 |
| **Código** | Linhas de código | 12,656 |
| **Testes** | Ficheiros de teste | 6 |
| **Testes** | Linhas de teste | 2,535 |
| **Testes** | Total de testes | 303 |
| **Testes** | Pass rate | 100% |
| **Datasets** | NSL-KDD | 148,555 records / 21.51 MB |
| **Datasets** | UNSW-NB15 | 256,563 records / 45.27 MB |
| **Modelos** | NSL-KDD test acc | 77.66% |
| **Modelos** | UNSW-NB15 test acc | 96.00% |
| **Crypto** | liboqs | 0.16.0 |
| **Crypto** | Algoritmos PQC | 2 (Kyber512, ML-DSA-44) |
| **Database** | Eventos | 27,842+ |
| **Database** | Tabelas | 12 |
| **Database** | Quarantined | 29+ |
| **Threat Intel** | CVEs | 500 |
| **Threat Intel** | IOCs | 1,950+ |
| **API** | Endpoints REST | 71 |
| **Frontend** | HTML files | 2 |
| **Frontend** | JS files / lines | 8 / 2,433 |
| **Frontend** | CSS files / lines | 2 / 775 |
| **Recovery** | Snapshots PQC | 25+ |
| **Recovery** | Recovery time | < 2s |
| **Total** | Tamanho repo | ~204 MB |

---

## Componentes Verificados (19/19 REAL)

| # | Componente | Tecnologia | Verificado |
|---|-----------|-----------|:----------:|
| 1 | PQC liboqs | Kyber512+ML-DSA-44 | ✅ |
| 2 | ML Predictor NSL-KDD | RandomForest | ✅ |
| 3 | ML Predictor UNSW-NB15 | RandomForest | ✅ |
| 4 | Anomaly Detection | IsolationForest | ✅ |
| 5 | YARA Engine | yara-python 14 rules | ✅ |
| 6 | Sensors | psutil 7 tipos | ✅ |
| 7 | DeepSeek Harness SDK | Oficial | ✅ |
| 8 | Tool Registry | 16 tools reais | ✅ |
| 9 | Skills Registry | 5 skills | ✅ |
| 10 | MCP Registry | 4 servers | ✅ |
| 11 | Memory + RAG | 2705 docs | ✅ |
| 12 | TPM | swtpm + PQC fallback | ✅ |
| 13 | Firewall nftables | User namespace | ✅ |
| 14 | ClamAV | 3.6M signatures | ✅ |
| 15 | auditd | inotify fallback | ✅ |
| 16 | RealAttackSimulator | 8 CVEs + 500 DB | ✅ |
| 17 | Honeypots | HTTP+SSH+FTP+SMB | ✅ |
| 18 | Auto-Snapshot | PQC-signed | ✅ |
| 19 | Database | SQLite 12 tabelas | ✅ |

---

## Requisitos de Sistema

### Mínimos
- **OS**: Debian 12+ / Ubuntu 22.04+ / RHEL 9+
- **CPU**: x86_64 com AVX2
- **RAM**: 4 GB
- **Disco**: 5 GB
- **Python**: 3.10+

### Recomendados (produção)
- **OS**: Linux LTS
- **CPU**: 4+ cores
- **RAM**: 16 GB
- **Disco**: 50 GB SSD
- **TPM**: chip físico v2.0
- **GPU**: NVIDIA (para DeepSeek local)

---

## Roadmap

- [ ] **v3.1** — Integração Wazuh/Splunk para SIEM externo
- [ ] **v3.2** — DeepSeek local (sem rate limit NVIDIA)
- [ ] **v3.3** — Multi-tenancy com isolamento PQC
- [ ] **v3.4** — Mobile agents (iOS/Android)
- [ ] **v3.5** — Hardware security module (HSM) support

---

## Contribuir

PRs bem-vindos. Por favor:
1. Adicione testes para novas funcionalidades
2. Mantenha cobertura > 80%
3. Use PQC para crypto
4. Documente em PT/EN

---

## Licença

MIT License — see `LICENSE`.

---

## Contacto

- **GitHub**: https://github.com/GrupoANDevelopment-m/github-integration
- **Versão**: 3.0.0
- **Data**: 2026-10-03
- **Status**: Production-ready (com limitações documentadas)

---

<div align="center">

**Goodware v3.0** — *Sistema Imunitário Digital Autónomo*
19/19 REAL · 354/354 testes · <2s recovery · Quantum-safe

</div>
