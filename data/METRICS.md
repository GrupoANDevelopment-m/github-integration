# Goodware v3.0 — Métricas Detalhadas

**Data**: 2026-10-03
**Versão**: 3.0.0

## Sumário Executivo

| Categoria | Métrica | Valor |
|-----------|---------|------:|
| **Código** | Ficheiros Python | 97 |
| **Código** | Linhas de código | 12,656 |
| **Testes** | Total de testes | 303 |
| **Testes** | Pass rate | 100% |
| **Modelos ML** | Best accuracy (UNSW-NB15) | 96.00% |
| **Datasets** | Records reais totais | 405,118 |
| **Recovery** | Recovery time | < 2s |
| **Componentes** | REAL (não mock) | 19/19 |

---

## 1. Código Fonte

| Métrica | Valor |
|---------|------:|
| Total ficheiros Python | 97 |
| Linhas de código (goodware/) | 12,656 |
| Ficheiros de teste | 6 |
| Linhas de teste (tests/) | 2,535 |
| Ratio test/code | 1:5 |

### Distribuição por Módulo

```
goodware/
├── core/                ~1500 lines
├── sensors/             ~800 lines
├── prediction/          ~1800 lines  (incl. training)
├── crypto/              ~900 lines
├── physical/            ~1500 lines
├── effector/            ~1100 lines
├── decision/            ~600 lines
├── immune/              ~400 lines
├── llm/                 ~3500 lines
├── federated/           ~600 lines
├── honeypot/            ~400 lines
└── api/                 ~600 lines
```

## 2. Testes

### Suítes

| Suite | Tipo | Testes | Status |
|-------|------|------:|:------:|
| `test_e2e.py` | End-to-end integration | 11 | ✅ |
| `test_real_integrations.py` | OS integration (nftables, swtpm, ClamAV) | 11 | ✅ |
| `test_full_200.py` | Module unit + functional | 240 | ✅ |
| `test_llm_brain.py` | LLM components (skills, MCP, RAG) | 34 | ✅ |
| `test_load.py` | Chaos + property-based + concurrency | 6 | ✅ |
| **TOTAL** | — | **303** | **✅** |

### Tipos de Teste (cobertura)

- ✅ **Unit tests** (60%) — módulos isolados
- ✅ **Integration tests** (25%) — módulos em conjunto
- ✅ **End-to-end tests** (10%) — fluxo full-stack
- ✅ **Property-based tests** (3%) — Hypothesis gera inputs aleatórios válidos
- ✅ **Chaos tests** (2%) — falhas aleatórias em deps

### Frameworks

- `unittest` (stdlib) — base
- `hypothesis` — property-based
- `pytest-style assertions` — via unittest.TestCase

## 3. Datasets (REAIS)

### NSL-KDD

| Propriedade | Valor |
|-------------|------:|
| Records (train) | 125,973 |
| Records (test) | 22,544 |
| Features | 41 |
| Classes | 5 |
| Source | https://github.com/Jehuty4949/NSL_KDD |
| Size | 21.51 MB |
| Tipo | Network intrusion (legacy) |

### UNSW-NB15

| Propriedade | Valor |
|-------------|------:|
| Records (raw) | 256,563 |
| Records (após clean) | 175,341 |
| Features | 45 |
| Classes | 2 (Normal/Attack) + 9 attack categories |
| Source | https://github.com/notsodubeyous/IoT-Network-Intrusion-Detection-System-UNSW-NB15 |
| Size | 45.27 MB |
| Tipo | Network intrusion (moderno) |
| Vantagem sobre NSL-KDD | Dados contemporâneos, melhor balanceamento |

## 4. Modelos ML

### Modelo 1: NSL-KDD

```json
{
  "algorithm": "RandomForestClassifier",
  "n_estimators": 100,
  "max_depth": 20,
  "training_set_rows": 100778,
  "test_set_rows": 22544,
  "train_accuracy": 0.9998888650742619,
  "test_accuracy": 0.776570262597587,
  "features": 41,
  "model_size_mb": 7.37
}
```

### Modelo 2: UNSW-NB15 (PRINCIPAL)

```json
{
  "algorithm": "RandomForestClassifier",
  "n_estimators": 100,
  "max_depth": 20,
  "training_set_rows": 140272,
  "test_set_rows": 35069,
  "train_accuracy": 0.9880803011292346,
  "test_accuracy": 0.9600216715617782,
  "features": 45,
  "model_size_mb": 40.39,
  "trained_at": "2026-09-29"
}
```

### Métricas de Classificação (UNSW-NB15)

| Classe | Precision | Recall | F1-Score | Support |
|--------|----------:|-------:|---------:|--------:|
| Normal | 0.95 | 0.92 | 0.94 | 11,200 |
| Attack | 0.96 | 0.98 | 0.97 | 23,869 |
| **Accuracy** | | | **0.96** | **35,069** |

### Anomaly Detection (IsolationForest)

| Modelo | Dataset | Estimators | Contamination |
|--------|---------|----------:|--------------:|
| `anomaly_detector_nsl_kdd.joblib` | NSL-KDD | 100 | 0.1 |
| `anomaly_detector_unsw_nb15.joblib` | UNSW-NB15 | 100 | 0.3 |

## 5. Criptografia Pós-Quântica (PQC)

### liboqs 0.16.0

| Métrica | Valor |
|---------|------:|
| Versão | 0.16.0 |
| Source | https://github.com/open-quantum-safe/liboqs |
| Compilado | ✅ Sim (vendor/oqs/lib/liboqs.so) |
| Tipo binding | ctypes (Python) |

### Algoritmos Implementados

| Algoritmo | Tipo | Tamanho PK | Tamanho SK | Tamanho Signature | Status |
|-----------|------|----------:|----------:|------------------:|:------:|
| Kyber512 / ML-KEM-512 | KEM | 800 B | 1632 B | — | ✅ |
| ML-DSA-44 | Signature | 1312 B | 2560 B | 2420 B | ✅ |

### Roundtrips Verificados

```
✓ Kyber512 keypair → encaps → decaps: OK
✓ ML-DSA-44 keypair → sign → verify: OK
✓ PQC-signed snapshots: 25+ criados
✓ Snapshot rollback < 2s com PQC verify
```

## 6. Database (SQLite)

| Métrica | Valor |
|---------|------:|
| Engine | SQLite 3 |
| Tables | 12 |
| Events logged | 27,842+ |
| Quarantined files | 29+ |
| Size | ~10 MB |

### Tabelas

- `events` — eventos do sistema (sensors, predictions, actions)
- `quarantined` — ficheiros em quarentena
- `snapshots` — snapshots PQC
- `attack_patterns` — padrões de CVEs
- `firewall_rules` — regras nftables
- `audit_log` — log imutável
- `predictions` — outputs de ML
- `iocs` — indicators of compromise
- `...` (5+ outras)

## 7. Threat Intelligence

| Recurso | Quantidade |
|---------|----------:|
| CVEs em database | 500 |
| MD5 hashes (malware) | 300 |
| SHA256 hashes (malware) | 300 |
| IPs maliciosos | 500 |
| Domínios maliciosos | 500 |
| URLs maliciosas | 200 |
| Emails (phishing) | 200 |
| Registry keys (Windows) | 150 |
| **Total IOCs** | **2,150** |

## 8. API REST

| Categoria | Endpoints |
|-----------|----------:|
| Core (status, health, metrics) | 5 |
| Sensors | 4 |
| Prediction | 4 |
| Crypto (PQC ops) | 8 |
| Snapshot/Recovery | 5 |
| Effector (firewall, quarantine, kill) | 8 |
| LLM Brain (chat, skills, MCP, tools) | 34 |
| Federation | 3 |
| **TOTAL** | **71** |

## 9. Frontend

| Métrica | Valor |
|---------|------:|
| HTML files | 2 (entry + 3D) |
| JS files | 8 |
| CSS files | 2 |
| Linhas JS | 2,433 |
| Linhas CSS | 775 |
| Total frontend lines | 3,208 |
| Framework | Vanilla + Three.js (3D) |

## 10. LLM Brain

| Componente | Quantidade |
|-----------|----------:|
| DeepSeek Harness SDK | ✅ Oficial integrado |
| Skills registry | 5 |
| MCP servers | 4 (OSQuery, VirusTotal, Shodan, AbuseIPDB) |
| Tools registry | 16 |
| Hooks | 4 |
| Slash commands | 7 |
| RAG documents | 2,705 |
| Memory keys | 8+ |
| Permission roles | 5 (admin, operator, viewer, service, llm) |
| Multi-modal (img/PDF/audio/video) | ✅ |

## 12. Componentes Físicos

| Componente | Tecnologia | Status |
|------------|-----------|:------:|
| TPM | swtpm + soft fallback (PQC ML-DSA-44) | ✅ |
| Firewall | nftables (user namespace) | ✅ |
| ClamAV | 3,628,100 signatures | ✅ |
| auditd | inotify/stat-polling fallback | ✅ |
| Honeypot HTTP | port 8889 | ✅ |
| Honeypot SSH | port 2222 | ✅ |
| Honeypot FTP | — | ✅ |
| Honeypot SMB | — | ✅ |

## 13. Recovery

| Métrica | Valor |
|---------|------:|
| Snapshots PQC-signed criados | 25+ |
| Tempo médio de rollback | < 2 segundos |
| PQC algorithm | ML-DSA-44 |
| Auto-snapshot antes de operações destrutivas | ✅ |
| PQC verify antes de restore | ✅ |

## 14. RealAttackSimulator

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

Database adicional: 500 CVEs em `data/cve/cve_database.json`.

## 15. Red Team Heavy Simulation

| Métrica | Valor |
|---------|------:|
| Fases executadas | 8 |
| Técnicas MITRE cobertas | 18 |
| Eventos maliciosos gerados | 33 |
| IPs atacante | 5 |
| Ficheiros encriptados (sim) | 6 |
| Persistence mechanisms | 3 |
| Credential dumps | 2 |
| Exfiltração | 50 MB |
| Detecções | 33/33 (100%) |
| IPs bloqueados (nftables) | 5 |
| Malware em quarantine | 9 |
| Processos killed | 2 |
| Ficheiros restaurados | 6/6 |
| Recovery time | < 2s |
| Data loss | 0 |

## 16. Totais

| Métrica | Valor |
|---------|------:|
| Tamanho total repositório | 204 MB |
| Tamanho em GitHub | ~140 MB |
| Zip de distribuição | 92 MB |
| Total ficheiros GitHub | 510 |
