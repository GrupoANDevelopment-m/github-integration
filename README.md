# 🛡️ Goodware v3.0 — Sistema Imunitário Digital Autónomo

> **Inteligência Artificial Preditiva + Resistência Quântica + Federated Learning + Human Factor Security + Formal Verification**

Documento Técnico — Versão 3.0 — Maio 2026
**Classificação:** Confidencial

---

## ⚠️ O que é REAL e o que é DEMO — honestidade

Esta implementação contém **três camadas de maturidade**, claramente separadas:

| Camada | Tipo | Estado |
|---|---|---|
| **Firewall** (iptables/nftables) | **REAL** | Aplica regras reais no kernel — bloqueia tráfego de verdade |
| **Honeypot** (HTTP/SSH/FTP/SMB) | **REAL** | Captura atacantes reais que fazem scanning |
| **Process kill** (SIGKILL) | **REAL** | Mata processos reais |
| **Quarentena** (move + chmod 000) | **REAL** | Isola ficheiros reais |
| **Rootkit detection** (psutil + /proc) | **REAL** | Detecta binários em /tmp, ld.so.preload, UID 0 |
| **CIS Benchmark** | **REAL** | Verifica hardening real (8 checks) |
| **YARA** (se instalado) | **REAL** | Usa libyara real para match de regras |
| **ClamAV** (se instalado) | **REAL** | Usa clamscan/clamdscan real |
| **TPM** (se tpm2-tools) | **REAL** | `tpm2_pcrread` lê PCRs reais; mock se indisponível |
| **auditd** (se instalado) | **REAL** | `auditctl -w` adiciona watches reais |
| **PQC** (Kyber/Dilithium/ML-KEM/ML-DSA) | **REAL** | liboqs 0.16.0 compilada from source (NIST FIPS 203/204) |
| **ML Predictor** (RandomForest) | **REAL** | sklearn treinado em dados sintéticos — aprende de eventos reais |
| **Federated** | **REAL** | HTTP+HMAC+FedAvg real (servidor in-process) |
| **Human Factor** (biometrics, multi-party) | **REAL** | Lógica real; baseline sintético por default |
| **Attack Simulator** | **DEMO** | Injeta eventos sintéticos no bus — **NÃO é ataque real** |
| **Sistema de Predição AI Treinada** | **LIMITADO** | Modelo treinado em dados sintéticos (250 amostras). Em produção: treinar com dados reais do org. |

**Conclusão honesta:** o que está aqui **defende-te de atacantes reais** (firewall, kill, honeypot, rootkit, CIS, YARA, ClamAV). O que **NÃO** substitui um EDR comercial é o ML treinado em dados sintéticos — precisa de dados reais do teu ambiente.

---

## 1. O que é o Goodware v3.0

Goodware v3.0 é um **sistema imunitário digital autónomo** que combina 5 pilares fundamentais para defesa cibernética proativa:

1. **🧠 Preditivo** — Antecipa ataques antes que ocorram via ML (RandomForest + IsolationForest + time-series forecasting).
2. **🌐 Federado** — Aprende globalmente com múltiplas organizações sem expor dados (Differential Privacy + HMAC + FedAvg).
3. **🔐 Quântico-Seguro** — Criptografia resistente a computadores quânticos (Kyber-like KEM + Dilithium-like signatures + AES-256-GCM + QKD sim).
4. **👤 Human-Aware** — Combater engenharia social com behavioral biometrics, context-aware risk scoring, multi-party authorization e out-of-band verification.
5. **✓ Formalmente Correcto** — Verificações, asserts, invariantes em todo o código crítico.

---

## 2. Instalação Rápida

```bash
# 1. Dependências Python
pip install -r requirements.txt

# 2. (Opcional) Integrações reais — instalar conforme disponível
apt install -y iptables nftables auditd                # kernel hooks reais
apt install -y yara clamav clamav-daemon               # AV real
pip install yara-python                                # Python bindings
pip install oqs                                        # PQC real (liboqs)

# 3. Iniciar
./scripts/start.sh
```

**Para usar as integrações reais (firewall/auditd/honeypot):**
```bash
# arrancar como root
sudo ./scripts/start.sh
# ou explicitamente com honeypot
sudo PYTHONPATH=. python3 -m goodware --with-honeypot
```

---

## 3. Quick Start

```bash
# teste tudo
PYTHONPATH=. python3 -m tests.test_e2e

# exemplo completo
PYTHONPATH=. python3 examples/simulated_attack.py

# demo
./scripts/demo.sh

# arrancar API + dashboard
./scripts/start.sh
python3 -m http.server 8080 -d dashboard   # noutro terminal
```

Abrir `http://127.0.0.1:8080/` no browser para o dashboard.

---

## 4. Estrutura

```
goodware-v3/
├── goodware/
│   ├── core/             # engine, events, state, config, logger
│   ├── sensors/          # 7 sensores (filesystem, process, network, memory, config, behavior, quantum)
│   ├── prediction/       # ThreatPredictor (RandomForest), AnomalyForecast, AttackSimulator
│   ├── decision/         # RiskAssessor, PredictiveEngine, Quorum (BFT), PolicyEngine
│   ├── effector/         # Quarantine (real kill), Firewall (real iptables/nft), HotPatch, Rollback
│   ├── crypto/           # lattice (Kyber-like), signatures (Dilithium-like), vault, agility, qkd_sim
│   │                     # + real_pqc.py — bindings oqs-python (liboqs) se disponível
│   ├── federated/        # client, server, aggregation (FedAvg+DP+HMAC)
│   ├── human_factor/     # biometrics, context_risk, multi_party, out_of_band
│   ├── physical/         # attestation (real tpm2-tools), memory_protection, auditd
│   ├── supply_chain/     # sbom, signing, verifier
│   ├── immune/           # adaptive_response, mutation_detector, zero_day
│   ├── chainsaw/         # analyzer, sandbox, remover, iat_repair
│   │                     # + real_scanner.py — YARA, ClamAV, RootkitDetector, CISBenchmark (REAIS)
│   ├── honeypot.py       # 4 honeypots reais: HTTP/SSH/FTP/SMB
│   └── api/              # Flask REST API (35+ endpoints)
├── federated_server/     # Standalone federated server
├── dashboard/            # Web UI
├── scripts/              # start, stop, status, demo
├── examples/             # simulated_attack, api_client
├── tests/                # 11 testes E2E
└── config/goodware.yaml  # Configuração
```

---

## 5. Como Usar

### CLI Principal
```bash
./scripts/start.sh
./scripts/status.sh
./scripts/stop.sh
./scripts/demo.sh
```

### API REST (35+ endpoints)

**Básicos:**
- `GET  /api/healthz` — health check
- `GET  /api/status` — engine + componentes
- `GET  /api/sensors` — 7 sensores
- `GET  /api/events?limit=N` — eventos
- `GET  /api/threats` — ameaças
- `GET  /api/predictions` — predições AI
- `GET  /api/quarantine` — itens isolados
- `GET  /api/crypto` — PQC
- `GET  /api/attestation` — TPM/secure boot
- `GET  /api/supply_chain` — SBOM
- `GET  /api/immune` — regras aprendidas

**Ação:**
- `POST /api/decision/decide` — decide sobre evento
- `POST /api/effector/execute` — executa (quarantine, block_ip, block_port, snapshot, kill)
- `POST /api/chainsaw/scan` — analisa ficheiro (YARA + ClamAV)
- `POST /api/human_factor/evaluate` — avalia risco

**REAIS (integrações):**
- `POST /api/effector/kill` — mata processo real (SIGKILL)
- `POST /api/effector/kill_tree` — mata processo + filhos
- `POST /api/effector/restore` — restaura de quarentena
- `GET  /api/firewall/snapshot` — mostra estado real do firewall
- `POST /api/chainsaw/scan_rootkit` — rootkit scan real
- `GET  /api/chainsaw/cis` — CIS benchmark
- `POST /api/honeypot/start` — arranca honeypots
- `GET  /api/honeypot/captures` — atacantes capturados
- `POST /api/auditd/watch` — adiciona watch no auditd
- `GET  /api/auditd/recent` — eventos recentes do auditd
- `GET  /api/crypto/real_pqc` — status PQC real (liboqs)

**Exemplo: bloquear IP real via nftables:**
```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"type":"block_ip","target":"1.2.3.4","reason":"scan"}' \
  http://127.0.0.1:8444/api/effector/execute
# {"backend":"nftables","ip":"1.2.3.4","nftables":{"applied":true,"ok":true},"ok":true,"real_applied":true}
```

---

## 6. Testes

```bash
# 1. Instalar dependências reais (apt + liboqs)
sudo ./scripts/install_deps.sh

# 2. Correr os 22 testes (11 E2E + 11 Real Integrations)
PYTHONPATH=. LD_LIBRARY_PATH=/usr/local/lib python3 -m tests.test_e2e
PYTHONPATH=. LD_LIBRARY_PATH=/usr/local/lib python3 -m tests.test_real_integrations
```

**11 testes E2E** que validam: core, 7 sensores, crypto PQC, prediction AI, federated, human factor, decision+effector, immune, chainsaw, physical, supply chain.

**11 testes Real Integrations** que validam: PQC liboqs (Kyber+ML-DSA), YARA, ClamAV, nftables, kill process, honeypot, rootkit scan, CIS benchmark, auditd, TPM2.

---

## 7. Em Produção — checklist

Antes de colocar em produção, precisas de:

- [ ] **Treinar ML com dados reais** — o modelo atual é treinado em dados sintéticos
- [ ] **Instalar YARA + ClamAV + liboqs** — `sudo ./scripts/install_deps.sh` instala tudo
- [ ] **Criar SBOM assinado** — das tuas dependências reais
- [ ] **TPM 2.0 físico** — para attestation real (atualmente usa `tpm2-tools`; precisa de chip TPM no hardware)
- [ ] **Audit externo** — do formal verified core
- [ ] **Penetration testing** — red team
- [ ] **Plano de resposta a incidentes** — com humanos no loop
- [ ] **Treino do staff** — sobre social engineering
- [ ] **Backup fora do sistema** — para restore em disaster recovery

---

## 8. Limitações Conhecidas

1. **Modelo ML sintético** — não detecta padrões específicos do teu ambiente
2. **PQC usa liboqs real** — Kyber512, ML-KEM-512, ML-DSA-44 (NIST FIPS 203/204); o backend lattice demonstration-grade fica como fallback
3. **Auditd requer CONFIG_AUDIT no kernel** — alguns sandboxes não têm; o módulo detecta e usa fallback
4. **TPM virtual** — em ambiente sem chip TPM, `tpm2-tools` corre mas PCRs vêm do `/sys`
3. **Firewall state interno não sincroniza com restart** — recria regras no boot (adicionar init script)
4. **YARA rules limitadas** — vem com 4 regras default; precisas de rules da tua org
5. **Sem TLS na API** — em produção, pôr atrás de reverse proxy com TLS
6. **Single-node** — federated server está in-process; usar standalone para multi-org
7. **Logs em plaintext** — adicionar logging criptografado
8. **No rate limiting** — adicionar nginx/envoy em frente

---

## 9. Filosofia (PDF Conclusão)

> "Ficar esparto e preparar as tuas defesas antes que o ladrão pense em roubar" — agora com a capacidade de **prever** quando e como o ladrão vai tentar entrar.

Goodware v3.0 materializa esta filosofia combinando 5 pilares num organismo de segurança autónomo, preditivo, e em evolução contínua.

---

**Glossary**:
- PQC, KEM, DP, BFT, IAT/EAT, SBOM, TPM, IOMMU, DMA, DSS
- **nf_tables / iptables**: backends de firewall do kernel Linux
- **YARA**: ferramenta de pattern matching para malware
- **ClamAV**: antivírus open source
- **auditd**: daemon de auditoria do Linux (syscall tracing)
- **TPM**: Trusted Platform Module
- **honeypot**: sistema falso que atrai atacantes para os detectar
