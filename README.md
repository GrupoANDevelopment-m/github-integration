# Goodware v3.0

> **Defensive framework agentic** — predictive AI, post-quantum crypto, federated learning, and an LLM SOC analyst in a single Python runtime.

Documento Técnico — v3.0 — Setembro 2026
**Classificação:** Confidencial

---

## O que é

Goodware v3.0 é um **framework Python** que combina detecção, decisão e resposta autônomas a incidentes de segurança, com três camadas:

1. **Detecção**: 7 sensores (filesystem, process, network, memory, config, behavior, quantum) + chainsaw scanner (YARA, ClamAV, rootkit, CIS) + honeypots reais (HTTP/SSH/FTP/SMB).
2. **Decisão**: Policy engine declarativo (YAML/JSON) + risk assessor + quorum + LLM Brain (DeepSeek Harness com 20+ tools).
3. **Resposta**: Effector (kill, quarantine, firewall nftables, snapshot, hot-patch, rollback).

Mais **post-quantum crypto** (liboqs via ctypes — NIST FIPS 203/204) e **federated learning** (FedAvg + DP + HMAC) entre nós.

## O que NÃO é

- **Não é um antivírus comercial** — é framework de defesa escrito do zero.
- **Não é "AGI defensivo autônomo"** — decisões críticas passam por aprovação humana (`request_oob_approval`, multi-party).
- **Não substitui EDR** — complementa; camadas reais (nftables, YARA, ClamAV, auditd, TPM2) defendem; ML e LLM dão inteligência sobre essas camadas.

## Status atual

| Componente | Estado |
|---|---|
| 7 sensores | ✅ Funcionais — testados com psutil real |
| Threat predictor (RandomForest + IsolationForest) | ✅ **Treinado com dados reais** de repositórios públicos de ameaças |
| Test suites | ✅ 297/297 testes passando (4 suites) |
| API REST endpoints | 47 endpoints |
| Frontend SPA | 19 páginas com RBAC |
| Chainsaw scanner (YARA/ClamAV/Rootkit/CIS) | ✅ Real — usa binários do sistema |
| PQC (liboqs via ctypes) | ✅ Real — Kyber/ML-KEM, Dilithium/ML-DSA, Falcon, SPHINCS+ |
| Federated learning (FedAvg + DP + HMAC) | ✅ Funcional — single-node hoje; standalone multi-org em roadmap |
| LLM Brain (DeepSeek Harness) | ✅ Funcional — 20+ tools, multi-turn, RAG, memory, multi-modal |
| Honeypots (HTTP/SSH/FTP/SMB) | ✅ Reais — capturam atacantes reais |
| Effector (kill/quarantine/firewall) | ✅ Real — iptables/nftables, SIGKILL, chmod 000 |
| Human Factor (biometrics, OOB, multi-party) | ✅ Lógica completa — baseline sintético por default |
| Supply Chain (SBOM, signing, verifier) | ✅ Funcional |
| Immune (adaptive, mutation, zero-day) | ✅ Lógica — falta validação empírica |

---

## Capacidades (sem fluff)

### 1. Detecção
- **Process anomaly** — base64 em cmdline, pipe-to-shell (`curl|sh`), reverse shells (`/dev/tcp/`, `nc -e`), miner names (xmrig, kdevtmpfsi, mirai, mimikatz), paths suspeitos (`/tmp`, `/dev/shm`).
- **Filesystem watch** — modificações em `/etc`, `/usr/local/bin`, `/usr/bin`, `/tmp`.
- **Network monitor** — listeners suspeitos (4444, 5555, 6666, 9001).
- **Memory scanner** — LD_PRELOAD, anomalies em regiões de memória.
- **Config drift** — mudanças em configs críticas.
- **Behavior** — padrões comportamentais via heurística + LLM.
- **Quantum sensor** — detecta uso de crypto fraca.

### 2. Scanner profundo (chainsaw)
- **YARA** — pattern matching real (se `yara-python` instalado).
- **ClamAV** — antivírus real (se `clamav` instalado).
- **Rootkit detection** — `/proc` + psutil.
- **CIS Benchmark** — 8 checks de hardening.
- **IAT/EAT repair** — análise de PE.

### 3. Decisão
- **Policy engine** — YAML/JSON declarativo. Default: `block-critical`, `alert-high`, `quarantine-suspicious-process`.
- **Risk assessor** — combina sinais.
- **Quorum (BFT)** — múltiplos decisores concordam antes de ação.
- **LLM Brain** — análise semântica + tool calling (ver abaixo).

### 4. Resposta
- **Process kill** (SIGKILL) + tree kill.
- **Quarentena** (move + chmod 000).
- **Firewall** (nftables / iptables).
- **Snapshot** + rollback.
- **Hot-patch** — correção sem reiniciar.

### 5. Post-quantum crypto
Algoritmos suportados (NIST FIPS 203/204):
- **KEMs**: Kyber512/768/1024, ML-KEM-512/768/1024
- **Sigs**: Dilithium 2/3/5, ML-DSA-44/65/87, Falcon-512, SPHINCS+ SHA2-128s, SLH-DSA

Bindings via `ctypes` direto em `liboqs.so`. Fallback demonstration-grade se liboqs não estiver instalado.

### 6. Federated learning
- **Cliente**: coleta updates locais, assina com HMAC, envia.
- **Servidor**: verifica assinatura, agrega com FedAvg + Differential Privacy.
- **Standalone**: rodar como processo separado pra multi-org.

### 7. Human Factor
- **Behavioral biometrics** — baseline sintético por default; aprende com uso.
- **Context risk** — hora, localização, dispositivo.
- **Multi-party authorization** — N de M aprovadores.
- **Out-of-band approval** — canal secundário pra ações críticas.

---

## LLM Brain (subsistema grande, destaque especial)

Quase ninguém fala dessa parte mas é **4.557 linhas de Python** sozinho. Integra **DeepSeek Harness** via JSON-RPC.

### Capacidades do Brain
- **Sessions stateful** (multi-turn: `investigate` / `continue_investigation`)
- **Tool calling** — LLM invoca ferramentas internas
- **Multi-modal** — texto + imagem + PDF (`multimodal_analyse`)
- **RAG** — pergunta sobre knowledge base (`ask_with_rag`)
- **Memory persistente** — `remember`/`recall`/`search_memory`
- **Slash commands** — `/command` style
- **Hooks** — pre/post (auditoria, transformação)
- **MCP servers** — integração com Model Context Protocol
- **RBAC** — permissions por role

### 20+ tools disponíveis para o LLM
```
list_active_threats        get_event_details
kill_process               quarantine_file
block_ip                   run_yara_scan
rollback_snapshot          request_oob_approval
alert_human                isolate_machine
generate_pqc_keypair       sign_pqc
verify_pqc                 search_iocs
lookup_cve                 generate_yara_rule
no_action                  ...
```

### Métodos do Brain
```
explain_event            triage              decide
summarise_incidents      generate_yara_rule  investigate
continue_investigation   multimodal_analyse  ask_with_rag
remember / recall / search_memory
run_custom / execute_slash / list_tools / execute_tool
```

O LLM Brain pode:
- Explicar por que um evento é suspeito.
- Triar alertas automaticamente.
- Decidir ação (com aprovação humana em críticos).
- **Gerar regras YARA** a partir de amostras.
- Investigar incidentes com multi-turn.
- Buscar CVEs/IOCs durante análise.

---

## Arquitetura

```
              ┌─────────────────────────────────────┐
              │       LLM Brain (DeepSeek)          │
              │  tool calling · RAG · memory        │
              └──────────────┬──────────────────────┘
                             │ (decide)
              ┌──────────────▼──────────────────────┐
              │     Decision (policy + risk)       │
              └──────────────┬──────────────────────┘
                             │ (act)
              ┌──────────────▼──────────────────────┐
   sensors ──►│  Event Bus (in-process, persisted)  │──► effector
              └──────────────┬──────────────────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
   ┌───▼───┐             ┌───▼───┐             ┌───▼───┐
   │Prediction│           │Federated│           │Crypto │
   │(ML)     │           │(FedAvg) │           │(PQC)  │
   └─────────┘           └─────────┘           └───────┘
```

Threads isoladas por subsistema. Estado central em SQLite (`data/goodware.db`). Logs em `logs/`.

---

## Quickstart

```bash
# Dependências Python
pip install -r requirements.txt

# Dependências nativas (opcional — tem fallback)
apt install -y iptables nftables auditd yara clamav clamav-daemon
pip install yara-python oqs
sudo ./scripts/install_deps.sh   # compila liboqs 0.16.0 from source

# Iniciar
sudo ./scripts/start.sh

# Status
./scripts/status.sh

# Demo
./scripts/demo.sh

# Dashboard
python3 -m http.server 8080 -d dashboard
# Abrir http://127.0.0.1:8080

# Testes (297 testes, 4 suites)
PYTHONPATH=. python3 -m tests.test_e2e                    # 11 testes
PYTHONPATH=. python3 -m tests.test_real_integrations     # 11 testes
PYTHONPATH=. python3 -m tests.test_full_200               # 241 testes
PYTHONPATH=. python3 -m tests.test_llm_brain              # 34 testes
```

---

## Threat Model (STRIDE básico)

Documento aberto para revisão. Ameaças cobertas e não cobertas:

| Categoria | Ameaça | Coberto? |
|---|---|---|
| **S**poofing | Process masquerading | ✅ Path + name + cmdline scoring |
| **S**poofing | Network identity | ⚠️ Parcial — TLS/HTTPS não incluso |
| **T**ampering | Filesystem modification | ✅ Watch em paths críticos |
| **T**ampering | Process injection | ⚠️ Heurística simples, sem syscalls trace |
| **R**epudiation | Logs | ⚠️ Plaintext — TODO logging criptografado |
| **I**nformation disclosure | Memory scraping | ✅ Memory sensor (básico) |
| **D**oS | Process spawn flood | ⚠️ Limitado — rate limit por implementar |
| **E**oP | Rootkit | ✅ Detection real (/proc + psutil) |
| **E**oP | Container escape | ❌ Fora do escopo |
| Supply chain | Typosquatting em deps | ✅ SBOM + signature verification |
| Supply chain | Runtime tampering | ⚠️ SBOM estático — sem runtime attestation contínua |
| Living-off-the-Land | LOLBins (PowerShell, WMI) | ⚠️ Limitado — foca em cmdline heuristics |
| Living-off-the-Land | Native binaries abusados | ❌ Sem Sysmon/Sigma rules |
| Ransomware | Pre-encryption activity | ⚠️ Preditor treinado, sem validação empírica ainda |
| APT lateral movement | Pass-the-hash, token theft | ❌ Fora do escopo |

**Fora do escopo:** Cloud control plane attacks, network-level DDoS, physical access, social engineering (mitigado parcialmente por Human Factor).

---

## Limitações conhecidas (honesto)

1. **Threat model documentado em nível básico** — precisa de revisão STRIDE completa por terceiro.
2. **APIs entre componentes são internas** — refactor para API pública versionada é TODO.
3. **Logs em plaintext** — adequado pra protótipo; em prod precisa logging criptografado com rotação.
4. **API REST sem TLS** — usar reverse proxy (nginx/envoy/caddy) com TLS na frente.
5. **YARA rules default limitadas** — 4 regras incluídas; substituir por rules específicas da org.
6. **Auditd requer kernel CONFIG_AUDIT** — detecta e cai em fallback se ausente.
7. **TPM virtual em sandbox** — em produção precisa chip TPM físico pra attestation real.
8. **Firewall state não sincroniza com restart** — recria regras no boot (init script).
9. **Single-node federated** — `federated_server/` standalone existe mas ainda não testado em prod multi-org.
10. **No rate limiting** — adicionar nginx/envoy em frente em prod.
11. **Logs do Brain são texto** — human-readable; faltam métricas (latência, tokens, errors).

---

## Roadmap

### Curto prazo
- [ ] Threat model STRIDE completo (revisão externa)
- [ ] TLS no API server (reverse proxy doc)
- [ ] Logging criptografado com rotação
- [ ] SBOM runtime attestation (TPM + signed manifest)
- [ ] Sysmon-equivalente / Sigma rules pra LOLBins

### Médio prazo
- [ ] Standalone federated server em prod multi-org
- [ ] Rate limiting + DoS protection
- [ ] Dashboard real-time com WebSocket
- [ ] Tool calling estendido (LLM → mais tools nativas)
- [ ] Multi-tenancy (uma instalação, várias orgs isoladas)

### Longo prazo
- [ ] Formal verification do core (TLA+ ou statecharts)
- [ ] Reinforcement learning no effector (ação → outcome feedback)
- [ ] Hardware integration (TPM 2.0 físico, secure enclaves)
- [ ] Audit externo + penetration testing

---

## Estrutura

```
goodware/
├── core/             # engine, events, state, config, logger
├── sensors/          # 7 sensores
├── prediction/       # ML (RandomForest + IsolationForest)
├── decision/         # policy, risk, quorum
├── effector/         # kill, quarantine, firewall, snapshot, hot-patch, rollback
├── crypto/           # PQC (ctypes liboqs), lattice, signatures, vault, QKD sim
├── federated/        # client, server, aggregation (FedAvg + DP + HMAC)
├── human_factor/     # biometrics, context, multi-party, OOB
├── physical/         # attestation (TPM), memory, auditd
├── supply_chain/     # SBOM, signing, verifier
├── immune/           # adaptive_response, mutation_detector, zero_day
├── chainsaw/         # YARA, ClamAV, rootkit, CIS, IAT/EAT
├── llm/              # LLM Brain (DeepSeek Harness) — 4557 linhas
│   ├── brain.py
│   ├── harness/      # JSON-RPC client
│   ├── tools.py      # 20+ tools
│   ├── rag.py
│   ├── memory.py
│   ├── multimodal.py
│   ├── mcp.py        # Model Context Protocol
│   ├── skills.py
│   ├── permissions.py
│   ├── hooks.py
│   ├── telemetry.py
│   └── slash_commands.py
├── honeypot.py       # HTTP/SSH/FTP/SMB honeypots
└── api/              # Flask REST (47 endpoints)

federated_server/     # Standalone federated server
dashboard/            # Web UI
scripts/              # start, stop, status, demo, install_deps
examples/             # simulated_attack, api_client
tests/                # 22 testes (11 E2E + 11 Real Integrations)
config/               # goodware.yaml, mcp_servers.json
data/                 # SQLite, training, snapshots, vault
keys/                 # PQC keypairs
models/               # ML models (joblib)
policies/             # YAML/JSON policies
vendor/oqs/           # liboqs compilado localmente
sbom/                 # Software Bill of Materials
signatures/           # Assinaturas de supply chain
attestations/         # TPM attestations
```

**Total**: 11.171 linhas Python, 50.6% docstrings, 14 módulos isolados.

---

## Licença

GNU General Public License v3.0.

---

## Glossário

- **PQC**: Post-Quantum Cryptography
- **KEM**: Key Encapsulation Mechanism
- **NIST FIPS 203/204**: Padrões PQC do NIST (ML-KEM, ML-DSA)
- **FedAvg**: Federated Averaging (algoritmo de McMahan et al.)
- **DP**: Differential Privacy
- **BFT**: Byzantine Fault Tolerance
- **IAT/EAT**: Import/Export Address Table (PE)
- **SBOM**: Software Bill of Materials
- **TPM**: Trusted Platform Module
- **nf_tables/iptables**: Backends de firewall do kernel Linux
- **YARA**: Ferramenta de pattern matching para malware
- **ClamAV**: Antivírus open source
- **auditd**: Daemon de auditoria do Linux (syscall tracing)
- **honeypot**: Sistema falso que atrai atacantes para os detectar
- **MCP**: Model Context Protocol (Anthropic)
- **OOB**: Out-of-Band (canal secundário de aprovação)
- **STRIDE**: Modelo de threat modeling da Microsoft
