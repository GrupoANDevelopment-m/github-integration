# Goodware v3.0 — Architecture Deep-Dive

## Camadas do Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│  ┌──────────────────┐  ┌─────────────────┐  ┌────────────┐  │
│  │  Frontend SPA    │  │  REST API       │  │  WebSocket │  │
│  │  (vanilla JS)    │  │  (Flask)        │  │  (live)    │  │
│  │  19 pages        │  │  47 endpoints   │  │            │  │
│  └──────────────────┘  └─────────────────┘  └────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      BUSINESS LOGIC                          │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │  Decision      │  │  Effectors      │  │  LLM Brain   │  │
│  │  Engine        │  │  (nftables,     │  │  (DeepSeek   │  │
│  │  Risk+Predict  │  │   quarantine,   │  │   Harness)   │  │
│  │  +Policy       │  │   hot_patch)    │  │              │  │
│  └────────────────┘  └─────────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    INTELLIGENCE LAYER                        │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │  Federated     │  │  Adaptive       │  │  Threat      │  │
│  │  Learning      │  │  Immune         │  │  Predictor   │  │
│  │  FedAvg+DP     │  │  System         │  │  ML          │  │
│  └────────────────┘  └─────────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                      SENSORS (7)                             │
│  filesystem | process | network | memory | config |         │
│             behavior | quantum                                │
├─────────────────────────────────────────────────────────────┤
│                   SECURITY PRIMITIVES                        │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │  PQC           │  │  TPM            │  │  YARA +      │  │
│  │  liboqs        │  │  Attestation    │  │  ClamAV      │  │
│  │  Kyber+ML-DSA  │  │  PCR reads      │  │  Signatures  │  │
│  └────────────────┘  └─────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Fluxo de um Evento

```
1. Sensor emite evento (severity, source, payload)
   ↓
2. Event bus distribui aos subscritores
   ↓
3. RiskAssessor calcula score 0-100
   ↓
4. ThreatPredictor (ML) calcula probabilidade de breach
   ↓
5. PolicyEngine avalia IF-THEN rules + RBAC
   ↓
6. SE crítico → QuorumEngine (m-of-n admin)
   ↓
7. Effector executa acção (nftables/kill/quarantine)
   ↓
8. PQC assina audit log (forward-secure)
   ↓
9. LLM brain explica (se Harness disponível)
   ↓
10. Immune system aprende
    ↓
11. Federated: gradient para servidor central
```

