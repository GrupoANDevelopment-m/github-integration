# Goodware v3.0 — Datasets Documentation

**Data**: 2026-10-03
**Total de datasets**: 2 (NSL-KDD + UNSW-NB15)
**Records reais**: 405,118

---

## 1. NSL-KDD

### Visão Geral

Versão melhorada do KDD Cup 1999 dataset, removendo redundâncias e bias.

| Propriedade | Valor |
|-------------|------:|
| Nome completo | NSL-KDD |
| Records (KDDTrain+.txt) | 125,973 |
| Records (KDDTest+.txt) | 22,544 |
| **Total** | **148,517** |
| Features | 41 |
| Classes principais | Normal, DoS, Probe, R2L, U2R |
| Source | https://github.com/Jehuty4949/NSL_KDD |
| Tamanho | 21.51 MB |

### Features (41)

#### Basic (10)
- duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot

#### Content (9)
- num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files

#### Time-based traffic (9)
- count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate

#### Host-based traffic (10)
- dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate

#### Dificuldade (1)
- difficulty (Nível de dificuldade do ataque)

### Vantagens

- ✅ Sem duplicações
- ✅ Sem redundâncias
- ✅ Records selecionados proporcionalmente
- ✅ Melhor para avaliação comparativa

### Limitações

- ⚠️ Dados de 1998 (legados)
- ⚠️ Não reflete padrões modernos (botnets, ransomware, etc)

---

## 2. UNSW-NB15

### Visão Geral

Dataset moderno criado pela UNSW Sydney (2015) usando IXIA PerfectStorm tool.

| Propriedade | Valor |
|-------------|------:|
| Nome completo | UNSW-NB15 |
| Records (raw CSV) | 256,563 |
| Records (após clean) | 175,341 |
| Features | 45 |
| Classes | 2 (Normal/Attack) |
| Attack categories | 9 |
| Source | https://github.com/notsodubeyous/IoT-Network-Intrusion-Detection-System-UNSW-NB15 |
| Tamanho | 45.27 MB |

### Features (45)

#### Flow features (5)
- id, dur, proto, service, state

#### Basic packet features (1)
- spkts

#### Content features (2)
- dpkts, sbytes

#### Time features (8)
- dbytes, rate, sttl, dttl, sload, dload, sloss, dloss

#### Packet-based features (10)
- sinpkt, dinpkt, sjit, djit, swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat

#### Connection-based features (13)
- smean, dmean, trans_depth, response_body_len, ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, is_ftp_login, ct_ftp_cmd, ct_flw_http_mthd

#### Additional features (3)
- ct_src_ltm, ct_srv_dst, is_sm_ips_ports

#### Labels (2)
- attack_cat (categorical), label (binary)

### Attack Categories (9)

- **Fuzzers** — tentativas de crash via inputs random
- **Analysis** — port scans, spam
- **Backdoors** — bypass authentication
- **DoS** — denial of service
- **Exploits** — exploits de vulnerabilidades conhecidas
- **Generic** — ataques contra cifras block
- **Reconnaissance** — gathering info
- **Shellcode** — code injection
- **Worms** — self-propagating malware

### Vantagens

- ✅ Dados modernos (2015)
- ✅ 9 categorias de ataques contemporâneos
- ✅ Melhor balanceamento
- ✅ Captura padrões reais
- ✅ Inclui features temporais

### Modelo Treinado

```json
{
  "algorithm": "RandomForest",
  "n_estimators": 100,
  "max_depth": 20,
  "rows_used": 175341,
  "train_test_ratio": "80/20",
  "train_accuracy": 0.9881,
  "test_accuracy": 0.9600,
  "test_set": {
    "normal_samples": 11200,
    "attack_samples": 23869,
    "total": 35069
  }
}
```

---

## Comparação NSL-KDD vs UNSW-NB15

| Critério | NSL-KDD | UNSW-NB15 |
|----------|---------|-----------|
| Ano | 1998 | 2015 |
| Records | 148K | 175K |
| Features | 41 | 45 |
| Classes | 5 | 2 (+ 9 subcategorias) |
| Modernidade | ⚠️ Legado | ✅ Moderno |
| Accuracy (Goodware) | 77.66% | **96.00%** |
| Uso | Valid. histórica | **Produção** |

**Conclusão**: O modelo UNSW-NB15 é o modelo principal do Goodware v3.0 em produção.
