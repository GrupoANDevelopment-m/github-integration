# Threat Model — Goodware v3.0

## Ameaças Consideradas

### 1. Insider Threat
- **Vector**: Admin autenticado executa acções maliciosas
- **Defesa**: Multi-party approval + behavioural biometrics
- **Detecção**: Risk score elevado + context (hora, localização)

### 2. Supply Chain
- **Vector**: Dependência comprometida (npm, pip, apt)
- **Defesa**: SBOM + PQC-signed artifacts + zero trust verifier
- **Detecção**: Hash mismatch, signature invalid

### 3. Zero-Day
- **Vector**: CVE desconhecido, sem signature
- **Defesa**: Behavioural ML + zero-day predictor
- **Detecção**: Execution pattern anómalo

### 4. Lateral Movement
- **Vector**: Atacante já dentro move-se
- **Defesa**: Network sensor + process sensor + credential guard
- **Detecção**: SMB/RDP anómalo, novos processos filhos

### 5. Ransomware
- **Vector**: Encrypt + demand ransom
- **Defesa**: Immutable snapshots + YARA + early kill
- **Detecção**: Mass file write + extension change + entropy

### 6. Crypto-Quantum Threat
- **Vector**: Adversário com quantum computer
- **Defesa**: PQC (Kyber + ML-DSA)
- **Detecção**: Use de algoritmos clássicos em contexto sensível

### 7. Physical Attack
- **Vector**: Boot evil maid, DMA attack
- **Defesa**: TPM measured boot + memory protection
- **Detecção**: PCR mismatch

## Não Considerado (Out of Scope)

- Side-channel attacks em hardware específico
- Compromisso do hypervisor
- Zero-days no hardware de execução (Intel ME, AMD PSP)

