# Compliance Mapping

## GDPR

| Article | Requirement | Goodware Coverage |
|---------|-------------|-------------------|
| Art 5 | Data minimization | Only metadata collected |
| Art 17 | Right to erasure | Configurable retention |
| Art 25 | Privacy by design | DPIA documentation |
| Art 32 | Security of processing | PQC + MFA + audit |

## NIS2 Directive

| Requirement | Coverage |
|-------------|----------|
| Risk management | ✓ RiskAssessor |
| Incident handling | ✓ Event bus + effector |
| Business continuity | ✓ Snapshot + rollback |
| Supply chain security | ✓ SBOM + signing |
| Encryption | ✓ PQC + classical |

## ISO 27001

| Control | Goodware Module |
|---------|-----------------|
| A.5.10 Information classification | Data tagging |
| A.8.16 Monitoring activities | Sensors (7) |
| A.8.20 Networks security | Network sensor + firewall |
| A.8.21 Security of network services | mTLS |
| A.8.24 Use of cryptography | liboqs PQC |
| A.8.28 Secure coding | SBOM + signed artifacts |

## SOC 2

| Trust Service Criteria | Coverage |
|------------------------|----------|
| CC6.1 Logical access | RBAC + Quorum |
| CC6.6 External boundaries | Firewall |
| CC6.7 Data transmission | PQC |
| CC7.2 Monitoring | Sensors + audit log |
| CC7.3 Anomaly detection | ML predictor |

## HIPAA

| Requirement | Coverage |
|-------------|----------|
| 164.308(a)(1) Security management | Risk assessment |
| 164.308(a)(5) Security awareness | Behavioural biometrics |
| 164.312(a)(1) Access control | Quorum + RBAC |
| 164.312(b) Audit controls | PQC-signed audit log |
| 164.312(e)(1) Transmission security | PQC encryption |

