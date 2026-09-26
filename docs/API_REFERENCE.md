# API Reference — Goodware v3.0

Base URL: `http://localhost:8443`
Auth: Bearer token in Authorization header

## Authentication

### POST /api/auth/login
```bash
curl -X POST http://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```
Response:
```json
{"token": "eyJ...", "expires_at": "2026-09-27T00:00:00Z", "role": "admin"}
```

## Health

### GET /api/healthz
```bash
curl http://localhost:8443/api/healthz
```
Response:
```json
{"status": "healthy", "uptime_seconds": 12345, "version": "3.0"}
```

## Status

### GET /api/status
```bash
curl http://localhost:8443/api/status
```
Response:
```json
{
  "engine": "running",
  "components": 12,
  "events_processed": 12345,
  "threats_detected": 7,
  "pqc_backend": "liboqs"
}
```

## Events

### GET /api/events
Query parameters:
- `severity`: low | medium | high | critical
- `type`: process | filesystem | network | ...
- `since`: ISO timestamp
- `limit`: int (default 100)

```bash
curl 'http://localhost:8443/api/events?severity=critical&limit=10'
```

### GET /api/events/{id}
Get specific event by ID.

## Threats

### GET /api/threats
List active threats.

### POST /api/threats/{id}/mitigate
Trigger mitigation.

## Crypto

### GET /api/crypto
List crypto operations.

### POST /api/crypto/real_pqc/roundtrip
Test PQC roundtrip.

### POST /api/crypto/seal
Encrypt data with PQC.

### POST /api/crypto/open
Decrypt data with PQC.

## Effector

### POST /api/effector/kill
Kill a process by PID.

### POST /api/effector/kill_tree
Kill process tree by PID.

### POST /api/effector/execute
Execute effector action.

### POST /api/effector/restore
Restore from snapshot.

## Firewall

### GET /api/firewall/snapshot
Get current firewall rules.

## Sensors

### GET /api/sensors
List sensor status.

## Predictions

### GET /api/predictions
List ML predictions.

## Chainsaw

### POST /api/chainsaw/scan
Scan a file with YARA.

### POST /api/chainsaw/scan_rootkit
Rootkit scan.

### GET /api/chainsaw/cis
CIS benchmark results.

## Immune

### GET /api/immune
Immune system status.

### POST /api/immune/evolve
Trigger immune evolution.

## Federated

### GET /api/federated
Federated learning status.

## LLM

### GET /api/llm/status
Check DeepSeek Harness availability.

### POST /api/llm/explain
Get LLM explanation for an event.

### POST /api/llm/triage
LLM-powered triage.

### POST /api/llm/decide
LLM-based decision making.

### POST /api/llm/generate-yara
Generate YARA rule from description.

## Audit

### GET /api/auditd/recent
Recent auditd events.

### POST /api/auditd/watch
Watch specific path.

## WebSocket

### WS /ws/events
Real-time event stream.

```javascript
const ws = new WebSocket('ws://localhost:8443/ws/events');
ws.onmessage = (ev) => {
  const event = JSON.parse(ev.data);
  console.log(event);
};
```

## Error Responses

```json
{"error": "unauthorized", "message": "Invalid token"}
{"error": "not_found", "message": "Resource X not found"}
{"error": "rate_limited", "message": "Too many requests"}
```

