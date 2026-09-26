# Operations Runbook

## Instalação
```bash
# 1. Install system deps
./scripts/install_deps.sh

# 2. Build liboqs
cd /tmp && git clone https://github.com/open-quantum-safe/liboqs && cd liboqs
mkdir build && cd build
cmake -GNinja -DOQS_BUILD_ONLY_LIB=ON ..
ninja install
ldconfig

# 3. Update ClamAV signatures
freshclam

# 4. Install Python deps
pip install -r requirements.txt

# 5. Configure
cp config/goodware.yaml.example config/goodware.yaml
$EDITOR config/goodware.yaml

# 6. Start
./scripts/start.sh
```

## Monitoring

### Logs
- `/var/log/goodware/engine.log` — main events
- `/var/log/goodware/oob.log` — out-of-band verifications
- `data/goodware.db` — SQLite persistent state

### Health checks
```bash
curl http://localhost:8443/api/healthz
curl http://localhost:8443/api/status
```

### Metrics
```bash
curl http://localhost:8443/api/metrics
```

