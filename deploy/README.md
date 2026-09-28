# Goodware v3.0 — Deployment

## Docker (recomendado)

```bash
# Build
docker build -t goodware-v3 .

# Run API
docker run -d --name goodware \
    -p 8443:8443 \
    -e NVIDIA_API_KEY=nvapi-xxx \
    -v goodware-data:/var/lib/goodware \
    -v /var/lib/clamav:/var/lib/clamav:ro \
    goodware-v3

# Ou docker-compose (com monitoring)
docker-compose up -d
```

## Systemd (bare-metal)

```bash
sudo cp deploy/systemd/goodware.service /etc/systemd/system/
sudo useradd -r -s /sbin/nologin goodware
sudo cp -r . /opt/goodware
sudo chown -R goodware:goodware /opt/goodware
sudo systemctl daemon-reload
sudo systemctl enable --now goodware
```

## Kubernetes (Helm)

```bash
helm install goodware ./deploy/helm/ \
    --set apiKey=nvapi-xxx \
    --set persistence.size=50Gi
```

## Nginx reverse proxy

```bash
sudo cp deploy/nginx/goodware.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/goodware.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Monitoring

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/goodware)
- Métricas Goodware: http://localhost:8443/api/llm/telemetry/prometheus

## Health checks

- Liveness: `GET /api/healthz` → 200 healthy
- Readiness: `GET /api/status` → engine running
- Metrics: `GET /api/llm/telemetry/prometheus`
