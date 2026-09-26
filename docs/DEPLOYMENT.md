# Deployment Guide

## Production Deployment

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores (AVX2) |
| RAM | 8 GB | 16 GB |
| Storage | 50 GB SSD | 200 GB SSD |
| Network | 1 Gbps | 10 Gbps |

### Software Requirements

- Linux kernel 6.0+ (with CONFIG_AUDIT=y)
- Python 3.11+
- TPM 2.0 chip (recommended, not required)
- liboqs 0.16.0

## Single-Node Setup

```bash
# Ubuntu 22.04
sudo apt update
sudo apt install -y python3-pip python3-venv git

# Clone repo
git clone https://github.com/GrupoANDevelopment-m/github-integration.git
cd github-integration

# Setup
./scripts/install_deps.sh
pip install -r requirements.txt

# Run
./scripts/start.sh
```

## Distributed Setup

```bash
# On each node
./scripts/install_node.sh --node-id=node-1 --server=https://coordinator:8443

# On coordinator
./scripts/install_node.sh --node-id=coordinator
```

## Docker

```bash
docker build -t goodware-v3 .
docker run -d --name goodware \
    -p 8443:8443 \
    -v /var/lib/goodware:/var/lib/goodware \
    -v /sys/fs/tee:/sys/fs/tee:ro \
    --privileged \
    goodware-v3
```

## Kubernetes

```bash
kubectl apply -f deploy/k8s/
```

## High Availability

- 3-node minimum for HA
- Use Redis or PostgreSQL for shared state
- Load balancer on front
- Each node runs independent sensors

