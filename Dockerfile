# Goodware v3.0 — Dockerfile multi-stage
# Stage 1: Build liboqs from source
# Stage 2: Python application

# === Stage 1: liboqs builder ===
FROM debian:bookworm-slim AS oqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git
WORKDIR /build/liboqs
RUN mkdir build && cd build && \
    cmake -GNinja \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_ENABLE_KEM_KYBER=ON \
        -DOQS_ENABLE_KEM_ML_KEM=ON \
        -DOQS_ENABLE_SIG_ML_DSA=ON \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        .. && \
    ninja -j$(nproc) && \
    ninja install && \
    ldconfig

# === Stage 2: Runtime ===
FROM debian:bookworm-slim AS runtime

LABEL maintainer="Goodware Team"
LABEL description="Goodware v3.0 — Sistema Imunitário Digital Autónomo"
LABEL version="3.0"

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara clamav clamav-daemon tpm2-tools nftables iptables \
    python3 python3-pip python3-venv \
    python3-yara python3-yaml python3-flask python3-flask-cors \
    python3-psutil python3-watchdog python3-sklearn python3-joblib \
    python3-requests python3-cryptography python3-rich \
    build-essential ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs from builder
COPY --from=oqs-builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=oqs-builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

# ClamAV signatures
RUN freshclam --quiet || true

# Application
WORKDIR /opt/goodware
COPY . /opt/goodware/

# Python deps
RUN pip3 install --no-cache-dir --break-system-packages \
    openai pydantic httpx pyyaml

# Permissions
RUN mkdir -p /var/log/goodware /var/lib/goodware /var/lib/goodware/snapshots
RUN chmod 755 /opt/goodware/scripts/*.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8443/api/healthz || exit 1

EXPOSE 8443

# Entrypoint
ENTRYPOINT ["/opt/goodware/scripts/docker-entrypoint.sh"]
CMD ["api"]

# Labels
LABEL org.opencontainers.image.source="https://github.com/GrupoANDevelopment-m/github-integration"
LABEL org.opencontainers.image.version="3.0"
LABEL org.opencontainers.image.title="goodware-v3"
