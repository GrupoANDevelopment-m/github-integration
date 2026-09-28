#!/bin/bash
# Generate self-signed TLS certificates for Goodware
# Use Let's Encrypt in production

set -e
DOMAIN="${1:-goodware.local}"
DAYS=365

mkdir -p deploy/tls/certs deploy/tls/private

# Generate CA
openssl genrsa -out deploy/tls/ca.key 4096
openssl req -new -x509 -days $DAYS -key deploy/tls/ca.key \
    -out deploy/tls/certs/ca.crt \
    -subj "/C=PT/ST=Lisboa/L=Lisboa/O=Goodware/CN=Goodware-CA"

# Generate server cert
openssl genrsa -out deploy/tls/private/server.key 2048
openssl req -new -key deploy/tls/private/server.key \
    -out deploy/tls/server.csr \
    -subj "/C=PT/ST=Lisboa/L=Lisboa/O=Goodware/CN=$DOMAIN"

# Config for SAN
cat > /tmp/san.cnf << CONF
[req]
distinguished_name = req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
DNS.3 = *.goodware.local
IP.1 = 127.0.0.1
IP.2 = ::1
CONF

openssl x509 -req -days $DAYS \
    -in deploy/tls/server.csr \
    -CA deploy/tls/certs/ca.crt \
    -CAkey deploy/tls/ca.key \
    -CAcreateserial \
    -out deploy/tls/certs/server.crt \
    -extfile /tmp/san.cnf \
    -extensions v3_req

# Generate client certs for mTLS (optional)
openssl genrsa -out deploy/tls/private/client.key 2048
openssl req -new -key deploy/tls/private/client.key \
    -out deploy/tls/client.csr \
    -subj "/C=PT/ST=Lisboa/L=Lisboa/O=Goodware/CN=goodware-client"
openssl x509 -req -days $DAYS \
    -in deploy/tls/client.csr \
    -CA deploy/tls/certs/ca.crt \
    -CAkey deploy/tls/ca.key \
    -CAcreateserial \
    -out deploy/tls/certs/client.crt

# Permissions
chmod 600 deploy/tls/private/*
chmod 644 deploy/tls/certs/*
chmod 644 deploy/tls/ca.key

echo "Certificates generated in deploy/tls/"
echo "  Server cert: deploy/tls/certs/server.crt"
echo "  Server key:  deploy/tls/private/server.key"
echo "  CA cert:     deploy/tls/certs/ca.crt"
echo "  Client cert: deploy/tls/certs/client.crt"
echo "  Client key:  deploy/tls/private/client.key"
