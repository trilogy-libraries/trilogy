#!/usr/bin/env bash

set -euo pipefail

cd /mysql-certs

# Generate a CA to test with

openssl req -new -newkey rsa:2048 -days 365 -nodes -sha256 -x509 -keyout ca-key.pem -out ca.pem -config <(
cat <<-EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN=MySQL Test CA
O=GitHub

[v3_req]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:TRUE
keyUsage = critical, keyCertSign
EOF
)

# Generate a server certificate

domain=${MYSQL_HOST:-localhost}

openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=$domain" -keyout server-key.pem -out server-csr.pem
openssl x509 -req -sha256 -CA ca.pem -CAkey ca-key.pem -set_serial 1 \
    -extensions a \
    -extfile <(echo "[a]
        basicConstraints = CA:FALSE
        subjectAltName=DNS:$domain,DNS:*.$domain
        extendedKeyUsage=serverAuth
        ") \
    -days 365 \
    -in  server-csr.pem \
    -out server-cert.pem

# Generate a client certificate

openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=MySQL Test Client Certificate" -keyout client-key.pem -out client-csr.pem
openssl x509 -req -sha256 -CA ca.pem -CAkey ca-key.pem -set_serial 2 \
    -extensions a \
    -extfile <(echo "[a]
        basicConstraints = CA:FALSE
        extendedKeyUsage=clientAuth
        ") \
    -days 365 \
    -in  client-csr.pem \
    -out client-cert.pem
