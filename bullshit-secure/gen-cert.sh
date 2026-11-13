#!/bin/sh
# Creates a self-signed HTTPS certificate for localhost (valid 365 days).
# Needs OpenSSL (Linux/macOS: preinstalled; Windows: use Git Bash or WSL).
set -e
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout certs/key.pem -out certs/cert.pem -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
chmod 600 certs/key.pem
echo "Done: certs/key.pem and certs/cert.pem created. Start the server with: npm start"
echo "Your browser will warn about a self-signed certificate: that is expected for a local certificate."
