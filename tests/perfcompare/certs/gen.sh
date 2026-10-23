#!/bin/sh
set -eu
OUT=${1:-/root/alos-perf/harness/certs}
STATIC=${2:-/root/alos-perf/harness/static}
mkdir -p "$OUT" "$STATIC"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null
head -c 65536 /dev/urandom > "$STATIC/file-64k.bin"
echo "cert=$OUT/cert.pem key=$OUT/key.pem static=$STATIC/file-64k.bin"
