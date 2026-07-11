#!/bin/sh
# Self-signed Cert erzeugen (der echte FMG hat auch ein self-signed Cert;
# der Tracker verbindet mit ssl_verify=false). Danach HTTPS auf 443 —
# so passt `host: fmg-sim` (ohne Schema/Port) durch den SSRF-Guard und der
# Tracker baht base_url = https://fmg-sim.
set -e
CERT=/tmp/sim.crt
KEY=/tmp/sim.key
if [ ! -f "$CERT" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CERT" -subj "/CN=fmg-sim" >/dev/null 2>&1
fi
exec uvicorn main:app --host 0.0.0.0 --port 443 \
  --ssl-keyfile "$KEY" --ssl-certfile "$CERT"
