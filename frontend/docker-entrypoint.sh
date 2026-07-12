#!/bin/sh
# nginx-Config zur Laufzeit aus /certs generieren:
#  - cert.pem + key.pem vorhanden → HTTP(80)→HTTPS-Redirect + HTTPS(443)
#  - sonst → nur HTTP(80) (Fallback, Erstinstallation)
# server_name kommt aus /certs/.hostname (sonst catch-all "_").
# Ein Watcher lädt nginx neu, sobald sich Cert/Key/Hostname ändern — so greift
# ein im UI erzeugtes/hochgeladenes Zertifikat ohne Container-Neustart (~10 s).
set -e

CERT=/certs/cert.pem
KEY=/certs/key.pem
HOSTNAME_FILE=/certs/.hostname
CONF=/etc/nginx/conf.d/default.conf

gen_conf() {
    SERVER_NAME="_"
    if [ -f "$HOSTNAME_FILE" ]; then
        HN=$(tr -d '[:space:]' < "$HOSTNAME_FILE")
        [ -n "$HN" ] && SERVER_NAME="$HN"
    fi

    if [ -f "$CERT" ] && [ -f "$KEY" ]; then
        cat > "$CONF" <<EOF
server {
    listen 80;
    server_name $SERVER_NAME;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name $SERVER_NAME;

    ssl_certificate     $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    root /usr/share/nginx/html;
    index index.html;
    client_max_body_size 16m;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache";
    }
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    location /api/ {
        proxy_pass http://api:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
EOF
    else
        cat > "$CONF" <<EOF
server {
    listen 80;
    server_name $SERVER_NAME;

    root /usr/share/nginx/html;
    index index.html;
    client_max_body_size 16m;

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache";
    }
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    location /api/ {
        proxy_pass http://api:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 120s;
    }
}
EOF
    fi
}

gen_conf

# Reload-Watcher: pollt mtime von Cert/Key/Hostname und lädt nginx bei Änderung
# neu. Baseline wird VOR der Schleife aus dem Ist-Zustand erfasst, damit auch der
# erste Übergang "kein Cert → Cert" (Self-Signed im UI erzeugt) reloaded wird.
snapshot() { stat -c '%Y' "$CERT" "$KEY" "$HOSTNAME_FILE" 2>/dev/null | tr '\n' ' '; }
(
    LAST=$(snapshot)
    while true; do
        sleep 10
        CUR=$(snapshot)
        if [ "$CUR" != "$LAST" ]; then
            gen_conf
            nginx -t 2>/dev/null && nginx -s reload 2>/dev/null || true
            LAST="$CUR"
        fi
    done
) &

exec nginx -g "daemon off;"
