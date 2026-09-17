#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# A38 — Standort-Zuordnung nachvollziehen
#
# Beantwortet die Frage "warum steht diese Firewall im falschen Standort?".
# Gibt die drei Dinge aus, aus denen sich die Zuordnung ergibt:
#   1. die Standort-Supernetze (Einstellungen → Standort-Supernetze)
#   2. die Site-Overrides    (Einstellungen → Standorte) — die schlagen alles
#   3. je Gerät den Standort samt Begründung ("Gas Nord · 7 von 8 Netzen")
#
# Aufruf im Repo-Verzeichnis auf dem Host, auf dem der Stack läuft:
#     ./scripts/standort-diagnose.sh
#
# Zugang: Default admin + ADMIN_PASSWORD aus .env. Sonst überschreiben:
#     API=https://a38.example:8443 A38_USER=jan A38_PASS=… ./scripts/standort-diagnose.sh
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

API=${API:-http://localhost:8766}
A38_USER=${A38_USER:-admin}
if [ -z "${A38_PASS:-}" ]; then
  [ -f .env ] || { echo "Keine .env gefunden — A38_PASS setzen oder im Repo-Verzeichnis starten." >&2; exit 1; }
  A38_PASS=$(grep -E '^ADMIN_PASSWORD=' .env | cut -d= -f2-)
fi
CURL=(curl -sS --max-time 20)
case "$API" in https://*) CURL+=(-k) ;; esac   # Self-signed im OT ist der Normalfall

TOKEN=$("${CURL[@]}" -X POST "$API/api/auth/login" -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,os;print(json.dumps({"username":os.environ["U"],"password":os.environ["P"]}))' \
        U="$A38_USER" P="$A38_PASS")" |
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))')
[ -n "$TOKEN" ] || { echo "Login an $API fehlgeschlagen." >&2; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")

echo "=== Standort-Supernetze"
"${CURL[@]}" "${AUTH[@]}" "$API/api/itop/site-supernets" |
  python3 -c '
import sys, json
for s in json.load(sys.stdin)["sites"]:
    print(f"  {s[\"cidr\"]:<20} {s[\"name\"]}")
'

echo
echo "=== Site-Overrides (schlagen jede Berechnung)"
"${CURL[@]}" "${AUTH[@]}" "$API/api/config/sites" |
  python3 -c '
import sys, json
rows = (json.load(sys.stdin).get("value") or {}).get("overrides") or []
if not rows:
    print("  (keine)")
for o in rows:
    print(f"  {o.get(\"cidr\",\"\"):<20} {o.get(\"device\",\"\")}/{o.get(\"vdom\") or \"root\"}"
          f"  -> {o.get(\"name\") or \"(ohne Namen)\"}")
'

echo
echo "=== Zuordnung je Gerät"
"${CURL[@]}" "${AUTH[@]}" "$API/api/diagram/scopes" |
  python3 -c '
import sys, json
d = json.load(sys.stdin)
devs = d.get("devices") or []
if devs and "site_detail" not in devs[0]:
    print("  !! Alte API-Version — Container neu bauen:")
    print("     docker compose build api && docker compose up -d api")
for x in devs:
    print(f"  {x[\"device\"]:<30} {str(x[\"site\"]):<14} {x.get(\"site_detail\") or \"\"}")
'
