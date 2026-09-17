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
# Aufruf auf dem Host, auf dem der Stack läuft (Verzeichnis egal):
#     ./scripts/standort-diagnose.sh
#
# Zugang: Default admin + ADMIN_PASSWORD aus .env. Sonst überschreiben:
#     API=https://a38.example:8443 A38_USER=jan A38_PASS=… ./scripts/standort-diagnose.sh
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

API=${API:-http://localhost:8766}
A38_USER=${A38_USER:-admin}

# .env im aktuellen Verzeichnis ODER neben dem Skript — damit es auch aus
# scripts/ heraus läuft und nicht nur aus dem Repo-Wurzelverzeichnis.
if [ -z "${A38_PASS:-}" ]; then
  HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  for CAND in ./.env "$HERE/../.env" "$HERE/.env"; do
    [ -f "$CAND" ] && { ENVFILE=$CAND; break; }
  done
  [ -n "${ENVFILE:-}" ] || {
    echo "Keine .env gefunden — A38_PASS=… setzen oder im Repo-Verzeichnis starten." >&2
    exit 1; }
  A38_PASS=$(grep -E '^ADMIN_PASSWORD=' "$ENVFILE" | head -1 | cut -d= -f2-)
  [ -n "$A38_PASS" ] || { echo "ADMIN_PASSWORD steht nicht in $ENVFILE." >&2; exit 1; }
fi

CURL=(curl -sS --max-time 20)
case "$API" in https://*) CURL+=(-k) ;; esac   # Self-signed im OT ist der Normalfall

# Zugangsdaten über die Umgebung an Python geben, nicht über die Kommandozeile:
# ein Passwort mit Anführungszeichen oder $ zerlegt sonst das JSON — und in der
# Prozessliste hat es ohnehin nichts zu suchen.
BODY=$(U="$A38_USER" P="$A38_PASS" python3 -c \
  'import json, os; print(json.dumps({"username": os.environ["U"], "password": os.environ["P"]}))')
LOGIN=$("${CURL[@]}" -X POST "$API/api/auth/login" -H 'Content-Type: application/json' -d "$BODY" || true)
TOKEN=$(printf '%s' "$LOGIN" |
  python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")')
[ -n "$TOKEN" ] || {
  echo "Login an $API als '$A38_USER' fehlgeschlagen." >&2
  echo "Antwort: ${LOGIN:-（leer — läuft die API dort?）}" >&2
  exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")

echo "=== Standort-Supernetze"
"${CURL[@]}" "${AUTH[@]}" "$API/api/itop/site-supernets" | python3 -c '
import sys, json
for s in json.load(sys.stdin)["sites"]:
    print("  %-20s %s" % (s["cidr"], s["name"]))
'

echo
echo "=== Site-Overrides (schlagen jede Berechnung)"
"${CURL[@]}" "${AUTH[@]}" "$API/api/config/sites" | python3 -c '
import sys, json
rows = (json.load(sys.stdin).get("value") or {}).get("overrides") or []
if not rows:
    print("  (keine)")
for o in rows:
    print("  %-20s %s/%s  ->  %s" % (o.get("cidr", ""), o.get("device", ""),
                                     o.get("vdom") or "root",
                                     o.get("name") or "(ohne Namen)"))
'

echo
echo "=== Zuordnung je Gerät"
"${CURL[@]}" "${AUTH[@]}" "$API/api/diagram/scopes" | python3 -c '
import sys, json
devs = json.load(sys.stdin).get("devices") or []
if devs and "site_detail" not in devs[0]:
    print("  !! Alte API-Version — Container neu bauen:")
    print("     docker compose build api && docker compose up -d api")
    print()
for x in devs:
    print("  %-30s %-14s %s" % (x["device"], x["site"], x.get("site_detail") or ""))
'
