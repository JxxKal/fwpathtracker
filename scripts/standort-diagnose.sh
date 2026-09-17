#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# A38 — Standort-Zuordnung nachvollziehen
#
# Beantwortet die Frage "warum steht diese Firewall im falschen Standort?".
# Gibt die drei Dinge aus, aus denen sich die Zuordnung ergibt:
#   1. die Standort-Supernetze (Einstellungen → Standort-Supernetze)
#   2. die Site-Overrides      (Einstellungen → Standorte) — die schlagen alles
#   3. je Gerät den Standort samt Begründung ("Gas Nord · 7 von 8 Netzen")
#
# Aufruf auf dem Host, auf dem der Stack läuft — Verzeichnis egal:
#     ./scripts/standort-diagnose.sh
#
# Gefragt wird der API-Container direkt (docker exec, localhost:8000). Damit
# sind nginx, TLS, Host-Ports, Corporate-Proxy und das Admin-Passwort aus dem
# Spiel — genau die Dinge, an denen ein Diagnosewerkzeug nicht scheitern soll.
# Das Token baut der Container sich aus seinem eigenen JWT_SECRET.
#
# Anderer Containername:   A38_CONTAINER=meinname ./scripts/standort-diagnose.sh
# Kein Docker zur Hand:    API=https://a38.example.com A38_PASS=… ./scripts/…
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

CONTAINER=${A38_CONTAINER:-fwpt-api}

# ── Bericht: läuft entweder IM Container oder außerhalb gegen $API ──────────
read -r -d '' REPORT <<'PY' || true
import json, os, sys

BASE = os.environ.get("A38_BASE", "http://localhost:8000")
TOKEN = os.environ.get("A38_TOKEN", "")
if not TOKEN:
    sys.path.insert(0, "/app")
    from jwt_utils import create_token          # noqa: E402
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        sys.exit("JWT_SECRET steht dem Container nicht zur Verfügung.")
    TOKEN = create_token(secret, "0", "standort-diagnose", "admin")

# Nur Standardbibliothek: das Skript läuft damit im Container UND auf dem
# Host, ohne dort irgendetwas zu installieren. ProxyHandler({}) schaltet einen
# Corporate-Proxy aus der Umgebung ab — A38 liegt im eigenen Netz.
import ssl, urllib.request                       # noqa: E402

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                      urllib.request.HTTPSHandler(context=_ctx))


def get(path):
    req = urllib.request.Request(BASE + path,
                                 headers={"Authorization": "Bearer " + TOKEN})
    with _opener.open(req, timeout=60) as r:
        return json.loads(r.read().decode())


def main():
    print("=== Standort-Supernetze")
    sup = get("/api/itop/site-supernets")
    if sup.get("source") == "default":
        print("  (!) nie konfiguriert — das sind die Beispielwerte aus dem Code.")
        print("      Einstellungen -> Standort-Supernetze")
    for s in sup["sites"]:
        print("  %-20s %-16s %s" % (s["cidr"], s["name"], s.get("description") or ""))

    print()
    print("=== Site-Overrides (schlagen jede Berechnung)")
    rows = (get("/api/config/sites").get("value") or {}).get("overrides") or []
    if not rows:
        print("  (keine)")
    for o in rows:
        print("  %-20s %s/%s  ->  %s" % (o.get("cidr", ""), o.get("device", ""),
                                         o.get("vdom") or "root",
                                         o.get("name") or "(ohne Namen)"))

    print()
    print("=== Zuordnung je Gerät")
    devs = get("/api/diagram/scopes").get("devices") or []
    if not devs:
        print("  (keine Geräte im Inventar — FMG-Sync zuerst laufen lassen)")
    elif "site_detail" not in devs[0]:
        print("  !! Alte API-Version — Container neu bauen:")
        print("     docker compose build api && docker compose up -d api")
        print()
    for x in devs:
        print("  %-30s %-14s %s" % (x["device"], x["site"], x.get("site_detail") or ""))

    print()
    print("=== Welche Netze die Zuordnung tragen")
    for x in get("/api/diagram/site-evidence")["devices"]:
        print("  %s" % x["device"])
        if x.get("override"):
            print("      Override aus den Einstellungen -> %s" % x["override"])
        for site, nets in sorted(x["networks_by_site"].items()):
            shown = ", ".join(nets[:6]) + (" … (+%d)" % (len(nets) - 6) if len(nets) > 6 else "")
            print("      %-14s %s" % (site or "(kein Standort)", shown))
        if not x["networks_by_site"]:
            print("      (keine connected Netze)")


main()
PY

# ── Weg 1 (Standard): im API-Container ──────────────────────────────────────
if [ -z "${API:-}" ]; then
  command -v docker >/dev/null 2>&1 || {
    echo "Kein docker gefunden — mit API=… und A38_PASS=… von außen aufrufen." >&2; exit 1; }
  docker inspect -f '{{.State.Running}}' "$CONTAINER" >/dev/null 2>&1 || {
    echo "Container '$CONTAINER' läuft nicht. Laufende Container:" >&2
    docker ps --format '  {{.Names}}' >&2
    echo "Anderen Namen mit A38_CONTAINER=… angeben." >&2; exit 1; }
  printf '%s' "$REPORT" | docker exec -i "$CONTAINER" python3 -
  exit $?
fi

# ── Weg 2: von außen gegen die API, mit Anmeldung ───────────────────────────
A38_USER=${A38_USER:-admin}
if [ -z "${A38_PASS:-}" ]; then
  HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  for CAND in ./.env "$HERE/../.env" "$HERE/.env"; do
    [ -f "$CAND" ] && { ENVFILE=$CAND; break; }
  done
  [ -n "${ENVFILE:-}" ] || { echo "A38_PASS=… setzen (keine .env gefunden)." >&2; exit 1; }
  A38_PASS=$(grep -E '^ADMIN_PASSWORD=' "$ENVFILE" | head -1 | cut -d= -f2-)
fi

# --noproxy: A38 liegt im eigenen Netz; ein Corporate-Proxy aus der Umgebung
# beantwortet den Aufruf sonst mit seiner eigenen HTML-Fehlerseite.
CURL=(curl -sS --max-time 30 -k -L --post301 --post302 --noproxy '*')
BODY=$(U="$A38_USER" P="$A38_PASS" python3 -c \
  'import json, os; print(json.dumps({"username": os.environ["U"], "password": os.environ["P"]}))')
LOGIN=$("${CURL[@]}" -X POST "$API/api/auth/login" -H 'Content-Type: application/json' -d "$BODY" || true)
TOKEN=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")')

if [ -z "$TOKEN" ]; then
  echo "Login an $API als '$A38_USER' fehlgeschlagen." >&2
  case "$LOGIN" in
    *"<html"*|*"<HTML"*)
      echo "Die Antwort war HTML, nicht JSON — die URL trifft nicht die API." >&2
      echo "Einfacher ist der Weg über den Container: API weglassen und" >&2
      echo "    ./scripts/standort-diagnose.sh" >&2
      echo "auf dem Docker-Host aufrufen." >&2 ;;
    "") echo "Keine Antwort — falscher Port oder Host?" >&2 ;;
    *)  echo "Antwort: $(printf '%s' "$LOGIN" | head -c 300)" >&2 ;;
  esac
  exit 1
fi

A38_BASE="$API" A38_TOKEN="$TOKEN" python3 -c "$REPORT"
