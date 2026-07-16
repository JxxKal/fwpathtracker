# A38 — Firewall Path Tracker

> *„Der Passierschein für jedes Paket."*

Firewall-Pfad-Analyse für verteilte **FortiGate**-Umgebungen (Full-Mesh-SD-WAN,
mehrere VDOMs/Standorte, zentral über einen **FortiManager** verwaltet).

Für einen Flow zeigt das Dashboard den kompletten Pfad über alle beteiligten
Firewalls/VDOMs — mit **Live-Verdict pro Hop**, den greifenden Regeln aus der
gecachten FMG-DB und **Regelvorschlägen bei Deny**. Der Tracker hat **keinen
Schreibzugriff** auf den FortiManager (No-Write-Garantie, s.u.).

---

## Inhalt

- [Features](#features)
- [Architektur](#architektur)
- [Quickstart](#quickstart)
- [Deployment](#deployment)
- [Proxy-Umgebungen](#proxy-umgebungen) ← *wie wir es hinter Corporate-Proxy gelöst haben*
- [Konfiguration](#konfiguration)
- [No-Write-Garantie & FMG-Profil](#no-write-garantie--fmg-profil)
- [FortiManager-Besonderheiten](#fortimanager-besonderheiten)
- [Entwicklung & Tests](#entwicklung--tests)
- [Sicherheit](#sicherheit)

---

## Features

### 🛰️ Pfad-Tracker — zwei Modi (Umschalter im Kopf)

**1. Einzel-Dienst** (Quelle, Ziel, Protokoll, Port)
- **Live-Verdict pro Hop** aus der echten FortiGate: `router/lookup` +
  `firewall/policy-lookup`, per FortiManager `/sys/proxy/json` durchgereicht.
- **Hop-Kette** dynamisch aus Live-Routen + PrefixTable (connected Networks +
  statische Routen aller Geräte/VDOMs), nicht statisch konfiguriert.
- **Egress-Klassen**: `LOCAL` · `VDOM_LINK` · `OVERLAY` · `ROUTED` (Standort-
  kopplung) · `DEFAULT`.
- **Multi-VDOM**: tritt am Router-/Eintritts-VDOM ein und läuft per VDOM-Link
  weiter — **jede** durchlaufene VDOM-Policy wird geprüft (der Deny kann auf der
  Router-VDOM liegen, nicht erst am Ziel).
- **Grafischer Pfad** (ReactFlow) mit Regel-Detail pro Hop im FortiManager-Stil
  (Objekte gestapelt, Typ-Icons Adresse/Gruppe/VIP/Dienst).
- **Regelvorschlag bei Deny** für **jede** blockierende Firewall (CLI +
  JSON-RPC + Deep-Link ins FMG-Policy-Package) — nur Anzeige.
- **Degraded Mode**: Gerät offline → Route aus dem Cache, Verdict `UNKNOWN`.
- **Debug-Drawer**: kopierbare Routing- und Policy-Lookups pro Hop (Proxy-
  Request + Response) zum Reproduzieren, wenn ein Hop hakt.

**2. Deep-Tracker — alle Ports** (nur Quelle + Ziel)
- Zeigt **alle end-to-end erlaubten TCP/UDP-Ports** über den gesamten Pfad.
- **Statisch aus dem Cache** (First-Match-Intervall-Engine über die geordneten
  Policies, Schnittmenge über alle Hops) — **kein Live-Lookup**, läuft daher
  auch, wenn Geräte offline sind.
- **Pro-Firewall-Aufschlüsselung** + **„Blockade je Bereich"**: welcher Hop
  welchen Portbereich blockt („wo stirbt Port X").
- v1-Randfälle werden **gewarnt** statt still falsch gerechnet: VIP/DNAT,
  Internet-Service/ISDB, negierte Adress-/Service-Felder.

### ✅ Checks — Batch-Regression

Benannte Gruppen von Test-Flows (Soll vs. Ist) als Batch prüfen — vor und nach
Umsetzung im FortiManager. Aus einem Trace übernehmbar; Deny-Details +
Regelvorschlag + grafischer Trace als Overlay. Quelle/Ziel werden über
FMG/iTop/DNS aufgelöst.

### 🧰 Werkzeuge

- **Netz-Zugehörigkeit** — an welchem VDOM/Interface ist ein Netz *connected*
  (der Ursprung)? Mit VLAN, Maske, Gateway; Warnung bei Mehrdeutigkeit.
- **IP-Rechner** — Host/Maske oder Netzsegment → Netz, Maske, Host-Range,
  Broadcast (jodies-ipcalc-Stil).
- **Freies Subnetz finden** — freie Blöcke gewünschter Größe in einem Supernet;
  belegter Bestand aus iTop (IPAM). Standort-Supernetze als Vorauswahl (in den
  Einstellungen pflegbar).

### 🔎 Resolver & Namensauflösung

FMG-Objekte → **iTop** (TeemIP) → **DNS**, mit Provenance-Anzeige in beide
Richtungen. Autocomplete für Quelle/Ziel.

### ⚙️ Betrieb

- **Sync-Scheduling**: FMG-Auto-Sync (Default täglich, in der UI wählbar:
  täglich / 6 h / 1 h / 30 min / aus) + manueller Sync-Button. iTop-Namensindex:
  täglicher Refresh + Button.
- **SSL/TLS**: kein Cert / Upload / self-signed / ACME, inkl. Hostname.
- **SAML 2.0 SSO** (onelogin) neben lokalem Login.
- **Rollen**: `admin` (Config/Sync/Users) und `viewer` (Trace/Suche/Verlauf).
- **Verlauf** aller Traces.
- **Demo-Modus** ohne FMG: `?demo=1`, Login `demo`/`demo`.

---

## Architektur

```
Frontend (React + TS + Vite + Tailwind, nginx)
   │  /api/trace         → Einzel-Dienst (live)
   │  /api/trace/ports   → Deep-Tracker (statisch aus Cache)
   ▼
FastAPI (api/src)
   ├─ engine/path.py     Hop-Loop; _walk_path (Pfad, portunabhängig) wird von
   │                      beiden Modi geteilt → keine Divergenz
   │      Einzel-Dienst: pro Hop router/lookup + firewall/policy-lookup (live)
   │      Deep-Tracker : pro Hop hop_allowed() aus dem Cache + combine()
   ├─ engine/ports.py    Intervall-Algebra (merge/intersect/subtract)
   ├─ fmg/proxy.py       exec /sys/proxy/json → FortiManager → FortiGate
   ├─ inventory/sync.py  pm/config get → fmg_snapshot (PostgreSQL)
   └─ Read-Models        PrefixTable · Zonen/Aliase · Policies · Objekte (In-Memory)
   ▼
PostgreSQL (Snapshot + system_config + Trace-Verlauf + Users)
```

- **Live-first (Einzel-Dienst)**: nur die FortiGate kennt den Routing-Echtzeit-
  zustand. Die FMG-DB wird gecacht für Kandidaten, Namen und Vorschläge.
- **Cache-only (Deep-Tracker)**: die Alle-Ports-Analyse rechnet komplett aus dem
  Cache — kein zusätzlicher FMG-Load, funktioniert offline.
- **IPv6**: out of scope in V1 (sauberer 400).

---

## Quickstart

```bash
cp .env.example .env         # POSTGRES_PASSWORD + JWT_SECRET setzen (Pflicht!)
docker compose up -d --build
# → http://<host>:8766/     Login: admin / $ADMIN_PASSWORD  (Default: admin)
```

Danach im Web-UI unter **Einstellungen → FortiManager**: Host + API-Token
eintragen, **Verbindung testen** (zeigt Version + ADOMs), ADOMs wählen,
**Speichern**, **Sync starten**. Sobald der Sync durch ist, funktionieren Trace,
Autocomplete und Vorschläge.

Ohne echtes Lab: `docker compose --profile sim up -d --build` startet einen
FortiManager-JSON-RPC-**Simulator** (`fmg-sim`). Im Tracker konfigurieren:
`host=fmg-sim`, `ssl_verify=false`, `auth_mode=token`, Token beliebig,
`adoms=[corp]`. Topologie: `fmg-sim/lab.yaml`.

---

## Deployment

Drei fertige Compose-Varianten:

| Datei | Einsatz |
|---|---|
| `docker-compose.yml` | Lokal / CLI (`docker compose up -d --build`) |
| `docker-compose.portainer.yml` | Portainer-Stack aus **Git-Repo** |
| `docker-compose.portainer-webeditor.yml` | Portainer-Stack via **Web-Editor** (Repo liegt auf dem Host) |

**Stack:** `db` (postgres:16-alpine) · `api` (FastAPI/uvicorn, Python 3.12) ·
`frontend` (Vite-Build → nginx) · optional `fmg-sim` (`--profile sim`).
Log-Rotation 5 × 50 MB pro Container. Migrations laufen beim API-Start.

**Host-Ports** frei wählbar (Default `HTTP_PORT=8766`, `HTTPS_PORT=8443`; der
Container lauscht intern weiter auf 80/443 — hoch gewählt, da der Host oft schon
80/443 belegt).

**Persistenz** in Volumes: `db-data` (Postgres), `certs` (TLS-Cert/Hostname; api
schreibt, frontend-nginx liest), `fmg-fixtures` (aufgezeichnete FMG-Antworten).

### Portainer (Web-Editor)

Repo auf den Host legen (Default `/opt/a38/fwpathtracker`, sonst `REPO_ROOT`
setzen), dann Portainer → *Stacks → Add stack → Web editor*, Inhalt von
`docker-compose.portainer-webeditor.yml` einfügen und unter *Environment
variables* die Secrets (+ ggf. Proxy-Vars, s.u.) setzen.

---

## Proxy-Umgebungen

Der Build hinter einem Corporate-Proxy hat **zwei getrennte Ebenen** — das war
die eigentliche Stolperfalle, hier die saubere Lösung:

| Ebene | Was | Wer macht den Proxy | Konfiguration |
|---|---|---|---|
| **RUN-Schritte** | `apt` / `pip` / `npm` im Image-Build | der **Build-Stack** | `build.args` (unten) |
| **FROM-Pull** | Base-Images ziehen (`python:3.12-slim` …) | der **Docker-Daemon** | `daemon.json` auf dem Host |

### 1. RUN-Schritte — über `build.args` (schon im Compose gelöst)

Alle Stacks reichen die Proxy-Variablen als **vordefinierte Build-Args** durch
(ein YAML-Anchor `x-proxy-args`, an jeden Service gehängt):

```yaml
x-proxy-args: &proxy-args
  HTTP_PROXY: ${HTTP_PROXY:-}
  HTTPS_PROXY: ${HTTPS_PROXY:-}
  NO_PROXY: ${NO_PROXY:-}
  http_proxy: ${HTTP_PROXY:-}
  https_proxy: ${HTTPS_PROXY:-}
  no_proxy: ${NO_PROXY:-}
```

Warum das *gut* gelöst ist:
- `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` sind von Docker **vordefinierte Build-Args**
  — sie wirken in `RUN` **ohne** eine `ARG`-Deklaration im Dockerfile **und landen
  nicht im Image** (kein Secret-/Config-Leak, kein Proxy zur Laufzeit).
- **Default leer** (`${VAR:-}`) → ohne gesetzte Variablen baut es exakt wie ohne
  Proxy. Kein Zwang, keine Sonderpfade.
- Groß- **und** Kleinschreibung, weil manche Tools nur die eine Variante lesen.

Setzen (in `.env` oder Portainer-*Environment variables*):

```bash
HTTP_PROXY=http://PROXYHOST:PORT
HTTPS_PROXY=http://PROXYHOST:PORT
NO_PROXY=localhost,127.0.0.1,::1,db,api,frontend,fmg-sim,.local
```

### 2. FROM-Pull — einmalig am Docker-Daemon

Den Base-Image-Pull macht der **Daemon**, nicht der Stack — Build-Args greifen
hier nicht. Einmalig auf dem Host `/etc/docker/daemon.json`:

```json
{
  "proxies": {
    "http-proxy":  "http://PROXYHOST:PORT",
    "https-proxy": "http://PROXYHOST:PORT",
    "no-proxy":    "localhost,127.0.0.1,::1"
  }
}
```

```bash
systemctl restart docker
```

> Symptom, wenn nur Ebene 1 gesetzt ist: `apt`/`pip`/`npm` laufen, aber der Build
> bricht schon beim `FROM …`-Pull mit *„Could not resolve …"* ab, obwohl das
> Proxy-Log sauber aussieht. → Ebene 2 (daemon.json) fehlt.

### 3. Laufzeit — bewusst **kein** Proxy

Die Container reden zur Laufzeit nur ins Kundennetz (FortiManager, iTop, DNS) —
daher **keine** Proxy-ENV im laufenden Container. `NO_PROXY` deckt zusätzlich die
internen Servicenamen (`db`, `api`, `frontend`) ab.

> **Git hinter Proxy** (falls `git pull` auf dem Host hängt, obwohl Docker
> läuft): `git config --global http.proxy http://PROXYHOST:PORT` — git nutzt den
> Daemon-Proxy nicht automatisch.

---

## Konfiguration

**Infrastruktur-Secrets** in `.env` (nur diese; fachliche Config liegt in der DB):

| Variable | Pflicht | Default | Zweck |
|---|---|---|---|
| `POSTGRES_PASSWORD` | ✔ (fail-closed) | — | Postgres |
| `JWT_SECRET` | ✔ (fail-closed) | — | JWT HS256 |
| `ADMIN_PASSWORD` | | `admin` | Initial-Passwort des `admin`-Users |
| `HTTP_PORT` / `HTTPS_PORT` | | `8766` / `8443` | Host-Ports |
| `FMG_RECORD_FIXTURES` | | `0` | Lab-Mitschnitt (Tests/Demo) |
| `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` | | leer | Build-Proxy (s.o.) |

**Fachliche Config** liegt in `system_config` (JSONB, per Web-UI) — Keys:
`fmg`, `itop`, `dns`, `sites`, `tracker`, `saml`, `checks`, `site_supernets`.
`GET /api/config/*` maskiert Secrets (`•••`), `PATCH` merged den Sentinel zurück.

---

## No-Write-Garantie & FMG-Profil

Der Tracker schreibt **nie** in den FortiManager. Die Garantie liegt zentral in
`FmgClient.rpc()` (`api/src/fmg/client.py`): erlaubt sind nur `get` und `exec`,
`exec` nur für `/sys/login/user`, `/sys/logout`, `/sys/proxy/json`, und im
Proxy-Payload nur `action: "get"`. Abgesichert durch `tests/test_write_guard.py`.

**Empfohlenes FMG-Admin-Profil (read-only):**
1. *System Settings → Admin → Profile*: neues Profil, alles `None` außer
   `Device Manager` = Read-Only und `Policy & Objects` = Read-Only.
2. **REST-API-Admin** (FMG ≥ 7.2.2): Profil zuweisen, `rpc-permit read`,
   Trusted Host = Tracker-Host, API-Token erzeugen.
3. Falls die FMG-Version für `exec /sys/proxy/json` `read-write` verlangt:
   `rpc-permit read-write` setzen — das restriktive Profil + der Code-Write-Guard
   tragen die Garantie dann gemeinsam.
4. Fallback FMG < 7.2.2: Auth-Modus „User/Passwort (Session)" im FMG-Panel.

---

## FortiManager-Besonderheiten

Aus der Feldpraxis in den Engine-Code eingeflossen:

- **Eintritts-VDOM-Wahl**: robust über den VDOM-**Namen** (`Router`/`WAN-Edge`,
  Pattern konfigurierbar), da das Routing dynamisch ist (BGP übers SD-WAN) und
  die Default-Route nicht immer statisch sichtbar. Fallbacks: Default-Route-Edge,
  Overlay/Tunnel-Terminierung, Reverse-Route.
- **Connected schlägt statisch** (unabhängig von der Maske); **deaktivierte
  Interfaces** zählen nicht als connected/Ingress; **Secondary-IPs** werden
  erfasst.
- **Normalisierte Interfaces** (`obj/dynamic/interface`): ein lokales Interface
  kann zu **mehreren** normalisierten Interfaces gehören, und Mappings kommen in
  **zwei** Formen — per-Gerät `dynamic_mapping` **und** geräteübergreifendes
  `default-mapping`/`defmap-intf`. Beide werden aufgelöst (`zones_of`), sodass
  eine Policy jeden Alias des Egress-/Ingress-Interfaces referenzieren darf.
  Zusätzliches Sicherheitsnetz im Deep-Tracker: adressverankerte Auswahl, falls
  das Interface-Naming zwischen Routing-Egress und Policy-Interface abweicht.
- **iTop** hat keine Subnetz→Firewall-Zuordnung (nur einen Subnetz-Baum) — die
  Owner-Bestimmung läuft daher über Routing/PrefixTable, nicht über iTop.

---

## Entwicklung & Tests

```bash
# Backend-Tests (offline, deterministisch via FixtureTransport)
cd api && pip install -r requirements.txt pytest pytest-asyncio && pytest

# Frontend-Dev-Server (proxied /api → localhost:8000)
cd frontend && npm install && npm run dev
```

**Fixtures aufzeichnen** (Lab): `FMG_RECORD_FIXTURES=1` in `.env` — jede echte
FMG-Antwort landet als `{request, response}`-JSON im `fmg-fixtures`-Volume. Nach
`api/tests/fixtures/fmg/` kopiert werden sie zu pytest-/Demo-Fixtures (Key = Hash
über das normalisierte Request-Payload; session/id werden gestrippt).

**Offene Lab-Validierungen (ASSUMPTIONS):** exaktes Erfolgs-Payload von
`firewall/policy-lookup`; Feldnamen der `router/lookup`-Antwort
(`interface`/`oif`/`gateway`); `rpc-permit read` vs. `read-write` für
`/sys/proxy/json`; vdom-link-Erkennung (`<base>0/<base>1` + Typ).

---

## Sicherheit

- **SSRF-Guard** (`netguard.py`) auf allen admin-konfigurierbaren Zielen
  (FMG-Host, iTop-URL, DNS-Resolver): blockt loopback/link-local inkl.
  Cloud-Metadata; private LAN-Ranges bleiben erlaubt.
- **Secrets**: FMG-Token/iTop-Passwort in der DB, maskiert bei `GET`. In Env nur
  `JWT_SECRET`/`POSTGRES_PASSWORD` (fail-closed `${VAR:?}`).
- **TLS-Verify** gegen FMG/iTop default **an** (Opt-out pro Verbindung).
- **Rollen**: `admin` vs. `viewer`; JWT HS256.
- **Kein Schreibzugriff** auf den FortiManager (s.o.).

---

*A38 folgt den ids-Patterns (FastAPI + asyncpg, `system_config`-JSONB, JWT HS256,
Compose-Idiome), ist aber ein eigenständiges Repo ohne Laufzeit-Abhängigkeit.*
