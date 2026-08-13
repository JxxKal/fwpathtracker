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
- [Switchport-Suche (LibreNMS)](#switchport-suche-librenms)
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
- **Geteiltes Underlay/SD-WAN**: zeigt die Route ein Gateway, das **keinem**
  gemanagten FortiGate-Interface gehört (SD-WAN-Appliance, Provider-Router),
  gilt ein Nachbar im selben Transit-Netz **nicht** als nächster Hop — der Pfad
  folgt dem Präfix-Besitzer des Ziels bzw. endet sichtbar am Uplink.
- **Degraded Mode**: Gerät offline → Route aus dem Cache, Verdict `UNKNOWN`.
- **Debug-Drawer**: kopierbare Routing- und Policy-Lookups pro Hop (Proxy-
  Request + Response) plus **Pfad-Entscheidung** je Hop — geprüfte Regeln
  (LOCAL/VDOM_LINK/OVERLAY/ROUTING/OWNER), Gateway-Auflösung, Mitglieder des
  Transit-Segments, Präfix-Besitzer des Ziels und die Eintritts-VDOM-Wahl.

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

- **Erledigt-Status**: ein bestandener Lauf markiert den Check automatisch als
  erledigt (mit Datum + Benutzer) — genau der Fall „nach der Umsetzung erfolgreich
  getestet". Manuell erledigen/wieder öffnen geht ebenso; der letzte Lauf bleibt
  am Check gespeichert (auch nach Reload). Fällt ein erledigter Check später um,
  bleibt der Haken stehen und die **Regression** wird markiert statt still
  zurückgesetzt. Gruppenkopf zeigt `erledigt/gesamt`, Erledigte sind ausblendbar.
- **Teilbare Links**: pro Check (und pro Gruppe) ein Link zum Kopieren
  (`?tab=checks&group=…&check=…`) — per Teams/Mail an Kollegen schicken; beim
  Öffnen springt der Tracker in die Gruppe und hebt den Check hervor.

### 🧰 Werkzeuge

- **Netz-Zugehörigkeit** — an welchem VDOM/Interface ist ein Netz *connected*
  (der Ursprung)? Mit VLAN, Maske, Gateway; Warnung bei Mehrdeutigkeit.
- **IP-Rechner** — Host/Maske oder Netzsegment → Netz, Maske, Host-Range,
  Broadcast (jodies-ipcalc-Stil).
- **Freies Subnetz finden** — freie Blöcke gewünschter Größe in einem Supernet;
  belegter Bestand aus iTop (IPAM). Standort-Supernetze als Vorauswahl (in den
  Einstellungen pflegbar).
- **Martin Lehmann, wo hängt das Gerät?** — IP oder Name → **Switch und Port**, an dem das Gerät
  physisch steckt. IP→MAC live von der FortiGate (die ist an fast allen
  Standorten der L3-Router), MAC→Port aus der **LibreNMS**-FDB. Zeigt alle
  Fundstellen mit Uplink-Kennzeichnung, Konfidenz und Alter des Eintrags —
  siehe [Switchport-Suche](#switchport-suche-librenms).

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
   ├─ locate/chain.py    IP →(ARP: FortiGate live | LibreNMS)→ MAC
   │                        →(FDB: LibreNMS)→ Switchport   [/api/locate]
   └─ Read-Models        PrefixTable · Zonen/Aliase · Policies · Objekte (In-Memory)
   ▼
PostgreSQL (Snapshot + system_config + Trace-Verlauf + Users)
```

- **Live-first (Einzel-Dienst)**: nur die FortiGate kennt den Routing-Echtzeit-
  zustand. Die FMG-DB wird gecacht für Kandidaten, Namen und Vorschläge.
- **Cache-only (Deep-Tracker)**: die Alle-Ports-Analyse rechnet komplett aus dem
  Cache — kein zusätzlicher FMG-Load, funktioniert offline.
- **Zwei Systeme, klar getrennt**: der FortiManager weiß, wer routet; LibreNMS
  weiß, an welchem Kupfer die MAC hängt. Der Tracker fragt jedes nach dem, was
  es tatsächlich weiß, statt eines von beiden zu überdehnen.
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
`fmg`, `itop`, `dns`, `sites`, `tracker`, `saml`, `checks`, `site_supernets`,
`librenms`.
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

## Switchport-Suche (LibreNMS)

Beantwortet die Frage, die der Pfad-Tracker offenlässt: *an welchem Switchport
steckt die IP eigentlich?* Zu finden im Tracker-Tab unter den Werkzeugen.

Die Aufgabe zerfällt in zwei Schritte, die verschiedene Systeme beantworten:

| Schritt | Quelle | Weg |
|---|---|---|
| IP → MAC | FortiGate (live) | vorhandener FMG-Proxy, VDOM über die PrefixTable |
| IP → MAC (L3-Switch-Standorte) | LibreNMS `ipv4_mac` | `/resources/ip/arp/{ip}` |
| MAC → Switchport | LibreNMS `ports_fdb` | `/resources/fdb/{mac}` |

Die ARP-Seite kommt bewusst zuerst von der FortiGate: sie ist an fast allen
Standorten der L3-Router und damit die einzige Stelle mit ARP für *alle* VLANs.
LibreNMS springt ein, wo stattdessen ein HPE-Stack routet — und als Auffangnetz,
wenn der Live-Weg klemmt (Gerät offline, Endpunkt fehlt).

### Welcher Port ist der richtige?

Der Knackpunkt ist nicht das Finden, sondern das Aussortieren: eine MAC steht
auf **jedem** Switch im Pfad in der FDB — dort jeweils auf dem Uplink.

Zuerst der **Topologie-Abgleich**, denn der ist kein Indiz, sondern eine
Aussage:

| Signal | Bedeutung |
|---|---|
| `lldp_peer` | Der LLDP-Nachbar dieses Ports **ist** das gesuchte Gerät |
| `description` | Die Port-Description nennt es beim Namen (`uplink-bpvo300`) |

Beides braucht die Namen des Ziels in allen Schreibweisen — der Tracker holt
sie aus derselben Resolver-Kette wie Quelle/Ziel im Pfad-Tracker
(FMG-Adressobjekt → iTop → DNS) und ergänzt den LibreNMS-Hostnamen. Damit lässt
sich `10.133.167.5` gegen einen LLDP-Nachbarn namens `bpvo004` abgleichen.
Beim `lldp_peer` ist die Portklasse ausdrücklich egal: für einen Switch als
Suchziel *ist* die Antwort ein Uplink — nämlich der mit der passenden
Nachbarschaft.

Erst wenn kein Abgleich greift, entscheidet die Heuristik. Und dort gilt:
*„Port mit vielen MACs" ist nicht gleichbedeutend mit „falsch"*. Eine VM auf
einem Hypervisor hängt völlig legitim hinter einem Trunk mit Dutzenden MACs.
Ausschließen lässt sich nur der echte **Switch-zu-Switch-Uplink**, erkennbar an
der `remote_device_id` im `links`-Endpunkt — LibreNMS setzt sie nur, wenn der
LLDP-Nachbar selbst überwacht wird:

| Klasse | Signal | Bedeutung |
|---|---|---|
| `access` | wenige MACs, kein LLDP | der Normalfall |
| `edge` | LLDP-Nachbar, **nicht** überwacht | Hypervisor, AP, Telefon |
| `trunk` | viele MACs, kein LLDP | Ring-Uplink **oder** ESX-Trunk |
| `uplink` | LLDP-Nachbar **ist** überwacht | hier steckt es sicher nicht |

Zwischen Abgleich und Klasse steht die **Aktualität**: ein FDB-Eintrag wird bei
jedem Discovery-Lauf aufgefrischt, solange die MAC dort noch gesehen wird. Ein
alter Eintrag heißt also „die MAC ist von diesem Port verschwunden". Gebucketet
über `recency_bucket_s` (Default 1 h), damit gleich frische Treffer nicht durch
Sekunden Versatz zwischen zwei Discovery-Läufen auseinanderfallen.

Die vollständige Reihenfolge ist damit:
**Abgleich → Aktualität → Portklasse → MAC-Zahl.**

Das Ergebnis bekommt eine Konfidenz (`high`/`medium`/`low`) und immer das
**Alter** des Eintrags — FDB-Einträge altern in Minuten, LibreNMS discovert per
Default alle 6 Stunden.

### Wenn die gesuchte IP selbst ein Switch ist

Dann ist die Portsuche die falsche Frage: die Management-MAC eines Switches
steht per Definition nur auf Uplinks, weil es keinen Access-Port gibt, an dem
er „hängt". Der Tracker erkennt das über den Geräteindex (`/devices`) und
beantwortet stattdessen die Frage, die gemeint war — **wo ist das Gerät
angeschlossen?** — aus den LLDP-Nachbarn des Geräts selbst.

### Zugriff

Nur lesend über die LibreNMS-v0-API mit einem normalen API-Token
(*LibreNMS → Settings → API → API Access*), kein DB-Zugriff. Eintragen unter
**Einstellungen → LibreNMS**; der Token wird wie alle Secrets maskiert
zurückgeliefert. Gecacht werden LLDP-Links, Geräte-Stammdaten und Portlisten
(15 min) sowie die FDB je Gerät (5 min) — der Button *Cache aktualisieren*
leert sie nach einer frisch angestoßenen Discovery.

Bewusst wird `/resources/fdb/{mac}` genutzt und **nicht** `/detail`: die
Detail-Variante verknüpft intern mit der VLAN-Tabelle, und Geräte ohne
VLAN-Zuordnung in der FDB können dort herausfallen. Die Portnamen kommen
stattdessen aus `/devices/{id}/ports`.

### Im Pfad-Graphen

Quelle und Ziel im Trace-Graphen zeigen ihren physischen Switchport als zweite
Zeile im Endpunkt-Knoten — Switch, Port und Port-Description, eingefärbt nach
Konfidenz. Damit steht der komplette Weg in einem Bild: vom Kupfer über die
Firewalls bis zum Ziel-Kupfer.

Nachgeladen wird **nach** dem Trace, nicht als Teil davon. Die Pfadanalyse soll
weder auf LibreNMS warten noch scheitern, wenn dort nichts konfiguriert ist;
Fehler werden geschluckt und der Knoten bleibt schlicht unverändert. Endet der
Pfad im Internet, wird für das Ziel gar nicht erst gesucht.

### MOXA

MOXA-Switches liefern out of the box **einen** FDB-Eintrag und sind damit für
die Suche blind — ihre Firmware implementiert `dot1qTpFdbTable` als Stub,
während die vollständige Tabelle in der BRIDGE-MIB liegt. Der Fix an LibreNMS
ist dokumentiert in
[docs/wiki/LibreNMS-MOXA-FDB.md](docs/wiki/LibreNMS-MOXA-FDB.md).

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
