# fmg-sim — FortiManager-JSON-RPC-Simulator

Stellt die FortiManager-JSON-RPC-API so weit nach, wie der fw-path-tracker sie
nutzt — damit der **komplette Stack ohne echtes Lab** trocken durchgespielt
werden kann. Gleichzeitig ist der Simulator die **ausführbare Referenz** für die
API-Antwortshapes, die im Tracker-Plan noch als ASSUMPTIONS markiert sind:
weicht das echte Lab ab, wird die Abweichung hier korrigiert und der Tracker
bleibt unangetastet.

## Was emuliert wird

**Direkte FMG-Calls** (`method: get`):
- `/sys/status` — Version/Hostname (für den Verbindungstest)
- `/dvmdb/adom`, `/dvmdb/adom/<adom>/device` — ADOMs, Geräte + VDOMs
- `/pm/pkg/adom/<adom>` — Policy-Packages inkl. `scope member`
- `/pm/config/adom/<adom>/pkg/<pkg>/firewall/policy` — Policies (Reihenfolge!)
- `/pm/config/adom/<adom>/obj/firewall/{address,vip,service/custom}`,
  `obj/dynamic/interface` (Zonen mit per-Device `dynamic_mapping`)
- `/pm/config/device/<dev>/global/system/interface`
- `/pm/config/device/<dev>/vdom/<vdom>/router/static`

**Proxy-Calls** (`exec /sys/proxy/json` → FortiOS-Monitor der Ziel-FortiGate):
- `monitor/router/lookup` — Longest-Prefix-Match → Egress-Interface + Gateway
- `monitor/firewall/policy-lookup` — geordnetes Policy-Matching (Zonen, Adress-
  und Service-Objekte) → `{success, policy_id, action}` bzw. `{success:false}`
  (implizites Deny)

**Auth**: Token (`Authorization: Bearer <beliebig>`) und Session-Login
(`exec /sys/login/user` → `session`). Beides wird permissiv akzeptiert.

## Topologie bearbeiten

Alles steckt in [`lab.yaml`](./lab.yaml) — Standorte (/20), VDOMs, Interfaces,
Zonen, Policies, Objekte, statische Routen. `online: false` auf einem Gerät
lässt den Proxy „Ziel offline" melden (Degraded-Mode-Test).

`lab.yaml` ist als Volume gemountet — nach dem Editieren ohne Rebuild neu laden:

```bash
docker compose exec fmg-sim \
  python3 -c "import urllib.request,ssl; urllib.request.urlopen(urllib.request.Request('https://localhost/_reload',b'',{}),context=ssl._create_unverified_context())"
# danach im Tracker: Einstellungen → FortiManager → Sync (oder POST /api/fmg/sync)
```

## Starten & anbinden

```bash
docker compose --profile sim up -d --build fmg-sim
```

Im Tracker unter **Einstellungen → FortiManager** (oder per API):

| Feld       | Wert        |
|------------|-------------|
| host       | `fmg-sim`   |
| ssl_verify | `false` (self-signed Cert wie beim echten FMG) |
| auth_mode  | `token`     |
| token      | beliebig    |
| adoms      | `["corp"]`  |

`host: fmg-sim` (ohne Schema/Port) ist wichtig — so baut der Tracker
`base_url = https://fmg-sim` und der SSRF-Guard (blockt nur loopback/link-local)
lässt die private Bridge-IP durch.

## Fixtures für die Offline-OT-Umgebung

Läuft der Tracker mit `FMG_RECORD_FIXTURES=1`, zeichnet er jede Simulator-
Antwort als Fixture auf. So entsteht aus einem Sim-Durchlauf ein vollständiger
Fixture-Satz, mit dem der Tracker später auch ganz ohne Simulator
(`fixture_mode`) laufen kann — praktisch für den Transfer auf den Offline-Docker.

## Grenzen (bewusst)

- Kein NAT-Following (VIP wird erkannt und als Hinweis gemeldet, V1-Verhalten
  wie im Tracker selbst).
- Nur IPv4 (wie der Tracker in V1).
- Match-Semantik bildet FortiOS *hinreichend* nach, ist aber keine
  bit-genaue FortiOS-Engine — der Zweck ist der Durchstich des Stacks, nicht
  die Zertifizierung der FortiOS-Regelauswertung.
