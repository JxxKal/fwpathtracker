# Webdrive-Dashboard

Planung für eine Übersicht über das Webdrive (OpenCloud) in der Umgebung
OT-Prod-Offline: Wer ist angemeldet, wer hat ein Problem und warum.

**Stand:** 07.10.2026 · Entwurf, noch nichts umgesetzt
**Betrifft:** neues Backend-Modul `api/src/webdrive/`, Migration
`006_webdrive.sql`, neuer Reiter „Webdrive“, neues Einstellungs-Panel

---

## 1. Worum es geht

Das Webdrive ist eine OpenCloud-Instanz. Angemeldet wird über OAuth/OIDC, und
der FortiAuthenticator (FAC) ist der Identity Provider. Die User kommen per
LDAP-Sync (Regel `Webdrive-User`) aus dem AD in den FAC.

Scheitert eine Anmeldung, sieht man das heute an keiner Stelle zusammenhängend:

- Der FAC meldet den Login als **erfolgreich**. Er hat ja einen Token
  ausgestellt.
- OpenCloud lehnt den User danach ab, weil ein AD-Attribut fehlt. Im Log steht
  das in einer Zeile, die man suchen muss.
- Ob eine AD-Korrektur schon im FAC angekommen ist, hängt am nächsten Sync.

Das Dashboard soll **Zustände zeigen, keine Logzeilen**: „User X ist aktiv“,
„User Y hat ein Problem, Grund: Nachname fehlt im AD“, „letzter Sync 12:04“.
Wer Details braucht, kommt mit einem Link direkt in Graylog.

### Referenzfall 07.10.2026

Ein User meldete sich zum ersten Mal an:

| Zeit (UTC) | FAC | OpenCloud |
|---|---|---|
| 05:15 | Login mit E-Mail als Username → `NAS cannot find user realm` | |
| 05:16 | Login als `op-tech\user` → `user not filtered by groups` | |
| 06:38–10:32 | 11× Login ok, Token ausgestellt, je **1×** Userinfo abgerufen | 11× `could not create user: empty displayname` |
| 07:04 | Sync ändert die E-Mail des Users | ab 07:21 neue E-Mail im Claim, Fehler bleibt |
| 10:41:52 | Manueller Sync, `changed fields: first name and last name` | |
| 10:43:51 | Login ok, danach laufend Userinfo-Abrufe | User angelegt, arbeitet |

Die Ursache war der fehlende Nachname im AD. OpenCloud bildet daraus den
`displayName` und lehnt einen leeren Wert ab. Eine fehlende E-Mail führt
genauso zum Abbruch.

---

## 2. Datenquelle: Graylog, Abfrage jede Minute

FAC und OpenCloud schicken ihre Logs beide nach Graylog. A38 fragt Graylog
**jede Minute** über die REST-API ab (Variante „Pull“). Ein GELF-Eingang in A38
wurde erwogen und verworfen: Pull verliert bei einem Neustart von A38 nichts
und kann Rückschau halten.

- **Endpoint:** `GET /api/search/universal/absolute` mit `query`, `from`, `to`,
  `limit`, `offset`, `sort=timestamp:asc` und optional `filter=streams:<id>`.
  Diesen Endpoint gibt es in Graylog 4 bis 6.
- **Authentifizierung:** API-Token als Basic Auth (`<token>:token`). Der Token
  sollte zu einem eigenen Graylog-User nur mit Leserechten gehören.
- **Zeitfenster:** von „bis wohin zuletzt erfolgreich abgefragt“ minus 2 min
  Überlappung bis jetzt. Höchstens 24 h nachholen.
- **Vorfilter in der Abfrage:** Die Abfrage schließt das bekannte Rauschen
  serverseitig aus, vor allem `Failed to send user info due to invalid_token`.
  Das sind etwa 1.400 Meldungen am Tag von einem einzigen verwaisten Browser-Tab.
- **Seitenweise Abfrage:** 500 Nachrichten pro Seite, bis die Antwort leer ist.

**Offen, beim ersten Kontakt prüfen:** Wie Graylog die Nachrichten ablegt. Der
Parser arbeitet deshalb auf dem Rohtext im Feld `message`. Beim FAC ist das die
`key="value"`-Zeile. Bei OpenCloud ist es die JSON-Zeile; liegen deren Felder
schon extrahiert vor, nimmt der Parser die Felder. Wo die Graylog-Felder
anders heißen, wird der Parser an einer echten Nachricht angepasst.

---

## 3. Ereignisse

`parse.py` übersetzt jede Graylog-Nachricht in **höchstens ein** normiertes
Ereignis oder verwirft sie. Gespeichert werden nur Ereignisse, keine Rohzeilen.

### 3.1 FAC

| Ereignis | Erkennung (logid, Text) | Felder |
|---|---|---|
| `portal_login_ok` | `20701` „[U] has successfully logged in OAuth portal“ | user, client_ip |
| `portal_login_failed` | `20702` „[U] has failed to log in OAuth portal“ | user (wie eingegeben), client_ip |
| `auth_failed_reason` | Zeile ≤ 2 s vor `20702`, gleicher User: `20102`/`20103`/`20104`/`20324`/`20355`/`20100 … not been imported` | user, reason (siehe 3.3) |
| `login_abandoned` | `20114` „Failed 'FAC_GUI' login attempt was not followed by a successful login“ | user |
| `token_issued` | `20000` „Successful OAuth token login (<maske>)“ | token (Maske), client_ip |
| `userinfo_ok` | `20000` „Successfully returned user info (<maske>)“, nas = OpenCloud-IP | token |
| `sync_run` | `30303` „Performing … / Retrieved N user(s) / Found M modified / Successfully synced (rule: R)“, zusammengefasst je Lauf | rule, users, modified, ok |
| `user_added` | `10001` „Added Remote LDAP User: U“ | user |
| `attr_changed` | `10002` „Edited Remote LDAP User: U (changed fields: F)“, `10050`/`10051` „Set/Changed U email …“ | user, fields, old/new (falls im Text) |
| `user_locked` ○ | FAC-Sperre nach zu vielen Fehlversuchen | user |

Verworfen werden alle anderen FAC-Meldungen. Dazu gehören REST-API-Logins von
anderen Anwendungen (`nas="REST API"`, User `ldaps/…`), SAML-Logins anderer
Service Provider, Admin-Logins und Systemmeldungen.

### 3.2 OpenCloud

| Ereignis | Erkennung | Felder |
|---|---|---|
| `provision_failed` | service `graph`, „could not create user: …“ mit Objekt `user` | user (= `onPremisesSamAccountName`), reason (welches Feld leer ist) |
| `session_seen` | service `auth-machine`, „user idp:… opaque_id:X type:USER_TYPE_PRIMARY authenticated“ | opaque_id |
| `file_scanned` | service `antivirus`, „File scanned“ | opaque_id (`user`), filename, infected, virus, outcome |
| `scan_skipped` ○ | antivirus „max scan size“ o. ä. | opaque_id, filename |
| `upload_failed` ○ | access-log `PUT`/`POST`/`PATCH` auf `/dav/…` oder `/data/…` mit Status 400/413/423/507 | status, path; **User noch nicht zuordenbar** |
| `upload_incomplete` ○ | storage-users `ChunkWriteStart` ohne `UploadFinished` nach 30 min | upload-id |
| `postprocessing_failed` ○ | service `postprocessing`, Level error | upload-id |

**○ = Muster noch nicht an einem echten Fall geprüft.** Im Log vom 07.10. gab
es weder Virusfunde noch Upload-Fehler. Nach der Inbetriebnahme helfen ein
Test-Upload von EICAR und eine Datei über dem Limit, die Muster zu prüfen.
Fehler der Dienste antivirus, postprocessing und storage-users, die zu keinem
Muster passen, erscheinen bis dahin als „Datei-Problem (unbekannt)“.

Das Access-Log enthält keinen Usernamen, und `remote-addr` ist der Reverse
Proxy. Upload-Fehler aus dem Access-Log lassen sich deshalb vorerst keinem
User zuordnen. Sie erscheinen ohne Namen, bis eine zuverlässige Verknüpfung
gefunden ist.

### 3.3 Gründe im Klartext

| Rohgrund | Anzeige |
|---|---|
| `invalid password` | Falsches Passwort |
| `user password change required` | Passwort muss im AD geändert werden |
| `invalid user` | User im AD unbekannt |
| `NAS cannot find user realm` | Mit E-Mail statt Username angemeldet |
| `user not filtered by groups` | Nicht in der Webdrive-Gruppe |
| `… who has not been imported` | Noch nicht im FAC: Sync abwarten |
| `FortiToken failed: invalid token` | Falscher FortiToken-Code |
| locked out ○ | Im FAC gesperrt (zu viele Fehlversuche) |
| OC `displayName` leer | Name fehlt im AD (Vor-/Nachname) |
| OC `mail` leer | E-Mail fehlt im AD |
| OC `onPremisesSamAccountName` leer | sAMAccountName fehlt im AD |
| antivirus `infected=true` | Virus gefunden: <Datei> (<Virus>), <gelöscht/abgebrochen> |
| 413 / 507 / 423 / 400 ○ | Datei zu groß / Speicherplatz voll / Datei gesperrt / unzulässiger Dateiname |

Usernamen werden für den Vergleich normalisiert: Kleinschreibung, Präfixe
`op-tech\` und `ldaps/` entfernt. Angezeigt wird bei Realm-Fehlern trotzdem
das, was der User eingegeben hat, weil genau das der Fehler ist.

---

## 4. Korrelation

Kein Log enthält alles. Erst die Verknüpfung über drei Schlüssel ergibt das
Bild:

```
Username ──(FAC 20701, ±2 s)──▶ Token-Maske ──(FAC Userinfo / Zeit)──▶ OpenCloud opaque_id
```

1. **User → Token:** `token_issued` ≤ 2 s nach `portal_login_ok`. Bevorzugt
   wird dieselbe Client-IP. Die IP kann aber abweichen (am 07.10.: Login über
   .4, Token über .5); bei nur einem Kandidaten zählt deshalb die Zeit allein.
2. **Token → opaque_id:** Die erste `session_seen` einer bisher unbekannten
   opaque_id fällt sekundengenau auf den ersten `userinfo_ok` eines Tokens.
3. Die Zuordnung opaque_id → Username wird **dauerhaft** gespeichert
   (`webdrive_identity`). Sie muss länger leben als die 7 Tage der Ereignisse,
   denn eine einmal angelegte OpenCloud-Identität ändert sich nicht mehr.

**Nicht zuordenbare Sitzungen** (Token ohne Portal-Login, etwa ein
Desktop-Client oder ein Refresh) zählt das Dashboard nur: „+2 unbekannte
Sitzungen“.

**Fehlende Abmeldung:** Keines der Logs hat ein Abmelde-Ereignis. „Aktiv“
heißt deshalb: `session_seen` oder Userinfo-Abruf in den letzten 15 min
(einstellbar). Danach gilt der User als „heute angemeldet, nicht aktiv“, mit
erster und letzter Aktivität.

---

## 5. Zustand pro User

`state.py` ist eine reine Funktion `(Ereignisse, Identitäten, jetzt,
Einstellungen) → Dashboard`. Sie hat keine Seiteneffekte und lässt sich deshalb
gut testen.

| Zustand | Regel |
|---|---|
| **Problem: Anmeldung** | Das letzte Anmelde-Ereignis des Users ist ein Fehler (`portal_login_failed` mit Grund, `provision_failed`, `user_locked`), und danach kam keine erfolgreiche Sitzung. |
| **Problem: Datei** | Virusfund oder Datei-Fehler im gewählten Zeitraum. Bleibt bis Ende des Zeitraums stehen, weil es kein „behoben“ gibt. |
| **Hinweis: behoben** | Es gab ein Anmelde-Problem, danach war eine Sitzung erfolgreich, z. B. „Erstanmeldung scheiterte (Name fehlte im AD), behoben 10:43“. |
| **Hinweis: Fehlversuch** | Ein Fehlversuch mit späterem Erfolg, z. B. „1 Fehlversuch (Passwort), danach erfolgreich“. |
| **Hinweis: Attribut geändert** | `attr_changed` für einen User, der schon eine OpenCloud-Identität hat. Warnung, weil OpenCloud den User sonst evtl. doppelt anlegt. |
| **Aktiv** | Aktivität ≤ 15 min, mit „seit“ und Zahl der Uploads. |
| **Nicht aktiv** | Heute gesehen, aber > 15 min nichts mehr. |

**Sync-Kopfzeile:** letzter Lauf der Regel `Webdrive-User` mit Uhrzeit, Status
und Anzahl User, dazu die letzte Änderung durch einen Sync. Ein Lauf außerhalb
des üblichen Takts ist als „manuell“ markiert. Den Takt bestimmt die häufigste
Minute der letzten 24 Läufe.

---

## 6. Ansicht

```
┌ Webdrive ──────────────────────── Stand 12:41 · Zeitraum: [Heute ▾] ┐
│ Sync „Webdrive-User“: 12:04 ✓ · 25 User · zuletzt geändert 10:41     │
│                       (manuell) user-a: Name                         │
├──────────────────────────────────────────────────────────────────────┤
│ ⚠ PROBLEME (2)                                                       │
│  user-b   Falsches Passwort · 4 Versuche 13:22 · kein Erfolg         │
│  user-c   Virus gefunden: Report.pdf (Win.Test.EICAR) gelöscht       │
│                                                    [im Graylog ↗]    │
├──────────────────────────────────────────────────────────────────────┤
│ ⚑ HINWEISE (2)                                                       │
│  user-a   Erstanmeldung scheiterte (Name fehlte im AD), behoben 10:43│
│  user-d   1 Fehlversuch (Passwort), danach erfolgreich               │
├──────────────────────────────────────────────────────────────────────┤
│ ● AKTIV (3)                     │ ○ HEUTE ANGEMELDET, NICHT AKTIV (2)  │
│  user-d   seit 07:23            │  user-e   10:12 – 11:48              │
│  user-c   seit 05:26 · ⬆13      │  user-f   07:00 – 11:48              │
│  user-a   seit 10:43            │  +2 unbekannte Sitzungen             │
└──────────────────────────────────────────────────────────────────────┘
```

- **Zeitraum:** Heute (ab 00:00 Ortszeit, Standard), 24 h, 7 Tage.
- **Uhrzeiten** in Europe/Berlin. Die Logs liefern UTC.
- **Aktualisierung** jede Minute, solange der Reiter offen ist.
- **„im Graylog ↗“** je User öffnet die Graylog-Suche nach diesem User im
  gewählten Zeitraum. Logzeilen zeigt A38 nirgends an.
- **Kopfzeile „Stand hh:mm“:** zeigt, wann Graylog zuletzt erfolgreich abgefragt
  wurde. Liegt das mehr als 3 min zurück, steht dort ein Hinweis, damit ein
  veralteter Stand nicht wie „alles in Ordnung“ aussieht.
- **Zugriff:** Das Dashboard sehen alle Rollen, die Einstellungen nur Admins.

**Nicht im Umfang von V1:** ein eigener System-Block (Virenscanner ausgefallen,
Zertifikatsfehler). Ebenfalls nicht abgedeckt ist, wer die Login-Seite gar
nicht erreicht (Firewall, DNS). Das hinterlässt in keinem der beiden Logs eine
Spur.

---

## 7. Umsetzung

### Backend `api/src/webdrive/`

| Datei | Aufgabe |
|---|---|
| `graylog.py` | `GraylogClient`: `search(query, frm, to)` seitenweise, `test()`. httpx, `ssl_verify`, Timeout, `guard_egress_url` (Muster `librenms/client.py`) |
| `parse.py` | Nachricht → Ereignis oder `None`, inkl. FAC-`key="value"`-Parser |
| `correlate.py` | Paarung `portal_login_failed` ↔ Grund, User ↔ Token ↔ opaque_id |
| `state.py` | reine Funktion → Dashboard-Modell |
| `store.py` | Ereignisse schreiben (dedupliziert), lesen, Identitäten, Abfrage-Stand, Aufräumen nach 7 Tagen |
| `poller.py` | `_periodic_webdrive_poll` im `lifespan` von `main.py`, Muster wie `_periodic_arp_sweep` |
| `routers/webdrive.py` | `GET /api/webdrive/status?range=today\|24h\|7d` (alle Rollen), `POST /api/webdrive/test` (Admin), `GET /api/webdrive/poller` (Admin: letzter Lauf, Fehler, verworfen/erkannt) |

### Migration `006_webdrive.sql`

```sql
CREATE TABLE IF NOT EXISTS webdrive_event (
    id         BIGSERIAL PRIMARY KEY,
    gl_id      TEXT NOT NULL UNIQUE,      -- Graylog-Nachrichten-ID, gegen Doppelte
    ts         TIMESTAMPTZ NOT NULL,
    source     TEXT NOT NULL,             -- 'fac' | 'oc'
    kind       TEXT NOT NULL,
    username   TEXT,
    token      TEXT,
    opaque_id  TEXT,
    data       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS webdrive_event_ts ON webdrive_event (ts);

CREATE TABLE IF NOT EXISTS webdrive_identity (
    opaque_id  TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS webdrive_poll (
    id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    polled_until TIMESTAMPTZ,
    last_ok     TIMESTAMPTZ,
    last_error  TEXT,
    stats       JSONB NOT NULL DEFAULT '{}'
);

INSERT INTO system_config (key, value) VALUES ('webdrive', '{
  "base_url": "", "token": "", "ssl_verify": true, "timeout_s": 20,
  "stream_id": "", "fac_query": "", "oc_query": "",
  "oc_ip": "10.180.18.69", "sync_rule": "Webdrive-User",
  "active_window_min": 15, "poll_interval_s": 60, "retention_days": 7
}') ON CONFLICT (key) DO NOTHING;
```

Außerdem: `webdrive` in `KNOWN_KEYS` (`routers/config.py`) und
`"webdrive": ("token",)` in `SECRET_FIELDS` (`secrets_mask.py`).

### Frontend

- Neuer Reiter `webdrive` in `App.tsx`: `Tab`-Typ, Header-Button, `readTab`,
  Render-Zweig. Sichtbar für alle Rollen.
- `components/webdrive/WebdriveDashboard.tsx` mit den Blöcken aus Abschnitt 6.
- `components/settings/WebdrivePanel.tsx` nach dem Muster von
  `LibrenmsPanel.tsx` (Verbindungstest), eingehängt unter „Quellen“.
- Texte in `i18n/de.ts`, API-Funktionen mit Demo-Daten in `api.ts`.

### Fehlerbehandlung

- **Nicht konfiguriert:** Der Poller prüft alle 5 min erneut. Das Dashboard
  zeigt „Graylog nicht eingerichtet → Einstellungen“.
- **Graylog nicht erreichbar oder 401:** Der Poller schreibt eine Warnung ins
  Log und rückt `polled_until` **nicht** vor. Die Lücke wird beim nächsten
  Erfolg nachgeholt (höchstens 24 h). Das Dashboard zeigt den letzten Stand
  mit Hinweis.
- **Unbekanntes Format:** Die Nachricht wird verworfen und in `stats` gezählt,
  getrennt nach Quelle. Ein plötzlicher Anstieg weist auf ein geändertes
  Logformat hin.

### Tests

- `test_webdrive_parse.py`: je Ereignis eine echte, anonymisierte Logzeile aus
  den Logs vom 07.10. als Fixture.
- `test_webdrive_state.py`: Der Referenzfall aus Abschnitt 1 als Szenario
  (behoben 10:43, Fehlversuch mit Erfolg, aktiv / nicht aktiv, unbekannte
  Sitzungen). Dazu Randfälle: Problem ohne späteren Erfolg, Virusfund,
  Attribut-Änderung nach der Erstanmeldung, Grenze des Aktiv-Fensters,
  manueller Sync.
- `test_webdrive_poller.py`: Fake-Graylog mit gleicher Signatur wie
  `GraylogClient`. Geprüft werden Seitenweise-Abfrage, Weiterrücken, Nachholen
  nach Ausfall und Deduplizierung.
- Frontend: `npm run build` (Typprüfung) und Demo-Daten.
