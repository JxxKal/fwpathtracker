# „Stephan fragt, A38 antwortet" — der Wochenreport

Planung für einen automatisch erzeugten Wochenbericht über die Änderungen in der
Infrastruktur, aufbereitet zum Lesen und als PDF exportierbar.

**Stand:** 22.10.2026 · Entwurf, noch nichts umgesetzt
**Betrifft:** neue Pakete `api/src/report/` und `api/src/graylog/`, Aufteilung der
Webdrive-Einstellungen, Scheduler in `api/src/main.py`, neue Ansicht im Frontend,
ein Render-Dienst für PDF und draw.io-Bilder

---

## 1. Worum es geht

Freitagmorgen will jemand wissen, was diese Woche passiert ist, ohne dafür
FortiManager, iTop, Zabbix, Graylog und LibreNMS einzeln zu öffnen. Gefragt ist
keine Datensammlung, sondern eine Antwort auf wenige Fragen, die immer
wiederkehren. Deshalb ist der Report **als Fragen gegliedert**. Jedes Kapitel
ist eine Frage, die Stephan stellen würde, und beginnt mit einem Satz Antwort.
Erst darunter folgen Zahlen, Diagramme und Listen.

Leitsätze:

- **Erst die Aussage, dann der Beleg.** Jede Seite muss ohne Detailtabelle
  verständlich sein.
- **Nur Auffälliges im Fließtext.** Routine wird gezählt, Abweichungen werden
  genannt.
- **Lücken ehrlich ausweisen.** Fehlt eine Quelle, sagt der Report das, statt
  „keine Änderungen" zu behaupten. Das ist dieselbe Regel wie beim Zabbix-Punkt,
  wo kein Punkt „nicht überwacht" bedeutet und nicht „in Ordnung".
- **Jede Zahl ist anklickbar.** In der Web-Ansicht führt sie zur passenden
  Stelle in A38. Im PDF steht der Verweis als Fußnote.

---

## 2. Die Kapitel

Reihenfolge nach Bedeutung. Das Kapitel „Was sollte sich jemand ansehen?"
steht bewusst vorn und nicht am Ende.

| # | Frage | Antwort aus | Darstellung |
|---|---|---|---|
| 0 | **Die Woche auf einen Blick** | allen | Kacheln mit Vorwochenvergleich (▲▼), Heatmap Tag × Quelle |
| 1 | **Was sollte sich jemand ansehen?** | Querabgleich aller Quellen | kurze Liste mit Begründung und Verweis |
| 2 | **Was wurde an den Firewalls geändert?** | FAZ-Ereignislogs, FMG-Änderungsprotokoll | Zeitstrahl je Tag, Tabelle *wer, wann, welches Objekt* |
| 3 | **Was ist neu im Netz, was ist verschwunden?** | ARP-Historie, DNS-Cache, LibreNMS, iTop-Abgleich | Zahlen je Standort, Liste neuer Hosts mit iTop-Status |
| 4 | **Was hat sich an der Verkabelung getan?** | LibreNMS (LLDP, Ports, Geräte) | draw.io-Ausschnitt mit markierten Änderungen |
| 5 | **Was wurde im iTop gepflegt?** | iTop-Änderungslog (`CMDBChangeOp`) | Änderungen je Klasse und Bearbeiter |
| 6 | **Wie stabil lief der Betrieb?** | Zabbix-Ereignisse | Probleme nach Schwere je Tag, Top-10-Hosts, längste Ausfälle |
| 7 | **Was ist im Active Directory passiert?** | Graylog (AD-Logs) | Konten, privilegierte Gruppen, Sperrungen |
| 8 | **Was meldet iFIX?** | Graylog (iFIX-Logs) | *abhängig vom Logformat, siehe Abschnitt 9* |
| 9 | **Was wurde geblockt?** | FAZ-Traffic-Logs (Denies) | Top-Quellen und -Ziele, neue Deny-Muster gegenüber der Vorwoche |
| 10 | **Webdrive** | Webdrive-Store | Nutzer, Fehlanmeldungen, Trend |

### Kapitel 1: Was sollte sich jemand ansehen?

Das ist der eigentliche Mehrwert, denn kein Einzelsystem kann das allein. Es
entsteht nur aus dem Abgleich der Quellen:

- **Firewall-Änderung ohne iTop-Bezug.** Ein Adressobjekt oder eine Policy für
  eine IP, die im iTop nicht steht.
- **Änderung außerhalb des Änderungsfensters.** Konfiguriert nachts oder am
  Wochenende, mit Benutzer.
- **Neuer Host ohne Pflege.** Neu im Netz (ARP/FAZ), nicht im iTop, nicht in
  Zabbix.
- **Privilegierte AD-Gruppe geändert.** Domain Admins, Enterprise Admins und
  eine konfigurierbare Liste weiterer Gruppen.
- **Ausfall ohne Ticket- oder Änderungsbezug.** Ein Zabbix-Problem der Schwere
  „Hoch" oder höher, das zeitlich mit einer Firewall-Änderung zusammenfällt.
  Das ist ein Hinweis, kein Beweis, und wird auch so formuliert.
- **Uplink umgesteckt.** Eine LLDP-Nachbarschaft hat sich geändert.

Jeder Eintrag nennt **warum** er auffällt. Eine Liste ohne Begründung wird
nach zwei Wochen nicht mehr gelesen.

---

## 3. Woher die Antworten kommen

Entscheidend ist, **welche Quelle ihre Historie selbst führt**. Was A38 heute
nur als Gegenwart kennt, liefert erst eine Woche nach Einführung des
Änderungsprotokolls aus der [Zeitmaschine](planung-zeitmaschine.md) Ergebnisse.

| Quelle | Historie vorhanden? | Was der Report daraus zieht | Bereit |
|---|---|---|---|
| **FortiAnalyzer** | ja, Logs | FortiGate-Ereignislogs (`type=event`, `subtype=system`): Konfigurationsänderungen mit Admin, Objektpfad, Aktion. Dazu Denies | **sofort** |
| **Zabbix** | ja, `event.get` | Probleme der Woche mit Beginn, Ende und Dauer; Verfügbarkeit; die SLA-Berichte sind für den User bereits freigegeben | **sofort**, Rechte erweitern (Abschnitt 6) |
| **Graylog** | ja, Logs | AD-Ereignisse, iFIX, weitere Streams | nach der Aufteilung (Abschnitt 5) |
| **ARP-Historie** | ja, `first_seen`/`last_seen` | neue und verschwundene MACs und IPs | **sofort** |
| **DNS-Cache** | teilweise, `first_seen` | neue Namen. Einschränkung: Der Cache kennt nur Namen, nach denen gefragt wurde | **sofort**, mit Hinweis |
| **Webdrive-Store** | ja, 7 Tage | Wochenzahlen | **sofort** |
| **iTop** | ja, `CMDBChange`/`CMDBChangeOp` | Änderungen an CIs, Subnetzen und Services mit Bearbeiter | zu prüfen: Lesbarkeit per REST |
| **FortiManager** | nein, der Sync überschreibt | Diff von Policies, Objekten, Routen, Interfaces | erst mit Zeitmaschine Schritt 3 |
| **LibreNMS** | teilweise: Eventlog per API, LLDP nicht | neue Geräte, Port up/down aus `/logs/eventlog`; LLDP-Diff erst mit Zeitmaschine | Eventlog **sofort**, LLDP später |

**Folgerung:** Der Report ist **ohne die Zeitmaschine sinnvoll**. Die
Firewall-Änderungen kommen zuerst aus den FAZ-Ereignislogs. Die sind sogar
besser als ein Diff, weil sie *wer* und *wann* minutengenau enthalten. Das
FMG-Änderungsprotokoll ergänzt sie später um den fachlichen Inhalt („Adresse X:
10.1.2.3 → 10.1.2.4"). Beide Wege laufen also nicht parallel ins Leere, sondern
ergänzen sich: Das Log sagt, wer etwas getan hat, der Diff, was sich dadurch
geändert hat.

---

## 4. Ablauf und Speicherung

```
Freitag 06:30 ──► Sammeln (je Quelle parallel, mit Zeitlimit)
                     │  Fenster: Vorfreitag 06:30 → heute 06:30, lückenlos
                     ▼
                  Auswerten  → report.data (JSON, versioniert)
                     ▼
                  Rendern    → HTML (Web-Ansicht) und PDF (Render-Dienst)
                     ▼
                  Ablegen    → Tabelle weekly_report, optional versenden
```

- **Zeitfenster:** genau die sieben Tage seit dem letzten Lauf, ohne Lücke und
  ohne Überlappung. Ist ein Lauf ausgefallen, holt der nächste ihn nach (zwei
  Berichte), statt ein Doppelfenster zu bilden.
- **Zeitplan:** konfigurierbar, Standard Freitag 06:30 Europe/Berlin. Er läuft
  als weiterer periodischer Task neben Sync, ARP-Sweep und Webdrive-Poller. Es
  gibt **einen** Lauf, auch bei mehreren API-Workern; die Sperre läuft über
  `pg_try_advisory_lock`.
- **Daten zuerst, Darstellung danach.** Gespeichert wird das ausgewertete JSON,
  nicht nur das PDF. Damit lässt sich ein Bericht nach einer Layoutänderung neu
  rendern, und die Vorwochenvergleiche brauchen keine Quellen mehr.
- **Jede Quelle einzeln fehlertolerant.** Antwortet Graylog nicht, entsteht der
  Bericht trotzdem. Das Kapitel trägt dann „Quelle nicht erreichbar", und auf
  der Titelseite steht ein Vermerk.
- **Manuell auslösbar** für einen frei gewählten Zeitraum (Admin). Das ist für
  den ersten Test unverzichtbar und später für „was war in den Ferien?".

```sql
CREATE TABLE weekly_report (
    id           bigserial PRIMARY KEY,
    period_start timestamptz NOT NULL,
    period_end   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    trigger      text        NOT NULL,      -- schedule | manual
    status       text        NOT NULL,      -- ok | partial | failed
    data         jsonb       NOT NULL,      -- ausgewertete Kapitel + Quellenstatus
    pdf          bytea,                     -- gerendert, neu erzeugbar aus data
    UNIQUE (period_start, period_end)
);
```

Aufbewahrung: Standard ein Jahr. Die JSON-Daten sind klein, das PDF wird bei
Bedarf neu gerendert und kann früher entfallen.

---

## 5. Graylog als eigene Quelle

Heute steckt die Graylog-Verbindung in den Webdrive-Einstellungen (`webdrive`:
`base_url`, `token`, `stream_id`, `fac_query`, `oc_query` …). Für den Report
wird Graylog zu einer **eigenen Datenquelle**:

| Neu: Config `graylog` | Bleibt: Config `webdrive` |
|---|---|
| `base_url`, `token`, `ssl_verify`, `timeout_s` | `stream_id`, `fac_query`, `oc_query`, `oc_ip`, `sync_rule`, FAC-Zugang, Poller-Takt |
| **Quellen** mit Rolle: `{label, kind: ad \| ifix \| …, stream, filter}`; Stream standardmäßig *All messages* | nutzt die Verbindung aus `graylog` |

- **Migration ohne Zutun.** Beim Start werden `base_url` und `token` aus
  `webdrive` nach `graylog` übernommen, wenn `graylog` noch leer ist. Webdrive
  läuft danach unverändert weiter.
- **Alles liegt in *All messages*.** AD und iFIX sind dort enthalten. Getrennt
  wird deshalb **per Filter**, nicht per Stream: AD über
  `winlog.channel:Security` und die Domain Controller, iFIX über den
  iFIX-Provider bzw. die iFIX-Knoten. Die Filter sind je Rolle konfigurierbar,
  der Stream bleibt *All messages* (`000000000000000000000001`), sofern niemand
  etwas anderes einträgt.
- **Fallstrick „Remove matches from All messages".** Hat ein Stream diese
  Option gesetzt, fehlen seine Nachrichten in *All messages*, ohne dass es
  auffällt. Der Verbindungstest zählt deshalb je Rolle die Treffer der letzten
  24 Stunden. Null Treffer heißt: Filter, Feldname oder Stream stimmt nicht.
- **Eigener Token, eigener Graylog-User.** Mehr Rechte für den Report sollen
  nicht automatisch der Webdrive-Abfrage zufallen. Empfehlung: ein User
  `a38-report` mit der Rolle *Reader* und Leserecht auf den Stream *All
  messages*. Globale Suchrechte sind nicht nötig, weil jede Abfrage den Stream
  nennt. Diese Regel beachtet der vorhandene Client schon (`DEFAULT_STREAM`).
- **Settings-Panel „Graylog"** unter Datenquellen. Der Verbindungstest zeigt
  die Version, die sichtbaren Streams und je Rolle (AD, iFIX) die Treffer der
  letzten 24 Stunden samt erkannter Feldschreibweise.

### Zählen statt Herunterladen

Eine Woche AD-Logs sind Millionen Zeilen. Der heutige Client nutzt die klassische
Suche, die bei 10.000 Treffern je Abfrage endet. Für den Report wäre das der
falsche Weg. Stattdessen:

- **Aggregationen in Graylog rechnen lassen.** Hier läuft **Graylog 5.0.13**.
  Die einfache Aggregations-API (`/api/search/aggregate`) kam erst mit 5.2. Der
  Weg ist deshalb die **Views-API**, mit der Graylog auch seine eigenen
  Dashboard-Widgets rechnet: `POST /api/views/search/sync` mit einer Query
  (Stream, Zeitraum, Filter) und einem `pivot`-Suchtyp (Gruppierung nach Werten
  und/oder Zeit, Metrik `count`). So entstehen Zählungen nach EventID × Tag,
  Top-Konten und Top-Quellen, ohne eine einzige Rohzeile zu übertragen.
  Gekapselt in einer Funktion `aggregate(stream, query, group_by, interval)`.
  Ein späteres Update auf ≥ 5.2 tauscht nur deren Innenleben.
- **Rohzeilen nur für die wenigen Ereignisse, die genannt werden:** neue
  Konten, Änderungen an privilegierten Gruppen, Sperrungen. Das sind gezielte
  Suchen mit kleiner Trefferzahl.

### AD: welche Ereignisse

Erste Auswahl, konfigurierbar:

| EventID | Bedeutung | im Report |
|---|---|---|
| 4720 / 4726 | Konto angelegt / gelöscht | namentlich |
| 4722 / 4725 | Konto aktiviert / deaktiviert | namentlich |
| 4728, 4732, 4756 / 4729, 4733, 4757 | Mitglied zu Gruppe hinzugefügt / entfernt | namentlich bei privilegierten Gruppen, sonst gezählt |
| 4740 | Konto gesperrt | Top-Konten, Spitzen je Tag |
| 4625 | Fehlanmeldung | gezählt, Spitzen und Top-Quellen |
| 4724 | Kennwort durch Admin zurückgesetzt | gezählt |
| 5136 | Objekt im Verzeichnis geändert (GPO, OU) | bei GPO namentlich |

### Winlogbeat: ein Schema für AD und iFIX

AD und iFIX kommen beide über **Winlogbeat** ins Graylog. Damit gibt es nur
**ein** Feldschema und einen Parser für beide Kapitel. Unterschieden wird
nicht am Format, sondern an Kanal und Absender:

| Feld (Winlogbeat → Graylog-Beats-Input) | AD | iFIX |
|---|---|---|
| `winlog.channel` | `Security` | `Application` (bzw. ein eigener iFIX-Kanal) |
| `winlog.provider_name` | `Microsoft-Windows-Security-Auditing` | der iFIX-Provider (am Probe-Log festzustellen) |
| `winlog.computer_name` | die Domain Controller | die SCADA-, iClient- und Historian-Knoten |
| `winlog.event_id` | siehe Tabelle oben | iFIX-Meldungen; dazu Windows-Ereignisse der Knoten |
| `winlog.event_data.*` | `TargetUserName`, `SubjectUserName`, `TargetSid`, `MemberName`, `IpAddress` … | Meldungstext, Knoten, Tag |

**Ein Stolperstein bei den Feldnamen:** Der Beats-Input in Graylog stellt den
Feldern je nach Einstellung den Beat-Typ voran und ersetzt die Punkte. Aus
`winlog.event_id` wird dann `winlogbeat_winlog_event_id`, aus
`winlog.event_data.TargetUserName` wird
`winlogbeat_winlog_event_data_TargetUserName`. A38 erkennt beim
Verbindungstest an einer Probenachricht je Stream, welche Schreibweise
vorliegt, statt sie fest einzubauen. Die Erkennung lässt sich in den
Einstellungen überschreiben.

**iFIX: was sich ohne Spezialwissen sagen lässt.** Da iFIX hier über das
Windows-Ereignisprotokoll kommt, liefert derselbe Weg auch den **Zustand der
SCADA-Knoten**. Das ist für einen Wochenbericht vermutlich wertvoller als die
einzelnen iFIX-Meldungen:

| EventID / Quelle | Bedeutung | im Report |
|---|---|---|
| 6005 / 6006 / 6008 (`EventLog`) | Start / sauberes Herunterfahren / **unerwarteter Neustart** | je Knoten, 6008 namentlich |
| 7031 / 7034 (`Service Control Manager`) | Dienst unerwartet beendet | bei iFIX-Diensten namentlich |
| 7036 | Dienststatus geändert | gezählt, iFIX-Dienste einzeln |
| 1000 / 1002 (`Application Error` / `Hang`) | Absturz bzw. Hänger einer Anwendung | bei iFIX-Prozessen namentlich |
| iFIX-Provider | Meldungen von iFIX selbst (Alarme, Verbindungsabbrüche zu Knoten) | Zählung je Knoten und Tag; Inhalt nach Probe-Log |

Die Liste der iFIX-Knoten und iFIX-Dienste ist konfigurierbar. Ein erster
Vorschlag dafür kommt aus Graylog selbst: Gelistet werden alle
`computer_name`, die Ereignisse des iFIX-Providers schicken.

---

## 6. Weitere Rechte und Abfragen

**Zabbix:** In die Allow-Liste des API-Users kommen zusätzlich `event.get`
(Problembeginn und -ende in der Woche) und, wenn SLAs gepflegt sind,
`sla.getsli`. Weiterhin nur lesend.

**FortiAnalyzer:** Für die Ereignislogs wird derselbe Logsuche-Weg genutzt wie in
[planung-faz-logs.md](planung-faz-logs.md), nur mit `logtype=event`. Zu prüfen
ist, ob der FAZ-API-User die Event-Logs der ADOMs lesen darf.

**iTop:** Lesen auf `CMDBChangeOp` (und Unterklassen) für den REST-User. Ob das
geht, ist die offene Frage 2 der Zeitmaschine und wird hier zum ersten Mal
gebraucht.

**LibreNMS:** `/api/v0/logs/eventlog` mit Zeitfenster, mit dem vorhandenen
Token.

---

## 7. Darstellung und PDF

### Ein Renderer für beides

PDF und draw.io-Bilder entstehen im selben Werkzeug: einem **headless Chromium**
(Playwright) als eigener kleiner Container im Compose-Stack, intern erreichbar,
ohne Port nach außen.

- Der Bericht ist eine **HTML-Seite** mit Druck-CSS (A4 hoch, Kopf- und
  Fußzeile, Seitenumbrüche je Kapitel). Dieselbe Seite dient der Web-Ansicht.
  Es gibt also nur eine Darstellung, die auch gedruckt stimmt.
- **Diagramme als SVG**, serverseitig erzeugt. Keine Diagrammbibliothek, die
  erst im Browser rechnet, damit das PDF genau zeigt, was die Web-Ansicht zeigt.
  Gebraucht werden wenige Typen: Balken je Tag, Heatmap Tag × Quelle, Kacheln
  mit Trend, horizontale Top-10-Balken.
- **draw.io im Bericht:** Chromium lädt die `viewer-static.min.js` der
  selbst gehosteten draw.io-Instanz, rendert das XML zu SVG und bettet es ein.
  Das ist derselbe Weg wie im Browser des Nutzers und braucht keinen
  zusätzlichen Export-Server. Die `.drawio`-Datei liegt dem Bericht zusätzlich
  bei, zum Weiterbearbeiten.
- Corporate Design über die vorhandenen **Schriftfeld-Einstellungen**
  (Logo, Firma, Zeichnungsnummern-Präfix). Der Bericht erhält eine Nummer
  `A38-WR-2026-43`.

### Wo draw.io hilft und wo nicht

draw.io lohnt nur dort, wo eine **Lage** zu zeigen ist, nicht eine Menge:

- **Kapitel 4 (Verkabelung):** Ausschnitt der Switch-Physik bzw. des
  LLDP-Plans um die geänderten Verbindungen, Änderungen farbig, neu grün,
  entfallen rot gestrichelt. Erst sinnvoll, wenn LLDP-Änderungen protokolliert
  werden.
- **Kapitel 2 (Firewall), später:** die betroffenen Segmente als Vorher und
  Nachher. Das hängt an der Zustandsrekonstruktion der Zeitmaschine (dort
  Schritte 7 und 8).

Für Zahlen, Zeitverläufe und Listen ist ein normales Diagramm besser. In der
ersten Ausbaustufe enthält der Bericht deshalb **kein** draw.io. Das ist eine
Entscheidung und kein Versäumnis.

### Seitenaufbau

1. **Titelseite:** Titel, KW, Zeitraum, die Kacheln aus Kapitel 0, Quellenstatus
   (✓ / teilweise / nicht erreichbar).
2. **Kapitel 1** auf einer Seite.
3. Kapitel 2 bis 10 je ab neuer Seite: oben der Antwortsatz und ein Diagramm,
   darunter die Tabelle. Lange Tabellen werden gekürzt („… und 214 weitere,
   vollständig in A38"), damit der Bericht lesbar bleibt.

---

## 8. Ansicht und Zustellung

- **Network Tools → Wochenreport:** Liste der Berichte (KW, Status, Kurzzahlen),
  Öffnen als Web-Ansicht, PDF herunterladen, `.drawio` herunterladen, „Jetzt
  erzeugen" mit Zeitraum (Admin).
- **Einstellungen → Wochenreport:** Zeitplan, aktive Kapitel, Liste der
  privilegierten AD-Gruppen, Änderungsfenster (für „außerhalb des Fensters"),
  Aufbewahrung, Empfänger.
- **Zustellung**, wenn gewünscht: per Mail als PDF-Anhang (SMTP-Relay, neu)
  oder als Link in einen Teams-Kanal (Webhook). Beides ist optional. Ohne
  Zustellung liegt der Bericht in A38.
- **Rechte:** Der Bericht enthält Kontonamen aus dem AD und Benutzernamen aus
  FortiGate und iTop. Er gehört deshalb hinter eine eigene Berechtigung oder
  die Admin-Rolle, nicht in die normale Leseberechtigung.

---

## 9. Zu klären, bevor gebaut wird

1. ~~Welche Graylog-Version läuft?~~ **5.0.13** → Views-API (`/api/views/search/sync`
   mit Pivot). Zu prüfen ist, ob der Reader-User Views-Suchen ausführen darf.
   Bei Graylog genügt dafür normalerweise das Leserecht auf die Streams.
2. ~~Welche Streams gibt es?~~ **Alles liegt in *All messages***, getrennt
   wird per Filter. Offen ist nur, ob der Beats-Input Präfixe setzt. Das
   erkennt der Verbindungstest.
3. **Welcher Provider schreibt die iFIX-Meldungen**, und welche davon sind
   wichtig (Alarme, Verbindungsabbrüche, Bedieneingriffe)? Den Knotenzustand
   (Neustarts, Dienstabbrüche, Abstürze) liefert das Windows-Ereignisprotokoll
   ohnehin.
4. **Wer ist Stephan, und was ist ihm wichtig?** Wenn er Leitung ist, gehören
   Kapitel 0 und 1 auf eine Seite und der Rest in den Anhang. Wenn er Technik
   ist, umgekehrt.
5. **Gibt es Änderungsfenster?** Ohne sie entfällt „außerhalb des Fensters",
   übrig bleiben Nacht und Wochenende.
6. **Zustellung:** Reicht A38 als Ablage, oder Mail bzw. Teams? Gibt es ein
   SMTP-Relay ohne Authentifizierung im Netz?
7. **Ist `CMDBChangeOp` per REST lesbar?** Kapitel 5 hängt daran.
8. **Darf ein zusätzlicher Container (Chromium) in den Stack?** Er kommt ohne
   Internetzugang aus. Das Image muss aber, wie die anderen, über den Proxy
   gebaut werden.

---

## 10. Reihenfolge

| # | Schritt | Ergebnis |
|---|---|---|
| 1 | Graylog als eigene Quelle, Migration aus `webdrive`, Panel mit Rollen-Filtern und Treffertest | Grundlage; Webdrive läuft unverändert |
| 2 | Gerüst: `weekly_report`, Scheduler mit Advisory-Lock, manueller Lauf, Quellenstatus | ein leerer Bericht, der pünktlich entsteht |
| 3 | Kapitel aus Quellen mit eigener Historie: Zabbix, ARP/DNS, FAZ-Ereignislogs, Webdrive, LibreNMS-Eventlog | **erster brauchbarer Bericht ohne Wartezeit** |
| 4 | HTML-Ansicht mit SVG-Diagrammen in A38 | lesbar im Browser |
| 5 | Render-Container, PDF-Export | exportierbar |
| 6 | AD-Kapitel über Graylog-Aggregationen | nach Klärung von Fragen 1 und 2 |
| 7 | Kapitel 1 „Was sollte sich jemand ansehen?" (Querabgleich) | der eigentliche Mehrwert |
| 8 | Scheduler aktiv, optional Mail oder Teams | läuft von selbst |
| 9 | iTop-Änderungslog | nach Klärung von Frage 7 |
| 10 | FMG-Diff aus der Zeitmaschine im Firewall-Kapitel | fachlicher Inhalt der Änderungen |
| 11 | draw.io-Ausschnitte (Verkabelung, dann Vorher und Nachher) | die Lage, nicht nur die Menge |
| 12 | iFIX-Kapitel: Knotenzustand sofort mit Schritt 6 (gleicher Winlogbeat-Parser), iFIX-Meldungen nach Klärung von Frage 3 | OT im selben Bericht |

Schritt 3 kommt vor dem PDF: Was der Bericht aussagt, ist wichtiger als wie er
gedruckt aussieht. Kapitel 7 steht hinter den Einzelkapiteln, weil es aus ihnen
abgeleitet wird und erst dann Fehlalarme sichtbar werden.
