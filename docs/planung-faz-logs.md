# FortiAnalyzer-Logs: „Gestern ging es noch" und „Was wird geblockt?"

Planung für die beiden ersten Auswertungen der FAZ-Traffic-Logs im Pfad-Tracker.

**Stand:** 20.10.2026 · erste Ausbaustufe umgesetzt (`5b7e777`), gegen einen
echten FortiAnalyzer noch nicht geprüft
**Betrifft:** `api/src/faz/client.py`, `api/src/faz/logs.py`,
`api/src/routers/faz_insight.py`, `frontend/src/components/faz/`,
Tracker-Gruppe „Ist-Zustand (FortiAnalyzer)"

---

## 1. Warum

A38 beantwortet heute, was die Regeln **erlauben sollten**: Die Pfad-Engine
rechnet aus dem FortiManager-Cache, welche Policy auf welchem Hop greift. Die
Live-Session-Prüfung zeigt dazu, was **in diesem Moment** auf der FortiGate
offen ist.

Beim Helpdesk landen aber zwei andere Fragen:

1. **„Gestern ging es noch."** Nicht gefragt ist, ob der Flow heute erlaubt
   ist, sondern was sich seitdem geändert hat und wann. Die Antwort steht
   nur in der Vergangenheit, und die kennt nur der FAZ.
2. **„Die Anwendung geht nicht."** Gemeldet werden weder Ziel noch Port, nur
   ein Host und ein Symptom. Heute rät man den Port, trackt und rät weiter.
   Der FAZ weiß, was die Firewalls bei diesem Host verworfen haben.

Beide Fragen brauchen dasselbe Werkzeug: eine Logsuche über ein Zeitfenster
und eine Auswertung, die aus Logzeilen eine Aussage macht. Beide Ansichten
führen zurück in den Pfad-Tracker, wo der Regelvorschlag schon gebaut wird.

---

## 2. Die Logsuche

### 2.1 Ablauf

Die Logsuche des FAZ läuft asynchron in vier Schritten. Umgesetzt in
`faz.client.logsearch()`:

```
add    /logview/adom/{adom}/logsearch            → tid
get    /logview/adom/{adom}/logsearch/{tid}       (offset 0, limit 1)
       … wiederholen, bis percentage = 100 oder search_timeout_s erreicht
get    /logview/adom/{adom}/logsearch/{tid}       (offset n, limit 1000) je Seite
delete /logview/adom/{adom}/logsearch/{tid}       immer, auch bei Fehlern
```

Parameter beim Anlegen:

| Parameter | Wert |
|---|---|
| `apiver` | `3` |
| `logtype` | `traffic` |
| `device` | `[{"devid": "All_FortiGate"}]` |
| `time-range` | `{"start": …, "end": …}` als `YYYY-MM-DD HH:MM:SS` in der **Zeitzone des FAZ** |
| `time-order` | `desc` |
| `filter` | siehe 2.2 |

Die Dokumentation zeigt zwei Antwortformen (`percentage` gegenüber
`percentage-done`, `data` als Liste gegenüber `data.logs`, `total-count`
gegenüber `total_lines`). Der Client liest beide.

### 2.2 Filter

| Zweck | Filter |
|---|---|
| Flow-Historie | `srcip==A and dstip==B [and proto==6] [and dstport==443]` |
| Denies als Quelle | `srcip==A and action==deny` |
| Denies als Ziel | `dstip==A and action==deny` |
| Beide Richtungen | zwei Suchen, Ergebnisse zusammengeführt |

IPs werden vor dem Einsetzen mit `ipaddress` geprüft. Ein Name wird über die
vorhandene Auflösung (`resolve_query`) zur IP. In den Filter gelangt nie
freier Text.

### 2.3 Last auf dem FAZ begrenzen

Eine Logsuche ist für den FAZ teuer. Darum:

- **Limits:** höchstens 1000 Zeilen je Abruf und 5000 je Suche
  (`LOG_PAGE`, `LOG_LIMIT`). Für eine Aussage reicht das, denn sortiert wird
  absteigend, die jüngsten Zeilen kommen also zuerst.
- **Zeitfenster:** Flow-Historie bis 31 Tage, Denies bis 7 Tage.
- **Zeitgrenze:** `search_timeout_s` (Standard 45 s, einstellbar). Danach wird
  das bis dahin Gefundene ausgewertet, und das Ergebnis trägt
  `complete: false`.
- **Cache:** 60 s je identischer Suche, aber nur für vollständige Ergebnisse.
  Doppelklicks und das Hin- und Herspringen zwischen den Ansichten erzeugen
  keine zweite Suche.
- **Aufräumen:** `delete` läuft im `finally`, damit keine Suche auf dem FAZ
  liegen bleibt.

Ist eine Suche unvollständig oder hat sie das Limit erreicht, sagt die
Oberfläche das ausdrücklich (`SearchNotes`). Fehlende Logs dürfen nicht
aussehen wie fehlender Verkehr.

---

## 3. „Gestern ging es noch"

### 3.1 Eingabe

Quelle, Ziel, Protokoll, Port (leer heißt alle Ports) und ein Zeitfenster
von 6 Stunden bis 30 Tagen. Der Einstieg geht auch direkt aus einem
Tracker-Ergebnis (Verlaufssymbol) und aus jeder Zeile von „Was wird
geblockt?".

### 3.2 Klassifizierung je Logzeile

| `action` | Ergebnis |
|---|---|
| accept, close, timeout, server-rst, client-rst, start, ip-conn, … | erlaubt |
| deny, blocked, block, reject, drop | geblockt |
| sonst | anderes (wird mitgezählt, entscheidet nichts) |

`utmaction` mit Block zählt als geblockt. Das ist dann kein Regelproblem,
sondern ein Sicherheitsprofil, und die Tabelle zeigt es an der Aktion.

### 3.3 Die Aussage

Aus der zeitlich sortierten Folge erlaubt/geblockt ergibt sich genau eine
Aussage:

| Aussage | Bedingung | Was sie bedeutet |
|---|---|---|
| **Seit X geblockt** | erst erlaubt, jüngste Zeilen geblockt | Hier hat sich etwas geändert. X ist der erste Deny nach dem letzten Allow. |
| **Durchgehend geblockt** | nur Denies | Es ging im Fenster nie. Das „gestern" stimmt nicht oder liegt weiter zurück. |
| **Seit X kein Verkehr** | nur Allows, letzter liegt > 1 h zurück | Die Firewall hat nichts verweigert, der Verkehr kommt nur nicht mehr an. Eher Routing, Quelle oder Ziel als eine Regel. |
| **Wieder erlaubt** | Denies, jüngste Zeilen erlaubt | Problem ist behoben, oder es lag zwischendurch etwas anderes an. |
| **Durchgehend erlaubt** | nur Allows, auch zuletzt | Laut Firewall ist alles in Ordnung. |
| **Kein Verkehr** | keine Zeilen | Nie gesehen, oder es wird nicht geloggt (siehe 6). |

Dazu kommen der **Blocker** (Firewall, VDOM, Regel des jüngsten Deny),
letzter Allow, letzter Deny, eine **Zeitleiste** (15-min-, Stunden- oder
Tagesbalken je nach Fenster) und eine Tabelle **je Firewall, VDOM, Regel und
Ergebnis** mit Anzahl, erstem und letztem Auftreten und Interfaces.

Regelnamen kommen aus dem FortiManager-Cache. Policy 0 heißt „Impliziter
Deny". IDs ab 2^30 sind FortiOS-intern und werden ohne FMG-Abgleich angezeigt.

### 3.4 Noch nicht umgesetzt: Abgleich gegen den Pfad

Die erste Idee enthielt einen Vergleich **je Hop**: Die Pfad-Engine sagt
„Hop 2 erlaubt per Regel 47", der FAZ sieht den Flow aber über Regel 12 oder
auf einer Firewall, die gar nicht im berechneten Pfad liegt. Das wäre der
stärkste Hinweis auf asymmetrisches Routing, NAT oder einen Fehler in der
Pfad-Engine.

Vorgehen:

1. Der Tracker gibt beim Sprung in die Historie die berechneten Hops mit
   (`device`, `vdom`, `policyid`).
2. Die Hop-Tabelle der Historie bekommt eine Spalte „laut Pfad":
   - ✓ gleiche Firewall und Regel,
   - ≠ gleiche Firewall, andere Regel,
   - „nicht im Pfad" für eine Firewall, die die Engine nicht vorhersagt,
   - umgekehrt eine Zeile „im Pfad, aber nicht im Log" für vorhergesagte
     Hops ohne einen einzigen Logeintrag.
3. „Nicht im Log" ist nur ein Befund, wenn die Regel loggt (siehe 6).

Das ist reines Frontend plus eine Funktion in `faz/logs.py`, also ohne neue
FAZ-Abfrage.

---

## 4. „Was wird geblockt?"

### 4.1 Eingabe

Eine IP oder ein Name, die Richtung (als Quelle, als Ziel, beides) und ein
Zeitfenster von 15 Minuten bis 7 Tagen.

### 4.2 Ergebnis

Die Denies werden gruppiert nach **Gegenstelle, Protokoll, Port, Firewall,
VDOM und Regel**. Sortiert wird nach Anzahl, bei Gleichstand nach dem
jüngsten Auftreten. Je Zeile:

- **Richtung** (ausgehend oder eingehend),
- **Gegenstelle** mit Namen aus iTop, sonst FortiManager-Adressobjekt, sonst
  DNS (höchstens 256 Rückwärtsauflösungen je Anfrage),
- **Port und Dienst**, wie der FAZ ihn benennt,
- **Firewall/VDOM** mit Interfaces als Tooltip,
- **Regel**, wobei der implizite Deny hervorgehoben ist,
- **Anzahl** und **zuletzt**,
- **Sprung in den Pfad-Tracker** (mit dem Regelvorschlag dort) und **Sprung
  in „Gestern ging es noch"** für genau diesen Flow.

Ein Hinweis über der Tabelle sagt, wie viele Denies vom impliziten Deny
kommen. Das sind die Fälle, in denen schlicht eine Regel fehlt, im
Unterschied zu einer Regel, die ausdrücklich verweigert.

Die Liste bleibt beim Hin- und Herspringen erhalten, weil beide Ansichten
gemountet bleiben.

### 4.3 Noch nicht umgesetzt: User als Einstieg

Der UEBA-Teil des FAZ kennt zu einem Endpoint den angemeldeten User. Das
Feld nähme dann auch einen Usernamen an:

```
User → FAZ-Endpoints (UEBA) → IP(s) → Denies
```

Hat ein User mehrere Endpoints, wird je IP gesucht und die Richtung im
Ergebnis um die IP ergänzt. Die Endpoint-Liste liegt schon im Speicher
(`state.faz.endpoints`), es braucht also keine zusätzliche Abfrage. Das Feld
ist zugleich der Einstieg für Idee 7 (User → Switchport).

---

## 5. Einstellungen

Unter Einstellungen → FortiAnalyzer, beide schon umgesetzt:

| Feld | Standard | Wofür |
|---|---|---|
| Zeitzone | `Europe/Berlin` | `time-range` ist Ortszeit des FAZ, Logzeiten ohne `eventtime` ebenfalls |
| Zeitgrenze Logsuche | 45 s | danach wird das Teilergebnis ausgewertet |

`tzdata` steht in `requirements.txt`, weil das schlanke Image keine
Zeitzonendaten mitbringt.

---

## 6. Die größte Fehlerquelle: nicht geloggter Verkehr

Beide Ansichten sehen nur, was die FortiGate auch loggt:

- Eine Allow-Regel mit `logtraffic disable` erzeugt keine Zeilen. Die
  Historie meldet dann „kein Verkehr", obwohl alles läuft.
- Eine Deny-Regel ohne Logging und der implizite Deny ohne „log violation
  traffic" fehlen in „Was wird geblockt?" ganz. Die Liste ist dann leer,
  obwohl geblockt wird.

Heute steht das nur als allgemeiner Hinweis unter dem Ergebnis. Besser:

1. **Logging in den Cache aufnehmen.** `_normalize_policy` in
   `api/src/inventory/store.py` übernimmt `logtraffic` bisher nicht. Das Feld
   kommt in die normalisierte Policy (`all`, `utm`, `disable`), dazu je VDOM
   der Schalter für den impliziten Deny (`set fwpolicy-implicit-log` bzw.
   `log violation traffic`, Pfad im FMG zu prüfen).
2. **In der Historie:** Hat die vom Tracker berechnete Regel kein Logging,
   ersetzt ein deutlicher Hinweis die Aussage „kein Verkehr": „Regel 47 loggt
   nicht, der FAZ kann diesen Flow nicht sehen."
3. **In „Was wird geblockt?":** Loggt der implizite Deny auf einem VDOM im
   Pfad nicht, steht das über der Tabelle. Eine leere Liste ist dann kein
   Beleg.
4. **`logtraffic utm`** loggt nur Sitzungen mit Sicherheitsereignis. Das ist
   für die Historie fast so schlecht wie gar kein Logging und bekommt
   denselben Hinweis.

---

## 7. Prüfung am echten FortiAnalyzer

Lokal ist kein FAZ eingetragen. Getestet ist alles gegen Attrappen, mit
381 Unit-Tests, und im Demo-Modus. Vor dem ersten Einsatz in dieser
Reihenfolge prüfen:

1. **Rechte:** Das Admin-Profil des API-Benutzers braucht Lesezugriff auf
   **Log View**. Ohne ihn liefert `add` einen Berechtigungsfehler (A38 zeigt
   502 mit der FAZ-Meldung).
2. **Suche anlegen:** Eine Flow-Historie für einen bekannten, laufenden Flow
   über 6 h. Wird der Filter abgelehnt, ist die Schreibweise `==` der erste
   Verdacht. Die Alternative ist `srcip=A and dstip=B` bzw. die Form mit
   Klammern aus der Log-View-Suchleiste.
3. **Antwortform:** Kommen `percentage` und die Zeilen dort an, wo der
   Client sie sucht? Der Client loggt die rohe Antwort bisher nicht. Für
   diesen Test kommt ein `log.debug` der ersten `get`-Antwort dazu, oder man
   ruft die Suche einmal von Hand per `curl` auf.
4. **Deny-Aktionen:** Der Deny-Filter sucht nur `action==deny`. Prüfen, ob
   der FAZ verworfene Sitzungen auch als `blocked` oder `drop` führt. Falls
   ja, wird der Filter zu `(action==deny or action==blocked …)`.
5. **Zeitzone:** Liegt der jüngste Logeintrag eine oder zwei Stunden daneben,
   stimmt die Zeitzone nicht. `eventtime` ist UTC, `date`+`time` ist FAZ-Zeit.
6. **Gerätenamen:** Stimmen `devname` und `vd` mit den Namen im
   FMG-Cache überein? Sonst fehlen die Regelnamen.
7. **Last:** Eine Suche über 7 Tage auf einen viel genutzten Server. Wie lange
   dauert sie, und erreicht sie die Zeitgrenze? Danach `LOG_LIMIT` und die
   Fenster anpassen.
8. **Aufbewahrung:** Wie weit reichen die Logs zurück? Danach das größte
   Fenster der Historie festlegen (heute 30 Tage).

Die Ergebnisse gehören in diesen Abschnitt, damit die nächste Ausbaustufe
(Regelpflege, Idee 3) auf geprüften Annahmen aufsetzt.

---

## 8. Reihenfolge

| Schritt | Inhalt | Status |
|---|---|---|
| 1 | Log-Client mit Polling, Limits, Cache, Aufräumen | umgesetzt |
| 2 | Flow-Historie mit Aussage, Zeitleiste, Hop-Tabelle | umgesetzt |
| 3 | Denies je Host, gruppiert, mit Sprung in Tracker und Historie | umgesetzt |
| 4 | Prüfung am echten FAZ (Abschnitt 7) | offen, **als Nächstes** |
| 5 | `logtraffic` in den FMG-Cache, Hinweise bei nicht loggenden Regeln | offen |
| 6 | Abgleich Historie gegen den berechneten Pfad (3.4) | offen |
| 7 | User als Einstieg in „Was wird geblockt?" (4.3) | offen |

Schritt 5 kommt vor 6, weil der Pfad-Abgleich ohne Logging-Information
falsche Befunde („im Pfad, aber nicht im Log") liefern würde.

---

## 9. Zu klären

- **FortiView statt Rohlogs?** Für „Was wird geblockt?" über 7 Tage wären
  die vorverdichteten FortiView-Auswertungen günstiger als 5000 Rohzeilen.
  Hängt davon ab, ob sie nach Quell-IP filterbar sind und Policy-IDs
  mitliefern.
- **Mehrere ADOMs:** Heute wird nur die eingestellte ADOM durchsucht. Reicht
  das, oder liegen Firewalls im Pfad in anderen ADOMs?
- **Wer darf suchen?** Die Logsuche zeigt Verkehrsdaten aller Hosts. Sollen
  beide Ansichten auf eine Rolle beschränkt werden?
