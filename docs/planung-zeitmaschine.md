# Zeitmaschine

Planung für den Vergleich eines beliebigen Stichtags mit dem heutigen Stand.

**Stand:** 21.09.2026 · Entwurf, noch nichts umgesetzt
**Betrifft:** Postgres-Schema, Sync-Wege (`api/src/inventory/sync.py`,
`api/src/locate/arp_sweep.py`), neue Ansicht im Frontend

---

## 1. Was die Frage eigentlich ist

„Was hat sich seit dem 3. Februar geändert?" ist im Betrieb eine der teuersten
Fragen überhaupt. Heute beantwortet man sie, indem man sich erinnert, Kollegen
fragt und im FortiManager durch Revisionen klickt. Das Ergebnis ist unvollständig
und nicht belegbar.

Dabei sieht A38 fast alles, was für die Antwort nötig wäre — es wirft es nur
weg. Der FortiManager-Sync löscht bei jedem Lauf die alten Zeilen und schreibt
die neuen:

```sql
DELETE FROM fmg_snapshot WHERE adom = $1 AND kind = $2;
INSERT INTO fmg_snapshot (adom, kind, key, data, synced_at) VALUES (...);
```

Das ist für einen Cache richtig. Für eine Zeitmaschine ist es genau der
Verlust, um den es geht.

---

## 2. Was A38 heute schon weiß

Zwei Tabellen sind bereits Zeitmaschinen, ohne dass sie so heißen:

| Tabelle | Historie | Deckt ab |
|---|---|---|
| `arp_history` | `first_seen` / `last_seen` je (IP, MAC) | Wann tauchte eine MAC zuerst auf, wann verschwand sie, welche IP hatte sie |
| `dns_cache` | `first_seen`, `checked_at` | Wann wurde ein Name zum ersten Mal gesehen |
| `traces` | `created_at`, volle Anfrage und Antwort | Was wurde wann geprüft und mit welchem Ergebnis |

Das ist mehr, als es klingt: „neue, bisher unbekannte MAC-Adressen" und „neue
Hostnamen" — zwei der genannten Wünsche — sind damit **heute schon
beantwortbar**. Es fehlt nur die Abfrage und die Ansicht, nicht die Daten.

Alles andere kennt A38 ausschließlich als Gegenwart:

| Quelle | Tabelle | Historie |
|---|---|---|
| FortiManager (Geräte, Policies, Adressobjekte, Zonen, Interfaces, Routen) | `fmg_snapshot` | keine — wird je Sync ersetzt |
| iTop (CIs, Subnetze, Services) | keine, nur TTL-Cache im Speicher | keine |
| LibreNMS (Ports, FDB, LLDP, VLANs) | keine, nur TTL-Cache im Speicher | keine |

---

## 3. Der Kern: Änderungen speichern, nicht Zustände

Die Sorge, die Datenbank werde zu groß, ist berechtigt — aber sie trifft nur
den naheliegenden Weg. Wer **jede Woche den ganzen Bestand** ablegt, zahlt für
alles, was sich nicht geändert hat, und das ist der weitaus größte Teil. Eine
Firewall-Konfiguration ist über Wochen fast identisch mit sich selbst.

Wer stattdessen **nur Änderungen** schreibt, zahlt für das, was tatsächlich
passiert ist:

> Je Objekt einen Inhalts-Hash bilden. Ist er gleich dem zuletzt gespeicherten,
> passiert nichts. Ist er anders, wird eine Zeile geschrieben.

Das dreht die Rechnung um. Der Platzbedarf hängt nicht mehr an der Zahl der
Objekte mal der Zahl der Stichtage, sondern nur an der Zahl der tatsächlichen
Änderungen:

```
Wöchentlicher Vollstand:  Objekte × Wochen × Zeilengröße
Änderungsprotokoll:       Änderungen × Zeilengröße
```

Bei einem Bestand, der sich pro Woche um wenige Promille ändert, unterscheiden
sich die beiden Größen um Zehnerpotenzen.

**Damit ist auch die Frage nach der Wochenschärfe entschieden — und zwar
andersherum, als man erwartet.** Tagesgenau ist im Änderungsprotokoll nicht
teurer als wochengenau; der Takt bestimmt nur, wie fein die Zeitangabe ist,
nicht wie viel gespeichert wird. Der Sync läuft ohnehin täglich. Es gibt keinen
Grund, künstlich zu vergröbern.

**Vorher messen, nicht schätzen.** Die Zahlen oben sind eine Struktur, keine
Vorhersage. Der erste Schritt der Umsetzung ist, eine Woche lang mitzuschreiben,
wie viele Objekte sich tatsächlich je Sync ändern. Erst diese Zahl sagt, ob die
Aufbewahrung ein Jahr oder fünf Jahre beträgt.

---

## 4. Datenmodell

Eine Tabelle für alle Quellen. Ein Eintrag ist ein **Ereignis**, kein Zustand:

```sql
CREATE TABLE change_log (
    id         bigserial PRIMARY KEY,
    source     text        NOT NULL,   -- fmg | itop | librenms | dns
    scope      text,                   -- ADOM, Standort, Gerät — je Quelle
    kind       text        NOT NULL,   -- address | policy | route | subnet | vlan | ci | ...
    key        text        NOT NULL,   -- Identität des Objekts innerhalb kind
    op         text        NOT NULL,   -- created | changed | deleted
    hash       text        NOT NULL,   -- Inhalts-Hash NACH der Änderung
    before     jsonb,                  -- nur bei changed/deleted
    after      jsonb,                  -- nur bei created/changed
    seen_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX change_log_time_idx  ON change_log (seen_at DESC);
CREATE INDEX change_log_ident_idx ON change_log (source, kind, key, seen_at DESC);
```

Dazu eine schmale Begleittabelle mit dem **zuletzt gesehenen Hash** je Objekt,
damit der Vergleich ohne Rückgriff auf das Protokoll auskommt. Sie ist im
Grunde `fmg_snapshot` um eine Hash-Spalte erweitert und könnte darin aufgehen.

### Wie viel `before`/`after`?

Ohne die beiden Spalten ist die Tabelle winzig, aber die Antwort lautet nur
„hat sich geändert" — für ein Adressobjekt zu wenig. Die Frage lässt sich
allerdings nicht am Datenmodell entscheiden, sondern nur an der Ansicht: Die
Vorher-Nachher-Zeichnung (Abschnitt 7) braucht den **Zustand** am Stichtag,
nicht nur die Änderungen. Aus einem reinen Änderungsprotokoll lässt er sich nur
rückwärts rekonstruieren — von heute aus zurückgespielt. Das geht, verlangt aber
je Änderung genug Inhalt, um sie umzukehren.

Deshalb unterschiedlich je Objektart:

| Objektart | Was gespeichert wird | Warum |
|---|---|---|
| Interface, Route, Subnetz, VLAN, Zone | vollständig vorher **und** nachher | trägt die Zeichnung; wenige Objekte, seltene Änderungen |
| Adressobjekt, Gruppe, Service, VIP | nur die geänderten Felder | taucht in keiner Zeichnung auf |
| Policy | nur die geänderten Felder | großes Objekt, hohe Änderungsrate |
| CI, Host, MAC, DNS-Name | nur die geänderten Felder | Liste, keine Zeichnung |

Die erste Zeile ist die teure und zugleich die billige: Sie trägt die
Rekonstruktion, und es sind genau die Objekte, von denen es wenige gibt und die
sich selten ändern. Rohfelder der Quellen — Zeitstempel, interne IDs,
Zähler — werden vorher entfernt, sonst besteht das Protokoll aus
Nicht-Änderungen (siehe Fallstrick 3).

---

## 5. Je Quelle

### 5.1 FortiManager

Die reichste Quelle, und die mit der geringsten Änderung am Code: Der Sync
schreibt bereits alle Objektarten nach `fmg_snapshot`. Aus dem
Löschen-und-Neuschreiben wird ein Abgleich.

Antwortbar wird damit: neue und gelöschte **Adressobjekte, Gruppen, Services,
VIPs, Zonen**, geänderte **Policies** (auch die Reihenfolge — die bleibt beim
Sync erhalten), neue und entfallene **Interfaces**, geänderte **statische
Routen**, neue und gelöschte **VDOMs und Geräte**.

**Ein Fallstrick, der das ganze Feature entscheidet:** Ist der FortiManager
nicht erreichbar oder antwortet ein ADOM leer, darf daraus niemals „alles
gelöscht" werden. Genau das würde der naive Abgleich melden — und zwar
überzeugend, mit tausenden Einträgen. Regel: **Ein Sync, der für eine Objektart
nichts liefert, schreibt keine Löschungen.** Nur ein Lauf, der die Art
erfolgreich und nicht leer gelesen hat, darf Abwesenheit als Löschung deuten.
Diese Regel gehört in den Code, bevor die erste Zeile Protokoll geschrieben
wird. (Dass eine abgestützte FMG-Verbindung real vorkommt, ist in diesem Projekt
belegt.)

### 5.2 iTop

Hier führt der beste Weg nicht über Backups. **iTop protokolliert jede Änderung
selbst** — in `CMDBChange` und `CMDBChangeOp` stehen Zeitpunkt, Benutzer,
geändertes Attribut sowie alter und neuer Wert. Das ist fachlich genauer als
alles, was ein Vergleich zweier Stände liefern könnte, und es reicht weiter
zurück als der Tag, an dem A38 eingeschaltet wird.

**Zu prüfen:** ob `CMDBChangeOp` über `core/get` in der REST-Schnittstelle
erreichbar ist und ob die Aufbewahrung in der iTop-Instanz lang genug
eingestellt ist. Beides ist nicht selbstverständlich.

Geht es, ist iTop mit Abstand die billigste Quelle: A38 liest das Protokoll und
zeigt es an, ohne selbst etwas zu speichern. Geht es nicht, fällt iTop auf
denselben Hash-Abgleich zurück wie der FortiManager, mit den heute schon
gelesenen Objekten (CIs, Subnetze, Adressen) plus den geplanten Services aus
[der Service-Planung](planung-services-und-conduits.md).

**Periodische iTop-Backups als Vergleichsgrundlage wären der schlechteste der
drei Wege:** Ein Backup ist ein Datenbankabzug, kein Fachmodell. Ihn zu
vergleichen hieße, iTops internes Schema nachzubauen — viel Aufwand für ein
Ergebnis, das beide anderen Wege besser liefern. Backups bleiben, wofür sie da
sind.

### 5.3 LibreNMS

Antwortbar: neue und verschwundene **Geräte**, neue **VLANs** und entfallene,
geänderte **Portbeschreibungen**, veränderte **LLDP-Nachbarschaften** — also
umgestöpselte Uplinks.

**„Hosts an geänderten Netzwerkports"** ist der interessanteste und heikelste
Punkt der ganzen Liste. Die FDB ist naturgemäß flüchtig: Ein Notebook wechselt
täglich den Port, und jeder Wechsel wäre ein Ereignis. Das erzeugt Rauschen, in
dem die eine Änderung untergeht, die zählt.

Vorschlag: FDB-Wechsel **nicht** ins allgemeine Protokoll, sondern als eigene,
kürzer aufbewahrte Reihe, und in der Ansicht standardmäßig ausgeblendet. Wer
gezielt fragt „wo hing `10.133.165.42` im Februar", bekommt die Antwort; wer
nach Änderungen am Netz fragt, wird nicht damit zugeschüttet. Dieselbe
Unterscheidung wie zwischen Konfiguration und Verkehr.

### 5.4 DNS und ARP

Bereits vorhanden (Abschnitt 2). Zu tun ist nur die Abfrage:

- Namen, deren `first_seen` nach dem Stichtag liegt → neu im DNS.
- MAC-Adressen mit `first_seen` nach dem Stichtag → bisher unbekannt.
- Bindungen, deren `last_seen` vor dem Stichtag endet → seitdem verschwunden.

**Eine Einschränkung, die man kennen muss:** Der DNS-Cache sieht nur, was
abgefragt wurde. Ein Name, nach dem nie jemand gefragt hat, ist nicht „neu",
wenn er zum ersten Mal auftaucht — er war nur nie gesucht. Das gehört als
Hinweis an die Ausgabe, sonst führt die Zeitmaschine an dieser Stelle in die
Irre.

---

## 6. Fremde Versionierung

### FortiManager-Revisionen

Der FortiManager führt ADOM-Revisionen, und der Gedanke, sie zu nutzen, liegt
nahe. Die Grenzen:

- Die Aufbewahrung ist **am FortiManager** eingestellt und meist knapp. Für „vor
  zwei Jahren" trägt sie nicht.
- Eine Revision ist ein **Konfigurationsabzug**, kein Fachmodell. Ein Diff
  daraus ist ein Textdiff, kein „Adressobjekt X wurde gelöscht".
- Der Abgleich zweier Revisionen ist teuer und bei jeder Abfrage neu fällig.

**Vorschlag:** Revisionen nicht als Vergleichsgrundlage, sondern als **Beleg**.
Zu jedem Zeitpunkt im Protokoll notiert A38, welche Revision damals galt. Wer
den Befund prüfen will, hat den Verweis. Das kostet fast nichts und beantwortet
die Frage nach der Belegbarkeit, ohne die Zeitmaschine von der Aufbewahrung des
FortiManagers abhängig zu machen.

### Das grundsätzliche Argument

Fremde Versionierung ist immer *deren* Modell. Jeder Versuch, daraus A38s
Modell zu rekonstruieren, ist eine Übersetzung, die bei jeder Version des
fremden Systems neu brechen kann. Das eigene Änderungsprotokoll ist ein paar
Tage Arbeit und danach stabil. **Ausnahme ist iTop**, weil dessen Änderungslog
bereits ein Fachmodell ist und keine Übersetzung braucht.

---

## 7. Die Ansicht

Ein Punkt in den Network Tools, neben Verlauf und Checks.

**Eingabe:** ein Datum. Optional ein zweites, sonst gilt „bis heute". Dazu
Filter auf Quelle, Standort/ADOM und Objektart.

Die Ausgabe ist **keine Tabelle**. Eine Tabelle beantwortet „was steht drin",
aber die Frage lautet „ist da etwas, das mich beunruhigen sollte" — und das ist
eine Frage nach Form und Häufung, nicht nach Zeilen. Deshalb drei Ebenen von
grob nach fein.

### 7.1 Der Zeitstrahl: wann ist etwas passiert

Oben eine Leiste vom Stichtag bis heute, eine Spur je Quelle, jede Änderung ein
Strich. Wichtig ist nicht die einzelne Marke, sondern das **Muster**: Änderungen
treten in Bündeln auf, weil an einem Wartungsfenster gearbeitet wurde. Ein
Bündel, das niemand zuordnen kann, ist der eigentliche Befund — und der fällt
in einer nach Zeit sortierten Liste nicht auf, in einer Leiste sofort.

Der Zeitstrahl ist zugleich die Navigation: ein Bündel anklicken grenzt den
Zeitraum darauf ein.

Ein Kalenderraster (Tage als Kacheln, Intensität nach Anzahl) tut es auch und
ist billiger zu bauen, sagt aber nur *wann* und nicht *was*. Als schmale Leiste
über dem Detail ist es eine brauchbare erste Fassung.

### 7.2 Die Zeichnung als Vorher und Nachher

Das ist der Teil, den nur A38 kann, weil der Renderer bereits steht: Statt einer
Liste bekommt man den Netzplan **am Stichtag** und den von **heute**, und die
Differenz ist eingefärbt.

Die Farbsprache ist schon eingeführt und muss nicht neu gelernt werden:

| Änderung | Darstellung | entspricht heute |
|---|---|---|
| neu hinzugekommen | grün, kräftiger Rahmen | das normale Netz |
| entfallen | grau, gestrichelt, schraffiert | das abgeschaltete Interface |
| geändert | bernstein | das Netz ohne Link |
| unverändert | blass zurückgenommen | — |

Das Ergebnis ist eine draw.io-Datei mit Schriftfeld, also **druckbar**. Damit
fällt der Change-Nachweis als Nebenprodukt ab: Ein Auditor bekommt ein Blatt,
kein Bildschirmfoto. Eine interaktive Grafik leistet das nie.

Voraussetzung ist die Rekonstruktion des Zustands am Stichtag — genau dafür
speichert Abschnitt 4 bei Interfaces, Routen, Subnetzen, VLANs und Zonen den
vollständigen Inhalt vorher und nachher.

Als Ausbaustufe dieselbe Zeichnung an mehreren Zeitpunkten nebeneinander, klein.
Dann sieht man nicht nur, *dass* ein Standort gewachsen ist, sondern in welchen
Schritten.

### 7.3 Karten statt Zeilen im Detail

Ein geändertes Adressobjekt oder eine geänderte Policy hat Struktur. Eine Karte
je Änderung mit altem und neuem Wert nebeneinander und **nur den betroffenen
Feldern** liest sich deutlich besser als eine Tabellenzeile mit zwei
JSON-Spalten. Gruppiert wird nach Änderungsfenster, nicht nach Objektart: Was
zusammen passiert ist, gehört zusammen gelesen.

### 7.4 Was diese Ansichten ruiniert, wenn man es nicht vorher bedenkt

- **Masse ist nicht Bedeutung.** Ein einziger Policy-Push erzeugt hunderte
  Einträge und begräbt die eine geänderte Route, auf die es ankommt. Sortiert
  und gewichtet wird nach fachlichem Gewicht, nicht nach Anzahl: Route, Subnetz,
  VLAN und Interface wiegen schwerer als ein umbenanntes Adressobjekt. Im
  Zeitstrahl bestimmt das die Höhe der Marke, in den Karten die Reihenfolge.
- **Die FDB-Wechsel bleiben draußen.** Sonst besteht jedes Bündel aus Notebooks,
  die den Port gewechselt haben (siehe 5.3).
- **Farbe hat hier schon eine Bedeutung.** Grün, Grau und Bernstein sind in den
  Zeichnungen belegt. Die Delta-Farben müssen dazu passen, sonst heißt Grau in
  zwei Zeichnungen zweierlei.

### 7.5 Weiterarbeiten

**Sprungmarken:** Von einer geänderten Route in den Tracker. Von einer neuen MAC
in die Switchport-Suche. Von einem neuen Subnetz in den Netzplan. Der Befund ist
selten das Ziel — meist ist er der Anfang einer Frage.

**Export** als CSV und als Zeichnung, denn der häufigste Zweck ist eine
Zuarbeit: Audit, Change-Nachweis, Übergabe.

**Was die Ansicht ehrlich sagen muss:** Für Zeiträume vor der Einführung gibt es
nichts. Eine Abfrage auf ein Datum davor darf nicht „keine Änderungen" melden,
sondern „vor diesem Zeitpunkt wurde nicht aufgezeichnet". Der Unterschied ist
der zwischen einer Auskunft und einer Falschaussage. Dasselbe gilt für die
Zeichnung: Lässt sich der Zustand am Stichtag nicht vollständig rekonstruieren,
gehört das auf das Blatt und nicht in eine Fußnote.

---

## 8. Fallstricke

1. **Die Geburtsstunde.** Am Tag der Einführung ist jedes Objekt „neu". Der
   erste Lauf darf deshalb kein `created` schreiben, sondern legt still den
   Ausgangsbestand an.
2. **Unerreichbare Quelle ≠ Löschung.** Siehe 5.1. Der wichtigste Punkt der
   ganzen Planung.
3. **Rauschen erschlägt das Signal.** Felder, die sich bei jedem Sync ändern
   (Zeitstempel, Zähler, interne IDs), müssen vor der Hash-Bildung entfernt
   werden, sonst besteht das Protokoll aus Nicht-Änderungen.
4. **Umbenennung sieht aus wie Löschen plus Anlegen.** Solange der Name der
   Schlüssel ist, lässt sich das nicht unterscheiden. Wo es eine stabile ID gibt
   (iTop `_key`, LibreNMS `device_id`), sollte sie der Schlüssel sein.
5. **Zeitzonen und Takt.** Alles in UTC speichern, in lokaler Zeit anzeigen. Ein
   Stichtag ist ein Tag, kein Zeitpunkt — die Grenze gehört auf den Tagesbeginn
   in lokaler Zeit.
6. **Aufbewahrung.** Wie bei ARP und DNS eine Einstellung mit Vorgabewert und
   einem periodischen Aufräumer. Anders als dort ist die Vorgabe hier lang:
   Ein Änderungsprotokoll, das nach 180 Tagen endet, beantwortet die Frage nicht
   mehr, für die es gebaut wurde.

---

## 9. Reihenfolge

| # | Schritt | Ergebnis |
|---|---|---|
| 1 | Änderungsmenge je Sync eine Woche lang messen | Zahlen statt Schätzung, Entscheidung über Aufbewahrung |
| 2 | Je Objektart festlegen, welche Felder fachlich zählen | Grundlage für Hash und Anzeige — die eigentliche Arbeit |
| 3 | `change_log` + Hash-Spalte, Sync auf Abgleich umstellen | FortiManager-Änderungen laufen auf |
| 4 | **Ansicht mit DNS und ARP**: Zeitstrahl + Karten (7.1, 7.3) | erster Nutzen aus bereits vorhandenen Daten, ohne Wartezeit |
| 5 | FortiManager in der Ansicht | der Hauptteil, sobald Protokoll aufgelaufen ist |
| 6 | Gewichtung nach fachlicher Bedeutung (7.4) | die eine Route geht nicht im Policy-Push unter |
| 7 | Zustandsrekonstruktion zum Stichtag | Voraussetzung der Zeichnung |
| 8 | **Vorher-Nachher-Zeichnung** (7.2) | der eigentliche Grund für dieses Feature |
| 9 | iTop-Änderungslog prüfen und anbinden | CI- und Netzänderungen, rückwirkend |
| 10 | LibreNMS: Geräte, VLANs, LLDP | Änderungen an der Verkabelung |
| 11 | FDB-Wechsel als eigene, gedämpfte Reihe | „wo hing dieser Host im Februar" |
| 12 | FortiManager-Revision als Beleg mitschreiben | Belegbarkeit |
| 13 | CSV-Export und Sprungmarken | Zuarbeit und Weiterarbeit |

Schritt 4 steht bewusst vor dem FortiManager: Er nutzt Daten, die seit Monaten
auflaufen, und liefert sofort ein Ergebnis. Alles ab Schritt 5 kann
naturgemäß erst zeigen, was seit der Einführung passiert ist.

Schritt 7 ist die Stelle, an der sich zeigt, ob Abschnitt 4 richtig entschieden
wurde. Fällt die Rekonstruktion schwerer als gedacht, ist die Zeichnung teuer
und der Zeitstrahl trägt die Ansicht allein — brauchbar, aber ohne das
druckbare Ergebnis.

---

## 10. Zu klären, bevor gebaut wird

1. **Wie weit zurück muss die Auskunft reichen?** Ein Jahr für den
   Change-Nachweis oder fünf für ein Audit? Bestimmt die Aufbewahrung und damit
   die Größe.
2. **Ist `CMDBChangeOp` über die iTop-REST-Schnittstelle lesbar?** Entscheidet,
   ob iTop-Änderungen rückwirkend verfügbar sind oder erst ab Einführung.
3. **Welche Aufbewahrung haben die FortiManager-Revisionen?** Bestimmt, ob der
   Beleg aus Schritt 9 trägt.
4. **Wer darf die Zeitmaschine sehen?** Das Protokoll enthält vollständige
   Objektinhalte. Das ist mehr als die heutige Leseberechtigung — womöglich
   gehört die Ansicht hinter die Admin-Rolle.
5. **Reicht die Zustandsrekonstruktion für die Zeichnung?** Abschnitt 4 legt
   fest, was dafür gespeichert wird. Ob das genügt, lässt sich erst sagen, wenn
   der Netzplan-Renderer einmal mit einem rekonstruierten Stand gefüttert wurde.
   Das sollte früh ausprobiert werden, nicht erst in Schritt 8.
6. **Was passiert bei einem ADOM-Umbau?** Wird ein ADOM umbenannt oder
   aufgeteilt, sieht das nach einem vollständigen Austausch aus. Ob das
   akzeptabel ist oder abgefangen werden muss, hängt davon ab, wie oft es
   vorkommt.
