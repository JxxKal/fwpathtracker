# Services, Servicefamilien und Conduits

Planung für die Zone-&-Conduit-Dokumentation nach IEC 62443 aus iTop-Daten.

**Stand:** 21.09.2026 · Entwurf, noch nichts umgesetzt
**Betrifft:** iTop-Datenmodell (Extension), A38-Backend (`api/src/`), A38-Frontend

---

## 1. Warum

Die vier Zeichnungstypen der Hausvorgabe sind bis auf einen umgesetzt. Was
fehlt, ist die **Zone-&-Conduit-Zeichnung** — und sie fehlt nicht am Renderer,
sondern an den Daten. A38 weiß heute aus FortiManager und LibreNMS, *wie*
Segmente technisch gekoppelt sind. Es weiß nicht, *wozu*: welcher fachliche
Dienst über eine Kopplung läuft und welche Zone ein Segment trägt.

Diese Information steht nirgends automatisch. Sie ist eine fachliche Aussage
und muss gepflegt werden — die Frage ist nur, an welcher Stelle. iTop ist der
richtige Ort: dort stehen die CIs bereits, dort wird ohnehin gepflegt, und A38
liest iTop schon.

Der Weg führt über drei Schritte:

1. **Dienste zweistufig** in iTop führen (Servicefamilie → Service).
2. **CIs mit Diensten verknüpfen** — daraus fallen die Netze automatisch an,
   denn die Management-IP eines CIs liegt in einem Subnetz.
3. **Conduits als eigene Objekte** pflegen, die zwei Zonen und einen Dienst
   verbinden.

Erst danach ist die Zeichnung ein Leseproblem, kein Datenproblem mehr.

---

## 2. Der Kern: Netze ohne einen einzigen neuen Pflegeschritt

Der tragende Gedanke ist die Kette

```
Servicefamilie → Service → CI → Management-IP → Subnetz → VLAN / Netzname
```

Niemand trägt ein Netz an einem Dienst ein. Ein CI bekommt seinen Dienst, und
das Netz ergibt sich aus der IP, die ohnehin gepflegt ist. Das ist derselbe
Weg, den der Free-IP-Finder und die Namensauflösung heute schon gehen
(`ItopSource._index` liest `managementip_id_friendlyname` für `Server` und
`NetworkDevice`).

Daraus folgt eine Entscheidung, die früh getroffen werden muss: **Die
Zonenzugehörigkeit hängt am Netz, nicht am Dienst.** Ein Dienst kann in
mehreren Zonen Geräte haben — genau das macht ihn ja zum Kandidaten für einen
Conduit. Die Servicefamilie trägt trotzdem ein Zonen-Flag, aber als *Soll*:
sie sagt, wo die Familie hingehört. Weicht ein CI davon ab, ist das ein Befund
und keine Datenpanne. A38 soll das melden, nicht glätten.

---

## 3. iTop-Datenmodell

### 3.1 Was iTop schon mitbringt

iTop hat mit `ServiceFamily`, `Service` und `ServiceSubcategory` bereits eine
zweistufige Dienstestruktur, und `FunctionalCI` lässt sich über
`lnkFunctionalCIToService` mit einem Service verknüpfen. **Das ist zu prüfen,
bevor eine Extension gebaut wird** — die Standardklassen zu benutzen spart die
halbe Extension und jede spätere Migrationsfrage.

Offene Punkte dieser Prüfung:

- Trägt `ServiceFamily` in der eingesetzten Version ein freies Attributfeld,
  oder braucht das Zonen-Flag ohnehin eine Erweiterung?
- Ist `lnkFunctionalCIToService` in der Oberfläche brauchbar pflegbar, oder
  arbeitet der Betrieb faktisch mit `Service` an `Contact`?
- Wie verhält sich die bestehende Organisationsstruktur (`org_filter` in der
  A38-Konfiguration) dazu?

Fällt die Prüfung negativ aus, bleibt die eigene Extension. Die Struktur unten
beschreibt das fachliche Ziel und gilt für beide Wege.

### 3.2 Servicefamilie

| Feld | Typ | Bedeutung |
|---|---|---|
| `name` | Text | „Infrastrukturdienste", „Tier0", „PLS iFix" |
| `zone_level` | Auswahl | `L2`, `L3`, `PIN`, `PCN`, `DMZ`, `Enterprise` |
| `criticality` | Auswahl | für die spätere Bewertung, optional |
| `description` | Text | |

`zone_level` ist eine **Auswahlliste, kein Freitext**. Eine Zone, die sich auf
fünf Arten schreiben lässt, taugt nicht als Schlüssel — dieselbe Erfahrung wie
bei der Shape-Bibliothek, wo Freitext für Modellnamen ersetzt werden musste,
weil ein Tippfehler erst auffiel, als die Zeichnung fertig war und nichts
passte.

Die Liste der Stufen muss vor dem ersten Datensatz festgelegt werden. Sie
später zu erweitern ist leicht, sie umzubenennen nicht.

### 3.3 Service

| Feld | Typ | Bedeutung |
|---|---|---|
| `name` | Text | „AD", „Backup", „Fileshare" |
| `family_id` | Verknüpfung | → Servicefamilie |
| `description` | Text | |

Ein Service gehört zu **genau einer** Familie. Mehrfachzugehörigkeit würde die
Auswertung mehrdeutig machen, und die Familie ist die Ebene, an der das
Zonen-Flag hängt.

### 3.4 CI → Service

Eine n:m-Verknüpfung zwischen `FunctionalCI` und Service. Ein Domaincontroller
trägt „AD", ein Fileserver trägt „Fileshare" und vielleicht auch „Backup".

**Rolle mitführen** (`client` / `server` / `peer`): Ein Conduit hat eine
Richtung, und ohne die Rolle lässt sich später nicht sagen, wer den Dienst
anbietet und wer ihn nutzt. Das nachzurüsten, wenn schon dreihundert
Verknüpfungen stehen, ist teuer.

### 3.5 Conduit

Der eigentlich neue Objekttyp. Ein Conduit ist die **erlaubte, dokumentierte
Kommunikationsbeziehung zwischen zwei Zonen für einen Dienst**:

| Feld | Typ | Bedeutung |
|---|---|---|
| `name` | Text | „Verbindung zum AD", „Verbindung zur Ferneinwahl" |
| `service_id` | Verknüpfung | → Service |
| `zone_from` | Auswahl | Quellzone (dieselbe Liste wie `zone_level`) |
| `zone_to` | Auswahl | Zielzone |
| `protocols` | Text | „TCP 88, 389, 445" — Freitext genügt zunächst |
| `status` | Auswahl | `geplant` / `aktiv` / `stillgelegt` |
| `description` | Text | Begründung, Verweis auf Freigabe |

Die vier genannten Beispiele — AD, Ferneinwahl, iFix, Messwarte — sind
Instanzen dieser Klasse, keine eigenen Klassen. Wer sie als Kategorien
anlegte, müsste für jeden fünften Conduit die Extension anfassen.

**Was ein Conduit nicht ist:** keine Firewall-Regel. Er beschreibt die
fachliche Erlaubnis. Ob die Firewall sie tatsächlich umsetzt, ist die Frage,
die A38 ohnehin beantwortet — und genau daraus wird später der interessanteste
Bericht (siehe Abschnitt 7).

### 3.6 Zonenzugehörigkeit eines Netzes

Bleibt die Frage, woher A38 weiß, in welcher Zone ein **Subnetz** liegt. Drei
Wege, in der Reihenfolge ihrer Belastbarkeit:

1. **Am Subnetz gepflegt.** Ein `zone`-Feld an der TeemIP-Subnetzklasse.
   Genau und teuer: einmal je Subnetz.
2. **Aus den CIs abgeleitet.** Die Zone der Servicefamilien der CIs, die im
   Netz stehen. Kostenlos, aber mehrdeutig, sobald ein Netz gemischt ist.
3. **Aus dem Standort-Supernetz.** A38 hat die Liste bereits
   (*Einstellungen → Standort-Supernetze*); sie ließe sich um ein Zonen-Flag
   erweitern. Grob, aber ohne jeden Pflegeaufwand in iTop.

**Vorschlag:** alle drei, in dieser Reihenfolge als Kette, mit sichtbarer
Herkunft — so wie die Namensauflösung heute FMG → iTop → DNS kettet und in der
Oberfläche anzeigt, woher der Treffer kam. Wer es genau braucht, pflegt es am
Subnetz; wer nur einen Überblick will, bekommt ihn aus der Ableitung und sieht,
dass sie abgeleitet ist.

---

## 4. Was A38 daraus baut

### 4.1 Neue Quelle

`ItopSource` bekommt eine Methode `services(cfg)`, gebaut wie `ipam()`: ein
`core/get` je Klasse, TTL-Cache, und **jede Klasse einzeln fehlertolerant**.
Fehlt die Conduit-Klasse, weil die Extension noch nicht installiert ist, muss
der Rest weiterlaufen — dasselbe Muster wie bei `IPv4Range` heute, wo eine
fehlende Klasse nur die Ranges kostet und nicht den Subnetzbaum.

Rückgabe:

```python
{
  "families": [{"id", "name", "zone", "description"}],
  "services": [{"id", "name", "family_id", "description"}],
  "ci_links": [{"ci_id", "ci_name", "ci_class", "ip", "service_id", "role"}],
  "conduits": [{"id", "name", "service_id", "zone_from", "zone_to",
                "protocols", "status"}],
}
```

### 4.2 Auflösung zu Netzen

Ein neues Modul `api/src/services/model.py`:

- CI-IP → Subnetz über die bestehende `PrefixTable` (longest match, derselbe
  Weg wie im Tracker).
- Subnetz → VLAN, Name, Zone, Firewall/VDOM aus dem FMG-Inventar; das steht
  heute schon in `_networks()` in `api/src/diagram/model.py` bereit.
- Ergebnis je Service: die Netze, in denen er lebt, mit Standort und VDOM.

**Stolperstellen, die vorher feststehen müssen:**

- Ein CI **ohne** Management-IP fällt heute schon aus dem Index. Für die
  Serviceliste ist es trotzdem relevant und muss als „ohne IP, kein Netz
  zuordenbar" erscheinen statt stillschweigend zu fehlen.
- Ein CI mit **mehreren** IPs gehört in mehrere Netze. Das ist kein Fehler,
  sondern oft genau der Grund, warum es ein Conduit gibt.
- Eine IP, die in **keinem** bekannten Subnetz liegt, ist ein Befund: entweder
  fehlt das Subnetz in iTop oder das Netz an der Firewall.

Alle drei gehören als Warnung in die Ausgabe, nicht in eine Log-Zeile.

### 4.3 Endpunkte

| Endpunkt | Zweck |
|---|---|
| `GET /api/services/families` | Familien mit Zonen-Flag und Anzahl |
| `GET /api/services` | Dienste, gefiltert nach Familie/Standort |
| `GET /api/services/{id}/networks` | Netze eines Dienstes, mit Herkunft |
| `GET /api/conduits` | Conduits, gefiltert nach Zone/Dienst/Status |
| `POST /api/diagram` (`view=zone-conduit`) | die Zeichnung |

Die Zeichnung reiht sich in den bestehenden Netzplan-Endpunkt ein und erbt
Scope-Auswahl, Schriftfeld, draw.io-Link und PDF-Export.

---

## 5. Die Zeichnung

**Scope wie gewohnt:** global, Standort, Firewall, VDOM. Dazu eine
**Conduit-Auswahl** — man klickt zusammen, welche Conduits die Zeichnung zeigt.
Ohne Auswahl: alle im Scope.

**Aufbau:**

- **Zonen als Container**, aus dem `zone_level` der Familien beziehungsweise
  der Netz-Zone. Eine Zone je Container, Reihenfolge nach Stufe — Enterprise
  oben, PCN unten, wie es die Norm zeichnet.
- **Netze als Kästen** in der Zone, mit VLAN und CIDR. Dieselbe Beschriftung
  wie in der Strukturansicht, damit man zwischen den Zeichnungen nicht
  umdenken muss.
- **Conduits als beschriftete Kanten** zwischen den Zonen, Label aus dem
  Conduit-Namen und dem Dienst.

**Für die Zonenübergänge das Routing zeigen.** Das ist der Punkt, an dem diese
Zeichnung mehr kann als ein Visio-Bild: A38 kennt den tatsächlichen Weg. Für
jeden Conduit lässt sich die Pfad-Engine fragen, über welche Firewall, welches
VDOM und welchen Gateway der Übergang läuft — `classify_egress` in
`api/src/engine/classify.py` liefert genau das, inklusive der Unterscheidung
zwischen lokalem Segment, VDOM-Link, Overlay und Default-Route.

An der Kante steht dann nicht nur „Verbindung zum AD", sondern auch, wo dieser
Übergang stattfindet. Im globalen Scope ist das die eigentliche Auskunft: über
welche Gateways laufen die Zonenübergänge überhaupt.

**Grenze, die vorher klar sein muss:** Ein Conduit ohne auffindbaren Pfad ist
keine Fehlfunktion der Zeichnung. Entweder ist der Conduit gepflegt, aber nicht
gebaut, oder die Quelle/Ziel-Zone hat kein Netz im Scope. Beides gehört als
Hinweis an die Kante, nicht als leere Linie.

---

## 6. Die Serviceliste

Neben der Zeichnung die nüchterne Tabelle, je Standort oder Gerät:

| Servicefamilie | Zone | Service | CIs | Netze | VLANs |
|---|---|---|---|---|---|

Sie ist billiger zu bauen als die Zeichnung, im Alltag vermutlich häufiger
gebraucht, und sie ist der beste Test für die Datenqualität: Wer sie einmal
liest, sieht sofort, welche CIs noch keinen Dienst tragen.

**Deshalb zuerst bauen.** Sie deckt die Pflegelücken auf, solange das Nachtragen
noch billig ist.

---

## 7. Was danach möglich wird

Nicht Teil dieser Planung, aber der Grund, warum sich der Aufwand lohnt:

- **Conduit gegen Wirklichkeit.** Für jeden Conduit einen Trace fahren und
  prüfen, ob die Firewall ihn tatsächlich erlaubt. A38 kann beides; es fehlt
  nur die Liste der Soll-Beziehungen. Das ist dieselbe Mechanik wie die
  bestehenden Check-Gruppen, nur mit iTop als Quelle der Erwartung.
- **Regeln ohne Conduit.** Die Gegenrichtung: Freigaben, die zonenübergreifend
  wirken, ohne dass ein Conduit sie dokumentiert. Das ist der Audit-Befund, den
  niemand von Hand findet.
- **Zonenverletzungen.** CIs, deren Netz-Zone nicht zum `zone_level` ihrer
  Servicefamilie passt.

---

## 8. Reihenfolge

Jeder Schritt ist für sich nützlich. Keiner setzt voraus, dass der nächste
kommt.

| # | Schritt | Ergebnis |
|---|---|---|
| 1 | iTop-Standardklassen prüfen | Entscheidung Extension ja/nein |
| 2 | Datenmodell festlegen, Zonenliste beschließen | Pflege kann beginnen |
| 3 | Extension bauen oder Standard konfigurieren | Felder stehen in iTop |
| 4 | `ItopSource.services()` + Auflösung zu Netzen | A38 kennt die Dienste |
| 5 | **Serviceliste** (Tabelle, Standort/Gerät) | erster Nutzen, Datenprüfung |
| 6 | Zonenzuordnung der Netze (Kette aus 3.6) | Zonen sind benannt |
| 7 | Conduit-Objekte + Pflege | Soll-Beziehungen stehen |
| 8 | **Zone-&-Conduit-Zeichnung** | die vierte Zeichnung der Hausvorgabe |
| 9 | Routing an den Zonenübergängen | Ist-Weg an der Kante |
| 10 | Conduit-Checks gegen die Firewall | Abgleich Soll/Ist |

Schritt 5 ist die erste Stelle, an der jemand etwas davon hat. Bis dahin ist
alles Vorbereitung — das sollte man wissen, bevor man anfängt.

---

## 9. Zu klären, bevor gebaut wird

1. **Standardklassen oder Extension?** Bestimmt den Aufwand von Schritt 3
   maßgeblich.
2. **Welche Zonenstufen genau?** `L2`, `L3`, `PIN`, `PCN` sind gesetzt. Fehlen
   DMZ, Enterprise, Safety? Die Liste sollte vollständig sein, bevor Daten
   entstehen.
3. **Wer pflegt?** Ohne benannte Zuständigkeit steht die Struktur in iTop und
   bleibt leer. Das ist das wahrscheinlichste Scheitern dieses Vorhabens, und
   es ist kein technisches.
4. **Wie viele CIs sind betroffen?** Bestimmt, ob die Erstbefüllung von Hand
   geht oder ein Import gebraucht wird.
5. **Zonenzugehörigkeit am Subnetz pflegen?** Der genaue Weg kostet einmal
   Arbeit je Subnetz. Lohnt sich das gegenüber der Ableitung?
6. **Ist der Conduit standortbezogen?** „Verbindung zum AD" gibt es womöglich
   an jedem Standort einzeln. Entweder trägt der Conduit einen Standort, oder
   er ist global und die Zeichnung filtert über die beteiligten Netze. Die
   zweite Variante ist pflegeärmer und vermutlich richtig — aber es ist eine
   Entscheidung, keine Selbstverständlichkeit.
