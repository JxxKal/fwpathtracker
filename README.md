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
- **Geteiltes Underlay/SD-WAN**: Ein Next-Hop wird nur aus dem Routing abgeleitet,
  wenn das Gateway ihn wirklich belegt. Nicht belegt ist es, wenn das Gateway
  keinem gemanagten Interface gehört (SD-WAN-Appliance, Provider-Router), wenn
  mehrere Geräte dieselbe Gateway-IP tragen (Transfernetze sind pro Standort
  wiederverwendet) oder wenn das Ziel über die **Default-Route** läuft — dann
  kennt das Gerät das Ziel nicht und reicht es an den Uplink weiter. In allen
  drei Fällen entscheidet der Präfix-Besitzer des Ziels bzw. der Pfad endet
  sichtbar am Uplink, statt eine standortfremde Firewall mit implizitem Deny in
  den Pfad zu ziehen. Für Inter-VDOM-Links auf demselben Gerät gilt die Sperre
  nicht — dort IST die Default-Route der Weg zum Router-VDOM.
- **Live-Sessions (opt-in)**: Checkbox „Live-Sessions prüfen" liest zusätzlich
  `firewall/session` jeder Firewall im Pfad — der **Ist-Zustand** neben der
  Theorie des Policy-Lookups. Das Hop-Panel zeigt die passenden Sessions
  (Flow, Interface-Paar, getroffene Regel, Dauer); gewarnt wird nur bei
  Widersprüchen: Verkehr trotz `DENY`, oder Verkehr über eine **andere** Regel
  als der Lookup meldet (globale Header-Regel, NAT, geänderte Policy). Kostet
  einen weiteren Live-Aufruf je Hop, deshalb standardmäßig aus — Batch-Checks
  bleiben unberührt. Rein lesend (GET), die No-Write-Garantie gilt unverändert.
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

Eigener Tab **Network Tools** mit Seitenleiste: links die Werkzeuge nach
Aufgabe gruppiert (*Diagnose · Bestand · Planung*), rechts das gewählte über die
volle Breite. Das zuletzt benutzte wird gemerkt, und je Werkzeug gibt es einen
teilbaren Link (`?tab=tools&tool=…`).

Oben stehen damit nur noch drei Tabs: **Tracker · Network Tools ·
Einstellungen**. Der Tracker trägt dieselbe Seitenleiste — *Prüfen* mit
„Pfad prüfen", *Gespeichert* mit Checks und Verlauf. Verschickte Alt-Links
(`?tab=checks&…`, `?tab=werkzeuge&…`) landen weiterhin an der richtigen Stelle.

- **Netz-Zugehörigkeit** — an welchem VDOM/Interface ist ein Netz *connected*
  (der Ursprung)? Mit VLAN, Maske, Gateway; Warnung bei Mehrdeutigkeit.
- **IP-Rechner** — Host/Maske oder Netzsegment → Netz, Maske, Host-Range,
  Broadcast (jodies-ipcalc-Stil).
- **Freies Subnetz finden** — freie Blöcke gewünschter Größe in einem Supernet;
  belegter Bestand aus iTop (IPAM). Standort-Supernetze als Vorauswahl (in den
  Einstellungen pflegbar).
- **Freie IP-Adresse finden** — eine Stufe tiefer: Bereich aus dem iTop-IPAM
  wählen (Baum: Standort → Subnetz → Range, oder Netz/Von/Bis manuell), dann
  scheidet der Bestand aus — iTop-Adressobjekte mit Status *allocated/reserved*,
  Management-IPs von Servern/Netzgeräten (auch ohne Adressobjekt: nicht jede
  zugewiesene IP ist in iTop reserviert), Firewall-Interfaces aus dem
  FMG-Inventar, Gateway und DHCP-Ranges. Was iTop als frei durchlässt, wird
  live geprüft: **Ping**, **Reverse-DNS** (PTR, z. B. in der konfigurierten
  Suchdomain) und die **ARP-Historie** (hat hier kürzlich ein Gerät gesprochen,
  das gerade aus ist? — vorher wird die Live-ARP-Tabelle des zuständigen VDOMs
  einmal eingesammelt). Bewertung je Adresse: *frei* (alles still),
  *zweifelhaft* (DNS oder ARP kennen sie), *belegt* (antwortet), *nicht
  prüfbar* (kein Ping im Container). Geprüft wird in Wellen, bis die gewünschte
  Anzahl freier Adressen beisammen ist.
- **Switch-Ansicht** — was hängt an welchem Port? Switch wählen (mit Filter auf
  LibreNMS-Standort oder Gerätegruppe), Buchse anklicken, Belegung lesen: MAC,
  IP, Name, Alter des Eintrags. Dieselbe Quelle wie die physische Zeichnung —
  Ports und FDB aus LibreNMS, IP↔MAC aus der Historie, Namen aus Reverse-DNS —
  aber zum Klicken statt zum Drucken. Ist für das Modell ein Blech mit
  zugeordneten Buchsen hinterlegt, steht es hier; sonst ein Raster. Stacks
  zeigen je Einheit ein Blech. Logische Interfaces (Bridge-Aggregation,
  Vlan-interface, Loopback …) haben keine Buchse und stehen nicht in der Liste
  — gezählt werden sie trotzdem, sonst fragt jemand nach den fehlenden
  Interfaces.

  Diese Ansicht ersetzt die frühere zweite physische Zeichenebene. Auf Papier
  war das Blech entweder unlesbar klein oder die Leitungen liefen quer über
  alles; am Bildschirm klickt man die Buchse an. Ein Gerät, dessen sysName nur
  aus Steuerzeichen oder Punkten besteht, steht hier unter seiner **IP** — drei
  Einträge „.............................." sind keine Auswahl.
- **Netzplan (draw.io)** — zwei Darstellungen zur Wahl. **Struktur** (Default):
  Container für Firewall, VDOM und Netz mit Kopplungen und Switchen. **Logisch**
  nach der Hausvorgabe für die OT-Dokumentation: Netze als farbige Busleisten
  mit VLAN-ID, Endgeräte mit auf die signifikanten Stellen gekürzter IP
  (`.73` im /24, `.58.73` im /16) und um das gemeinsame Namenspräfix des Netzes
  gekürztem Namen (`WD-OT-L3-SVO3036` → `SVO3036`; das Präfix steht einmal an
  der Leiste). Geräte liegen in **zwei Höhenlagen** versetzt, damit lange Namen
  nicht aneinanderstoßen, und hängen mit **senkrechten** Abgängen an ihrer
  Leiste. **Nur Netze mit Geräten** — eine leere Busleiste belegt eine volle
  Zeile und sagt nichts; bei einer Firewall mit vielen angelegten, aber leeren
  Interfaces war die Zeichnung fast nur noch Leerlauf. Ausgeblendete Netze
  werden im Schriftfeld gezählt, und ein Hinweis nennt sie nach dem Erzeugen.
  Steht nirgends ein Gerät (Gesamtplan, *keine Hosts*, oder es wurden nur
  Netzwerkgeräte eingesammelt), bleiben alle Netze stehen — ein leeres Blatt
  wäre schlechter. **Ohne Switche und Ports** — ausgeblendete
  Switche werden im Schriftfeld gezählt. Wird eine Geräteliste zu lang, steht
  je Geräteklasse ein Symbol mit Anzahl und Verweis auf eine **Tabellenseite**
  in derselben Datei. Druckformat DIN A3 quer.
  **Physisch** zeichnet, wie die Netzwerkkomponenten untereinander hängen:
  Knoten und Kanten aus den **LLDP**-Nachbarschaften in LibreNMS, mit den Ports
  an beiden Enden, Ebenen per Breitensuche vom bestvernetzten Gerät (Core oben,
  Zugang unten), Firewalls mit eigenem Symbol. Kanten zu nicht überwachten
  Nachbarn bleiben draußen — einzelne Endgeräte beantwortet die
  **Switch-Ansicht**, nicht der Plan. Das Symbol richtet sich nach Hersteller
  und Rolle (Firewall, Layer-3-Switch, Access-Switch, Access Point). Wer die
  echte Frontblende will, hinterlegt sie unter
  *Einstellungen → Shape-Bibliothek*.
  Die Modellliste dort kommt aus **LibreNMS** (die tatsächlich erkannten
  Hardware-Strings), nicht aus einem Freitextfeld: jedes Modell lässt sich auf
  fünf Arten schreiben, und ein Tippfehler im Muster fällt erst auf, wenn die
  Zeichnung fertig ist und nichts passt. Ohne hinterlegtes Bild bleibt es beim
  Klassensymbol — ein unbekanntes Gerät fällt nie aus der Zeichnung.

  Ein Bild allein trägt allerdings keine Information — die Leitung muss an der
  richtigen Buchse landen. Dafür werden die Buchsen einmal je Modell
  **zugeordnet** — sie trägt die Switch-Ansicht: die Portliste des Geräts wird
  der Reihe nach abgearbeitet, der hervorgehobene Port landet dort, wo man
  klickt. Ein Raster taugt dafür
  nicht — echte Frontblenden haben Lücken zwischen den Portgruppen,
  Hutschienengeräte stehen hochkant, und 40/100-G-Buchsen sitzen abgesetzt und
  sind größer (Sondergrößen je Buchse einstellbar). Zugeordnet wird über den
  **Portnamen**, nicht über die Nummer: `HundredGigE1/0/1` und
  `GigabitEthernet1/0/1` tragen dieselbe Nummer und sind verschiedene Buchsen,
  während der Name bei allen Geräten desselben Modells gleich ist. Ports ohne
  Zuordnung verschwinden nicht, sie stehen als Kästchenreihe unter dem Bild.
  Ohne Zuordnung bleibt das Bild ein Erkennungszeichen, und die Ansicht fällt
  auf ein Raster zurück — die Rückfallebene für alles Unbekannte.
  Ein **Stack** ist mehrfach dasselbe Gerät: eingemessen wird EIN Blech, und
  die Zuordnung gilt für jede Einheit (`Ten-GigabitEthernet2/0/17` sitzt dort,
  wo `…1/0/17` sitzt).

  Bewusst ein **Upload** statt eines Visio-Konverters: Hersteller-Stencils sind
  teils altes Binärformat (`.vss`), liegen teils hinter Abo-Portalen und
  enthalten teils nur EMF, das kein Browser darstellt; SVG und PNG bettet
  draw.io dagegen direkt und verlustfrei ein.

  Der Umfang einer physischen Zeichnung ist genau **eine** Auswahl:
  **LibreNMS-Standort** (bei uns teils raumscharf gepflegt) oder
  **Gerätegruppe** — beide schließen sich in der Oberfläche gegenseitig aus.
  Gefiltert wird von LibreNMS selbst (`?type=location` bzw.
  `/devicegroups/:name`) — das Standortfeld heißt je nach Version anders, der
  Filter nicht. Derselbe Filter steht in der Switch-Ansicht: ein raumscharfer
  Standort macht aus 300 Geräten eine Handvoll.
  Struktur und Logisch teilen Scope und Schriftfeld: VDOM, Firewall, **Standort**
  oder **alle Standorte**; Netze je
  Interface (VLAN, CIDR, Zone, iTop-Name), VDOM-Links, Switches per
  LLDP (LibreNMS).

  Was **außerhalb des Scopes** liegt, wird nicht gezeichnet. Eine Firewall am
  Blattrand und eine Linie quer über das halbe Blatt sagen weniger als eine
  Zeile dort, wo die Kopplung entsteht: bei vier Uplinks kreuzen sich die
  Linien, laufen durch Netz-Kästen und treffen sich in einem Punkt, an dem
  niemand mehr auseinanderhält, welche zu welchem VDOM gehört. Stattdessen
  trägt jedes VDOM oben eine **Uplink-Marke** mit einer Zeile je Kopplung nach
  draußen — Default-Route zuerst, dann Transit und Overlay mit Ziel-VDOM; die
  vollständigen Netzlisten stehen im Tooltip. Die Überschrift ist frei wählbar
  (*Einstellungen → draw.io*), denn wer den Weg nach draußen betreibt, heißt
  bei jedem anders. Kopplungen **innerhalb** des Scopes bleiben Linien: die
  sind kurz und sagen genau das, was eine Linie gut sagt. Detailstufe wählbar: *nur Netze* (Netzverbindungsplan),
  *nur Netzwerkgeräte* (Switches, NetworkDevice-CIs) oder *alle Hosts* aus iTop,
  FMG-Objekten und ARP-Historie; *automatisch* fällt oberhalb von 1500 Hosts
  auf Netzwerkgeräte zurück. Symbole aus der draw.io-Bibliothek „Network"
  (Server, Switch, PC, Firewall — offline verfügbar, Zuordnung über
  iTop-Klasse und Beschreibung). Netz-Kästen mit vielen Hosts starten
  eingeklappt, jeder Knoten trägt einen Tooltip mit den Quellen — die Zeichnung ist damit
  gleichzeitig der Abgleich von FMG, iTop und LibreNMS. Herunterladen oder
  direkt in der eigenen draw.io-Instanz öffnen (s.u.).
  Der **Standort** ergibt sich aus den Standort-Supernetzen (*Einstellungen →
  Standort-Supernetze*, dieselbe Liste wie im Free-Subnet-Finder; der **Name**
  ist die Identität des Standorts und steht so in der Zeichnung, der
  **Bezeichner** daneben erklärt ihn nur): eine Firewall gehört dorthin, wo
  die **Mehrheit** der Netze liegt, die sie lokal routet — über alle ihre VDOMs
  gezählt. Nicht der erste oder engste Treffer, denn einzelne Netze zeigen
  woandershin (Management-Adresse aus einem zentralen Bereich, Transfernetz zum
  Nachbarstandort) und würden die Firewall ans falsche Haus hängen. Bei
  Gleichstand gewinnt das engere Supernetz; ein Site-Override aus den
  Einstellungen schlägt alles. Die Geräteauswahl im Werkzeug zeigt die
  Begründung als Tooltip („Gas Nord · 7 von 8 Netzen · auch Hamburg (1)"),
  damit eine falsche Zuordnung auffällt statt still zu bleiben.
  Wird es doch einmal unklar, zeigt `scripts/standort-diagnose.sh` auf dem
  Docker-Host in einem Rutsch die Supernetze (samt Hinweis, wenn es noch die
  Beispielwerte aus dem Code sind), die Overrides und je Gerät die Netze, die
  die Zuordnung tragen.
  Der **Gesamtplan** zeichnet Firewalls nach Standort gruppiert und ihre
  Kopplungen — ohne Netze und Hosts, weil bei Dutzenden Geräten nur die Frage
  „wer redet mit wem" lesbar bleibt.
  **Abgeschaltete Interfaces** (Shutdown) stehen mit im Plan, grau und
  gestrichelt als *abgeschaltet* gekennzeichnet und ans Ende der Spalte
  sortiert: ein Netzplan dokumentiert den konfigurierten Bestand, und ein
  stillgelegtes Segment wegzulassen hieße, dass der Plan der Firewall-Config
  widerspricht. Für die Pfad-Engine zählt es weiterhin **nicht** als connected.
  Davon zu trennen ist der **Link-Status**: `set status up` sagt nichts darüber,
  ob ein Kabel steckt. Das ist Laufzeitzustand und steht in keinem Snapshot —
  A38 holt ihn beim Erzeugen live (ein Monitor-Aufruf je VDOM im Scope,
  parallel) und zeichnet Interfaces ohne Link bernsteinfarben als *Link down*.
  Ist der Zustand nicht ermittelbar (FMG/Gerät nicht erreichbar), bleibt er
  **unbekannt** statt „up" — die Zeichnung sagt das dann in einer Warnung.
  Netze werden nach *aktiv · ohne Link · abgeschaltet* sortiert.
  **Firewalls im HA-Cluster** bekommen ein Abzeichen (`HA A-P · 2 Knoten`) und
  einen kräftigeren Rahmen; der Tooltip nennt Gruppe, Mitglieder, Rollen,
  Seriennummern und Status (aus `dvmdb/device`, kein zusätzlicher Sync nötig).
  Jede Zeichnung trägt **rechts daneben** ein **Schriftfeld** im Stil eines
  Engineering-Plans: Revisionstabelle, Vertraulichkeitsvermerk, Logo, Autor
  mit Datum, Titel mit Scope-Zahlen, Zeichnungsnummer und Blatt. Gefüllt wird
  es von A38 selbst — Titel und Zahlen aus dem Scope, Datum von heute, Autor
  aus dem angemeldeten Benutzer, Nummer aus dem Dateinamen. Firma, Vermerk,
  Gruppe und **Logo** sind Stammdaten aus *Einstellungen → Schriftfeld*
  (Logo-Datei dort hochladen, sie wird in jede Zeichnung eingebettet). Es steht
  **neben** dem Plan statt darunter: Container wachsen beim Aufklappen nach
  unten und würden ein Schriftfeld auf festen Koordinaten überdecken. Alle
  Zellen liegen in einer Gruppe, lassen sich also mit einem Klick anfassen und
  verschieben.
  Netze **mit** Hosts starten **zugeklappt** — beim Öffnen zählt die Struktur,
  die Hostliste holt man sich per Klick; die Anzahl steht am Kasten, damit man
  sieht, ob sich das lohnt. Für Ausdruck und PDF gibt es den Schalter
  *Hosts ausgeklappt*: dann sind alle Listen offen (und die Zeichnung groß).
  Firewall- und VDOM-Container tragen draw.ios **Stack-Layout**
  (`childLayout=stackLayout`): ein aufgeklapptes Netz schiebt die darunter
  liegenden nach unten und zieht Container mit, statt sie zu überdecken; beim
  Zuklappen schrumpft alles wieder (`resizeParentMax=0`). Netze stehen deshalb
  in einer Spalte je VDOM, VDOMs nebeneinander, Switches rechts neben der
  Firewall (dort stört das Wachstum nach unten nicht).
- **Martin Lehmann, wo hängt das Gerät?** — IP oder Name → **Switch und Port**, an dem das Gerät
  physisch steckt. IP→MAC live von der FortiGate (die ist an fast allen
  Standorten der L3-Router), MAC→Port aus der **LibreNMS**-FDB. Zeigt alle
  Fundstellen mit Uplink-Kennzeichnung, Konfidenz und Alter des Eintrags —
  siehe [Switchport-Suche](#switchport-suche-librenms). Findet **auch einen
  Host, der gerade aus ist**: die IP↔MAC-Bindungen werden mitgeschrieben,
  solange er läuft, und das Ergebnis dann klar als Aufzeichnung gekennzeichnet.
- **Netzwerkport-Check** — IP oder Name → **alle** Ports des Hosts mit VLAN, statt
  nur des besten Treffers: je Fundstelle das VLAN, in dem die MAC gelernt wurde
  (FDB) und die konfigurierte Mitgliedschaft des Ports (untagged/tagged). Ist der
  Host selbst ein überwachtes Gerät, dazu seine komplette Portliste mit den je
  Port beobachteten VLANs. Plus die L3-Seite: welches VLAN-Interface welcher
  Firewall/VDOM das Subnetz trägt (aus dem FMG-Inventar, ohne Live-Abfrage).
- **VLAN-Übersicht** — alle bekannten VLAN-Nummern mit Bezeichnung, Subnetz,
  Switch-Anzahl und Firewall-Interface. Zusammengeführt über die **Nummer**
  (Switch und Firewall benennen dasselbe VLAN oft verschieden), Quelle je Zeile
  erkennbar. Freie Nummern als Lücken über 1–4094 — Aussage über den bekannten
  Bestand, keine Reservierungs-Datenbank.

### 🔎 Resolver & Namensauflösung

Namen im Netzplan kommen aus **allen** Quellen: iTop-CI, iTop-Adressobjekt,
FortiManager-Adressobjekt, LibreNMS — und für alles, was danach noch namenlos
ist, aus **Reverse-DNS** (gedeckelt auf 400 Abfragen je Zeichnung, 16
parallel). Wie viele Namen von dort kamen, sagt die Antwort als Hinweis; das
ist zugleich eine Aussage über den Pflegestand im iTop.

FMG-Objekte → **iTop** (TeemIP) → **DNS**, mit Provenance-Anzeige in beide
Richtungen. Autocomplete für Quelle/Ziel.

#### Reverse-DNS-Cache

Eine Zeichnung fragt bis zu 400 Adressen rückwärts ab, die Switch-Ansicht 300,
der Free-IP-Finder 256 — und beim nächsten Aufruf dieselben wieder. Namen
ändern sich selten, also merkt A38 sie sich in einer eigenen Tabelle
(`dns_cache`, IP als Schlüssel).

Festgehalten wird auch die **Fehlanzeige**, und zwar gerade deshalb, weil sie
das Teure ist: eine Adresse ohne PTR-Eintrag läuft jedes Mal in die volle
Zeitüberschreitung, während ein Treffer sofort zurückkommt. Sie gilt nur
kürzer, denn eine leere Adresse bekommt eher einen Eintrag, als dass ein
bestehender Name sich ändert.

| Einstellung (**Einstellungen → DNS**) | Default | Bedeutung |
|---|---|---|
| `cache_hit_days` | 7 | wie lange ein gefundener Name ohne Nachfrage gilt |
| `cache_miss_hours` | 24 | wie lange eine Fehlanzeige gilt |
| `cache_retention_days` | 180 | ab wann ungeprüfte Zeilen gelöscht werden |

Beide Gültigkeiten auf 0 schalten den Cache ab; die Auflösung selbst läuft
weiter. Bestand, gesparte Abfragen und zwei Aufräum-Knöpfe stehen im selben
Panel — *Cache leeren* ist nach einem Resolver-Wechsel das Richtige, wenn die
gespeicherten Namen aus der falschen Zone stammen.

Gecacht wird **nur rückwärts**. Ein veralteter Name an einer Adresse
beschriftet falsch, mehr nicht; eine veraltete Adresse zu einem Namen würde den
Tracker den falschen Pfad prüfen lassen, ohne dass es auffiele. Ein Ausfall der
Tabelle kostet nie mehr als den Cache-Vorteil: gelesen und geschrieben wird
fehlertolerant, gefragt wird dann eben wieder direkt.

Die **Einstellungen** tragen dieselbe Seitenleiste wie Tracker und Network
Tools, gruppiert nach *Datenquellen · Zeichnungen · Standorte · Zugang* —
zwölf Panels untereinander waren eine Scrollstrecke.

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

### draw.io selbst hosten (für den Netzplan)

Die `.drawio`-Dateien des Netzplans gehören nicht auf app.diagrams.net. Eine
eigene Instanz im OT ist ein Container ohne Build — es zählt nur der
**Daemon-Proxy** für den Image-Pull (siehe unten), zur Laufzeit ruft draw.io
nichts nach außen:

```yaml
services:
  drawio:
    image: jgraph/drawio:latest        # nach dem ersten Lauf Version festnageln
    container_name: a38-drawio
    restart: unless-stopped
    ports: ["8780:8080"]
    environment:
      DRAWIO_BASE_URL: "http://svo3041-ot:8780"
```

Danach in A38 unter *Einstellungen → draw.io* die Basis-URL eintragen; der
Netzplan zeigt dann **„In draw.io öffnen"** (das Diagramm geht per URL-Hash in
den Browser, kein Upload). PDF, PNG und SVG exportiert draw.io dort selbst über
*Datei → Exportieren als* — der frühere separate Export-Server ist abgekündigt
und wird nicht mehr gebraucht.

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
- **Geräte-Zonen** (`config system zone`, je VDOM aus der Geräte-DB des FMG):
  das normalisierte Interface `Transfer` mappt per Gerät oft auf die
  **gleichnamige Zone auf der FortiGate**, und erst die kennt das physische
  Member `L3-WAN0`. Ohne diese Tabelle bridged der Kandidatenfilter nicht von
  Routing-Interface zu Policy-Zone, und der Tracker zeigt `L3-WAN0` statt
  `Transfer`. Aliase werden transitiv aufgelöst (Interface → Geräte-Zone →
  normalisiertes Interface). Meldet die FortiGate live *Policy 0*, obwohl der
  Cache eine passende Accept-Regel kennt, wird genau diese Regel genannt —
  typisch für ein nicht (vollständig) installiertes Package.
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

### Wenn der Host gerade aus ist — IP↔MAC-Historie

Ein abgeschalteter Host bricht die Suche **nicht** am Port, sondern eine Stufe
davor: LibreNMS hält seinen FDB-Eintrag noch tagelang vor (`ports_fdb_purge`,
Default 10 Tage), aber ohne IP→MAC kommt die Kette dort nie an. Die FortiGate
verwirft ARP-Einträge binnen Minuten, und LibreNMS gleicht seine `ipv4_mac`-
Tabelle bei jeder Discovery mit dem Gerät ab — beide Quellen kennen nur die
Gegenwart.

Deshalb zeichnet der Tracker die Bindungen auf (Tabelle `arp_history`):

| Quelle | Wann |
|---|---|
| ARP-Sweep über alle FortiGate-VDOMs mit connected Netz | alle `arp_sweep_interval_s` (Default 15 min) |
| jede Switchport-Suche nebenbei | die Monitor-Antwort enthält ohnehin die ganze ARP-Tabelle des VDOMs |

Findet keine Live-Quelle eine MAC, greift die zuletzt aufgezeichnete Bindung.
Das Ergebnis wird dann **deutlich als Aufzeichnung gekennzeichnet** (Zeitpunkt,
Alter, aufzeichnendes Gerät), die Konfidenz nie höher als `medium` — der Port
beschreibt den letzten bekannten Stand, nicht den aktuellen Aufenthalt.

Standen an einer IP nacheinander mehrere MACs (Gerätetausch, Neuvergabe), gewinnt
die zuletzt gesehene, und die anderen werden genannt statt verschwiegen. Der
vollständige Verlauf je IP ist ausklappbar.

Aufbewahrung `arp_retention_days` (Default 180), Bestand und letzter Lauf unter
**Einstellungen → LibreNMS**. Bewusst *kein* Spiegel der FDB: Der Cache
überbrückt nur, was die Live-Quellen vergessen — sonst gäbe es zwei Bestände,
die auseinanderlaufen. Reicht die 10-Tage-Grenze von LibreNMS nicht, ist
`ports_fdb_purge` dort hochzusetzen die günstigere Antwort.

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
`/sys/proxy/json`; vdom-link-Erkennung (`<base>0/<base>1` + Typ); Filter-
Verhalten von `firewall/session` (der generische `filter=`-Ausdruck wird für
diese Tabelle laut Fortinet-KB FD224183 ignoriert, die dedizierten Parameter
`srcaddr`/`dstaddr`/`dstport`/`protocol` greifen erst auf neueren Builds —
der Tracker filtert deshalb immer zusätzlich clientseitig und markiert im
Ergebnis, ob das Gerät gefiltert hat und ob die Liste abgeschnitten war).

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
