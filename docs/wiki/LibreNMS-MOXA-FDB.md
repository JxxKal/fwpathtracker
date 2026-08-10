# LibreNMS: FDB-Tabellen für MOXA-Switches aktivieren

> Voraussetzung für die Switchport-Suche im Tracker. Ohne diesen Fix liefern
> MOXA-Geräte genau **einen** FDB-Eintrag und sind damit für die Suche blind.

Verifiziert an **LibreNMS 26.6.1** (Docker) mit **MOXA IKS-G6524A-8GSFP-4GTXSFP-T**,
sysObjectID `.1.3.6.1.4.1.8691.7.95`, OS-Zuweisung `moxa-etherdevice`.
HPE- und Hirschmann-Switches sind **nicht** betroffen — die liefern
`dot1qTpFdbTable` sauber über alle VLANs.

---

## Symptom

In LibreNMS steht bei jedem MOXA genau eine Zeile in `ports_fdb` — die MAC des
Switches selbst. Bei HPE und Hirschmann stehen dort Hunderte Einträge aus
mehreren VLANs.

## Ursache

Zwei Dinge greifen ineinander.

**1. Die MOXA-Firmware implementiert `Q-BRIDGE-MIB::dot1qTpFdbTable` als Stub.**
Die Tabelle antwortet, enthält aber nur einen einzigen Eintrag für `fdbId 1`:

```console
$ snmpwalk -v2c -c <community> <moxa> 1.3.6.1.2.1.17.7.1.2.2.1.2
iso.3.6.1.2.1.17.7.1.2.2.1.2.1.0.3.121.4.170.112 = INTEGER: 23
```

Die Basis-Objekte darunter sind dagegen korrekt gefüllt — das Gerät kennt
seine VLANs sehr wohl:

```console
$ snmpwalk -v2c -c <community> <moxa> 1.3.6.1.2.1.17.7.1.1
iso.3.6.1.2.1.17.7.1.1.1.0 = INTEGER: 1      # dot1qVlanVersionNumber
iso.3.6.1.2.1.17.7.1.1.2.0 = INTEGER: 4094   # dot1qMaxVlanId
iso.3.6.1.2.1.17.7.1.1.3.0 = INTEGER: 256    # dot1qMaxSupportedVlans
iso.3.6.1.2.1.17.7.1.1.4.0 = INTEGER: 37     # dot1qNumVlans
```

Die **vollständige** MAC-Tabelle steht in der alten BRIDGE-MIB — im Beispiel
rund 380 Einträge, eindeutig VLAN-übergreifend (VMware `00:50:56`/`00:0c:29`,
Siemens `08:00:06`/`00:1b:1b`/`00:0e:8c`, Moxa `00:90:e8`/`00:03:79`):

```console
$ snmpwalk -v2c -c <community> <moxa> 1.3.6.1.2.1.17.4.3.1.2 | wc -l
380
```

Das Bridge-Port-Mapping ist dabei der Idealfall — 1:1, Bridge-Port *n* = ifIndex *n*:

```console
$ snmpwalk -v2c -c <community> <moxa> 1.3.6.1.2.1.17.1.4.1.2
iso.3.6.1.2.1.17.1.4.1.2.1 = INTEGER: 1
…
iso.3.6.1.2.1.17.1.4.1.2.24 = INTEGER: 24
```

**2. LibreNMS' Fallback greift nicht.** In
`includes/discovery/fdb-table/bridge.inc.php` steht genau die richtige Logik —
aber mit einer zu strengen Bedingung:

```php
// Try Q-BRIDGE-MIB::dot1qTpFdbPort first
$fdbPort_table = snmpwalk_group($device, 'dot1qTpFdbPort', 'Q-BRIDGE-MIB');
if (! empty($fdbPort_table)) {          // ← ein Stub-Eintrag ist "nicht leer"
    $data_oid = 'dot1qTpFdbPort';
} else {
    // If we don't have Q-BRIDGE-MIB::dot1qTpFdbPort, try BRIDGE-MIB::dot1dTpFdbPort
    $dot1d = snmpwalk_group($device, 'dot1dTpFdbPort', 'BRIDGE-MIB', 0);
```

Ein Gerät, das die Q-BRIDGE-FDB als funktionslosen Stub implementiert, ist
darin nicht vorgesehen: die eine Zeile gilt als Erfolg, der BRIDGE-MIB-Zweig
wird nie erreicht.

Der Dispatcher `includes/discovery/fdb-table.inc.php` lädt vorrangig eine
OS-spezifische Datei `includes/discovery/fdb-table/{$device['os']}.inc.php`,
falls vorhanden — für `moxa-etherdevice` existiert keine, also landet alles bei
`bridge.inc.php`. Genau dort setzt der Fix an.

> **Hinweis:** `fdb-table` ist in dieser Version ein **Discovery**-Modul, kein
> Poller-Modul. Aufrufe mit `poller.php -m fdb-table` laufen ins Leere.

---

## Fix

Eine Zeile Core plus eine neue Datei. Die Logik aus `bridge.inc.php` wird
bewusst **nicht** dupliziert — MAC-Normalisierung, VLAN-Mapping und die
Längenbyte-Behandlung dort sind zu viel, um sie bei jedem Update nachzupflegen.

### 1. `includes/discovery/fdb-table/bridge.inc.php` (Zeile 32)

```diff
-$fdbPort_table = snmpwalk_group($device, 'dot1qTpFdbPort', 'Q-BRIDGE-MIB');
+$fdbPort_table = empty($skip_qbridge)
+    ? snmpwalk_group($device, 'dot1qTpFdbPort', 'Q-BRIDGE-MIB')
+    : [];
```

### 2. Neu: `includes/discovery/fdb-table/moxa-etherdevice.inc.php`

```php
<?php

/*
 * MOXA implementiert Q-BRIDGE-MIB::dot1qTpFdbTable als Stub (ein Eintrag).
 * Die vollständige MAC-Tabelle über alle VLANs steht in BRIDGE-MIB.
 * bridge.inc.php fällt nur bei *leerer* Q-BRIDGE-Antwort zurück, deshalb hier
 * überspringen. Konsequenz: Einträge landen ohne VLAN-Zuordnung unter vlan_id 0.
 */

$skip_qbridge = true;
require base_path('includes/discovery/fdb-table/bridge.inc.php');
```

Der Dispatcher lädt die OS-Datei zuerst; weil sie `$insert` füllt, greift das
nachgelagerte `if (empty($insert))` nicht mehr und `bridge.inc.php` wird kein
zweites Mal eingebunden. **Alle** MOXAs sind automatisch abgedeckt, weil sie
sich dasselbe OS teilen.

Dass die Einträge mit `vlan_id = 0` landen, ist gewollt: die VLAN-Information
kommt in der Switchport-Suche ohnehin von der ARP-Seite. Zwei Nebenwirkungen
sind zu kennen — die LibreNMS-Weboberfläche blendet die Zeilen je nach Ansicht
aus, und der API-Endpunkt `/resources/fdb/{mac}/detail` kann sie ebenfalls
verschlucken. Der Tracker nutzt deshalb `/resources/fdb/{mac}` und holt die
Portnamen getrennt über `/devices/{id}/ports`.

---

## Einbau in den Docker-Stack

`/opt/librenms` liegt **im Image**, nicht im `app-data`-Volume — die Änderung
überlebt ein Container-Recreate also nur als Image-Layer. Gegenprobe:

```bash
docker exec librenms ls -ld /opt/librenms/includes
```

Ist das ein echtes Verzeichnis und kein Symlink nach `/data`, gilt der Weg unten.

### Schritt 1 — Testen ohne Build

```bash
cd /home/administrator/librenms-moxamod/moxa-fdb

docker cp moxa-etherdevice.inc.php librenms:/opt/librenms/includes/discovery/fdb-table/
docker cp patch-fdb.sh librenms:/tmp/patch-fdb.sh
docker exec -u root librenms sh /tmp/patch-fdb.sh

docker exec -u librenms -w /opt/librenms librenms \
  ./lnms device:discover -m fdb-table -vv <moxa-ip> 2>&1 | tail -25
```

Erwartung: `BRIDGE-MIB: ` statt `Q-BRIDGE-MIB:`, gefolgt von einer langen Reihe
`+`. Überlebt einen Restart, aber kein Recreate.

### Schritt 2 — Dateien

`patch-fdb.sh`:

```sh
#!/bin/sh
# Macht den Q-BRIDGE-Walk in bridge.inc.php per $skip_qbridge abschaltbar.
# Bricht ab, wenn das Ziel nicht exakt einmal gefunden wird -- dann hat sich
# der Upstream-Code geändert und der Patch muss neu geprüft werden.
set -eu

d=/opt/librenms/includes/discovery/fdb-table
f="$d/bridge.inc.php"

old="\$fdbPort_table = snmpwalk_group(\$device, 'dot1qTpFdbPort', 'Q-BRIDGE-MIB');"
new="\$fdbPort_table = empty(\$skip_qbridge) ? snmpwalk_group(\$device, 'dot1qTpFdbPort', 'Q-BRIDGE-MIB') : [];"

awk -v old="$old" -v new="$new" '
    index($0, old) { $0 = new; n++ }
    { print }
    END { if (n != 1) { print "patch-fdb: erwartete genau 1 Treffer, gefunden " n+0 > "/dev/stderr"; exit 1 } }
' "$f" > "$f.patched"

mv "$f.patched" "$f"
chown librenms:librenms "$f" "$d/moxa-etherdevice.inc.php"
chmod 644 "$f" "$d/moxa-etherdevice.inc.php"

echo "patch-fdb: bridge.inc.php gepatcht, moxa-etherdevice.inc.php installiert"
```

`Dockerfile`:

```dockerfile
# LibreNMS mit MOXA-FDB-Fix, aufbauend auf dem vorhandenen SAML2-Image.
FROM librenms-saml2:latest

USER root

COPY moxa-etherdevice.inc.php /opt/librenms/includes/discovery/fdb-table/moxa-etherdevice.inc.php
COPY patch-fdb.sh /tmp/patch-fdb.sh

RUN sh /tmp/patch-fdb.sh && rm /tmp/patch-fdb.sh
```

```bash
docker build -t librenms-moxamod:latest /home/administrator/librenms-moxamod/moxa-fdb/
```

Der Build **schlägt fehl**, wenn `awk` das Zielmuster nicht exakt einmal
findet. Das ist Absicht: bei einem LibreNMS-Update, das `bridge.inc.php`
anfasst, merkst du es beim Bauen statt still im Betrieb.

### Schritt 3 — Stack

Nur die `image:`-Zeilen ändern sich:

| Service | vorher | nachher |
|---|---|---|
| `librenms` | `librenms-saml2:latest` | `librenms-moxamod:latest` |
| `dispatcher` | `librenms/librenms:latest` | `librenms-moxamod:latest` |
| `mscheduler` | `librenms/librenms:latest` | `librenms-moxamod:latest` |
| `syslogng` | `librenms/librenms:latest` | `librenms-moxamod:latest` |
| `snmptrapd` | `librenms/librenms:latest` | `librenms-moxamod:latest` |

`db`, `redis`, `msmtpd`, `librenms-proxy` und `oxidized` bleiben unverändert.

Zwingend nötig sind **`dispatcher`** (führt die Discovery aus) und `librenms`
(Weboberfläche, manuelle Aufrufe). Die übrigen drei ziehen mit, damit alle
LibreNMS-Container garantiert dieselbe Codebasis haben — vorher lief der
Mischbetrieb aus `librenms-saml2` und `librenms/librenms`, was bei
auseinanderlaufenden Versionen schwer greifbare Effekte erzeugt.

> **In Portainer beim Redeploy „Re-pull image" ausschalten.**
> `librenms-moxamod:latest` ist ein rein lokaler Tag; mit aktiviertem Re-pull
> versucht Portainer, ihn aus der Registry zu holen — was offline zwangsläufig
> scheitert.

---

## Verifikation

Patch im Dispatcher angekommen (zwei Treffer = passt):

```bash
docker exec librenms_dispatcher grep -n skip_qbridge \
  /opt/librenms/includes/discovery/fdb-table/bridge.inc.php \
  /opt/librenms/includes/discovery/fdb-table/moxa-etherdevice.inc.php
```

Einträge pro Gerät:

```bash
docker exec librenms_db sh -c 'mysql -N -B -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" \
  -e "SELECT device_id, COUNT(*) FROM ports_fdb GROUP BY device_id ORDER BY 2 DESC LIMIT 20"'
```

Verteilung auf die Ports eines MOXA:

```sql
SELECT p.ifName, COUNT(*) AS macs
FROM ports_fdb f JOIN ports p ON p.port_id = f.port_id
WHERE f.device_id = <id>
GROUP BY p.ifName ORDER BY macs DESC;
```

Erwartung: zwei Ports mit je ~180 MACs — die Ring-Uplinks — und darunter Ports
mit einer Handvoll. Genau diese Signatur nutzt die Switchport-Suche, um den
Access-Port vom Uplink zu trennen.

---

## Ausrollen

Discovery läuft pro Gerät, per Default alle 6 Stunden
(`lnms config:get discovery_interval`, Wert in Sekunden). Abwarten genügt —
der Fix sitzt im Image. Wer nicht warten will:

```bash
docker exec librenms_db sh -c 'mysql -N -B -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" \
  -e "SELECT hostname FROM devices WHERE os=\"moxa-etherdevice\" AND disabled=0"' \
| while read -r h; do
    echo "== $h"
    docker exec -u librenms -w /opt/librenms librenms_dispatcher ./lnms device:discover -m fdb-table "$h"
  done
```

Bewusst gegen `librenms_dispatcher` — damit ist gleich verifiziert, dass das
neue Image dort auch tatsächlich greift.

Wann die Geräte regulär dran sind:

```sql
SELECT hostname, last_discovered FROM devices
WHERE os = 'moxa-etherdevice' AND disabled = 0 ORDER BY last_discovered;
```

---

## Offene Punkte

- **Upstream.** Die Bedingung „Q-BRIDGE ist leer" ist zu streng; sinnvoller
  wäre ein Vergleich gegen die Zeilenzahl von `dot1dTpFdbTable`. Das wäre ein
  kleiner, gut begründbarer PR gegen LibreNMS — dann entfällt der Core-Patch.
- **Bridge-Port ohne Mapping.** Im Beispielgerät taucht in `dot1dTpFdbTable`
  ein Bridge-Port 33 auf, der nicht in `dot1dBasePortTable` steht. Für den gibt
  es keine Portauflösung; `bridge.inc.php` fängt das ab und loggt es, statt
  eine 0 zu schreiben. Ein paar Einträge fehlen dadurch — bislang ohne
  praktische Auswirkung.
- **Alterung.** FDB-Einträge altern auf den Switches in Minuten, LibreNMS
  discovert alle 6 Stunden. Ein Treffer sagt „dort war das Gerät beim letzten
  Discovery-Lauf". Die Switchport-Suche zeigt das Alter deshalb immer mit an
  und markiert alte Treffer.
