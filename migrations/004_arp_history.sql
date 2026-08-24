-- IP↔MAC-Historie: die Brücke zu Hosts, die gerade offline sind.
--
-- Die Switchport-Suche bricht bei einem abgeschalteten Host nicht am Port ab,
-- sondern eine Stufe davor: LibreNMS hält den FDB-Eintrag noch (ports_fdb_purge,
-- Default 10 Tage), aber ohne IP→MAC kommt die Kette gar nicht erst dorthin.
-- ARP altert auf der FortiGate binnen Minuten, und LibreNMS gleicht seine
-- ipv4_mac-Tabelle bei jeder Discovery mit dem Gerät ab — beide Quellen
-- vergessen also sofort. Genau diese Bindung wird hier aufbewahrt.
--
-- Ein Eintrag je (ip, mac): first_seen/last_seen spannen den Zeitraum auf, in
-- dem diese Bindung galt. Mehrere Zeilen zur selben IP sind kein Fehler,
-- sondern der Verlauf — bei einem Gerätetausch hängt an derselben IP später
-- eine andere MAC.
CREATE TABLE IF NOT EXISTS arp_history (
    ip          text        NOT NULL,
    mac         text        NOT NULL,   -- normalisiert: 12 Hex-Zeichen, klein
    device      text,                   -- FortiGate/Quelle, die es gesehen hat
    vdom        text,
    interface   text,
    source      text        NOT NULL,   -- fortigate | librenms | locate
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    seen_count  integer     NOT NULL DEFAULT 1,
    PRIMARY KEY (ip, mac)
);

-- Rückwärtssuche (welche IPs hatte diese MAC) und das Aufräumen alter Zeilen.
CREATE INDEX IF NOT EXISTS arp_history_mac_idx       ON arp_history (mac);
CREATE INDEX IF NOT EXISTS arp_history_last_seen_idx ON arp_history (last_seen);

-- arp_sweep_interval_s  Takt des ARP-Sweeps über alle FortiGate-VDOMs. Die
--                       ARP-Tabelle der FortiGate hält Einträge nur Minuten,
--                       deshalb deutlich enger als der FMG-Sync. <= 0 → aus.
-- arp_retention_days    Aufbewahrung der Bindungen. Danach ist die Aussage so
--                       alt, dass sie mehr schadet als hilft.
UPDATE system_config
   SET value = value || '{"arp_sweep_interval_s": 900, "arp_retention_days": 180}'::jsonb
 WHERE key = 'tracker';
