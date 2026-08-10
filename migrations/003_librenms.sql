-- LibreNMS-Anbindung für die Switchport-Suche (IP → MAC → Port).
-- Deaktiviert, bis der Admin Base-URL und API-Token im UI einträgt.
--
-- access_max_macs  Bis zu so vielen MACs an einem Port gilt er als Access-Port.
--                  Darüber ist es ein Trunk/Ring-Uplink und der Treffer bekommt
--                  eine niedrigere Konfidenz.
-- stale_after_s    Ab diesem Alter ist ein FDB-Eintrag eine Vermutung. Default
--                  6 h = das Default-Discovery-Intervall von LibreNMS.
-- recency_bucket_s Innerhalb dieses Fensters gelten Treffer als gleich frisch.
--                  Sortiert wird primär nach Aktualität; ohne Bucketing würden
--                  gleichwertige Treffer durch Sekunden Versatz zwischen zwei
--                  Discovery-Läufen auseinandergerissen.
INSERT INTO system_config (key, value) VALUES
    ('librenms', '{"base_url": "", "token": "", "ssl_verify": true, "timeout_s": 20, "access_max_macs": 8, "stale_after_s": 21600, "recency_bucket_s": 3600}')
ON CONFLICT (key) DO NOTHING;
