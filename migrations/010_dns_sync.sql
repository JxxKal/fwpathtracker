-- iTop↔DNS-Abgleich: wöchentliche Vorschlagsliste, die ein Admin freigibt.
--
-- Ein Lauf hält seine Zeilen (items) samt Auswahl und nach dem Schreiben das
-- Ergebnis je Zeile — nachvollziehbar, wer was wann ins iTop geschrieben hat.
CREATE TABLE IF NOT EXISTS dns_sync_run (
    id          bigserial   PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    trigger     text        NOT NULL,             -- schedule | manual
    created_by  text,
    status      text        NOT NULL,             -- open | applied | partial | failed | discarded | superseded
    stats       jsonb       NOT NULL,
    items       jsonb       NOT NULL,
    decided_by  text,
    decided_at  timestamptz,
    result      jsonb
);

CREATE INDEX IF NOT EXISTS dns_sync_run_created_idx ON dns_sync_run (created_at DESC);

-- Adressobjekte, die dauerhaft nicht mehr vorgeschlagen werden.
CREATE TABLE IF NOT EXISTS dns_sync_ignore (
    ip_id      text        PRIMARY KEY,
    ip         text        NOT NULL,
    reason     text,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO system_config (key, value) VALUES ('dnssync',
    '{"enabled": false, "weekday": 0, "time": "06:00", "timezone": "Europe/Berlin",
      "write_enabled": false, "write_user": "", "write_password": ""}'::jsonb)
ON CONFLICT (key) DO NOTHING;
