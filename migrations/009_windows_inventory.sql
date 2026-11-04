-- Windows-Inventar (CSV-Dateien des Collector-Skripts aus einer SMB-Freigabe).
--
-- win_inventory: der aktuelle Stand je Host und Art (eine Datei).
-- win_inventory_history: jeder abweichende Inhalt mit dem Zeitpunkt, ab dem er
-- galt — daraus entsteht „was hat sich geändert" für den Wochenreport.
CREATE TABLE IF NOT EXISTS win_inventory (
    hostname   text        NOT NULL,
    kind       text        NOT NULL,
    file_name  text        NOT NULL,
    file_size  bigint      NOT NULL,
    file_mtime timestamptz NOT NULL,
    sha256     text        NOT NULL,
    rows       jsonb       NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    checked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (hostname, kind)
);

CREATE TABLE IF NOT EXISTS win_inventory_history (
    id         bigserial   PRIMARY KEY,
    hostname   text        NOT NULL,
    kind       text        NOT NULL,
    sha256     text        NOT NULL,
    file_mtime timestamptz NOT NULL,
    rows       jsonb       NOT NULL,
    valid_from timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS win_inventory_history_host_idx
    ON win_inventory_history (hostname, kind, valid_from DESC);
CREATE INDEX IF NOT EXISTS win_inventory_history_time_idx
    ON win_inventory_history (valid_from DESC);

INSERT INTO system_config (key, value) VALUES ('wininv',
    '{"enabled": false, "path": "", "username": "", "password": "", "interval_min": 60,
      "stale_days": 3, "history_days": 400}'::jsonb)
ON CONFLICT (key) DO NOTHING;
