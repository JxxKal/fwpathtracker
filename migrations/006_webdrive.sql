-- Webdrive-Dashboard: normierte Ereignisse aus FAC- und OpenCloud-Logs (via
-- Graylog), dauerhafte Zuordnung OpenCloud-ID → Username, Abfrage-Stand.
-- Gespeichert werden nur Ereignisse, keine Rohzeilen (docs/planung-webdrive-dashboard.md).

CREATE TABLE IF NOT EXISTS webdrive_event (
    id         BIGSERIAL PRIMARY KEY,
    gl_id      TEXT NOT NULL UNIQUE,      -- Graylog-Nachrichten-ID, gegen Doppelte
    ts         TIMESTAMPTZ NOT NULL,
    source     TEXT NOT NULL,             -- 'fac' | 'oc'
    kind       TEXT NOT NULL,
    username   TEXT,
    token      TEXT,
    opaque_id  TEXT,
    data       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS webdrive_event_ts ON webdrive_event (ts);

-- Lebt länger als die Ereignisse: eine OpenCloud-Identität ändert sich nicht.
CREATE TABLE IF NOT EXISTS webdrive_identity (
    opaque_id  TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS webdrive_poll (
    id           INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    polled_until TIMESTAMPTZ,
    last_ok      TIMESTAMPTZ,
    last_error   TEXT,
    stats        JSONB NOT NULL DEFAULT '{}'
);

INSERT INTO system_config (key, value) VALUES ('webdrive', '{
  "base_url": "", "token": "", "ssl_verify": true, "timeout_s": 20,
  "stream_id": "", "fac_query": "", "oc_query": "",
  "oc_ip": "10.180.18.69", "sync_rule": "Webdrive-User",
  "active_window_min": 15, "poll_interval_s": 60, "retention_days": 7
}') ON CONFLICT (key) DO NOTHING;
