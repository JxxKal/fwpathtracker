-- Wochenreport „Stephan fragt, A38 antwortet" (docs/planung-wochenreport.md).
--
-- Gespeichert wird das AUSGEWERTETE Ergebnis (data), nicht nur eine Darstellung:
-- So lässt sich ein Bericht nach einer Layoutänderung neu rendern, und der
-- Vorwochenvergleich braucht keine Quelle mehr. Das PDF ist abgeleitet und
-- kann jederzeit neu erzeugt werden.
CREATE TABLE IF NOT EXISTS weekly_report (
    id           bigserial   PRIMARY KEY,
    period_start timestamptz NOT NULL,
    period_end   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    trigger      text        NOT NULL,      -- schedule | manual
    status       text        NOT NULL,      -- ok | partial | failed
    created_by   text,
    data         jsonb       NOT NULL,
    pdf          bytea,
    UNIQUE (period_start, period_end)
);

CREATE INDEX IF NOT EXISTS weekly_report_end_idx ON weekly_report (period_end DESC);

-- Zeitplan: Freitag 06:30 Europe/Berlin; enabled=false bis jemand ihn einschaltet.
INSERT INTO system_config (key, value) VALUES ('report',
    '{"enabled": false, "weekday": 4, "time": "06:30", "timezone": "Europe/Berlin",
      "retention_days": 365, "change_window": "", "faz_change_filter": "subtype==system"}'::jsonb)
ON CONFLICT (key) DO NOTHING;
