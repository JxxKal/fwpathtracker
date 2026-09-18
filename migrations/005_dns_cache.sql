-- Reverse-DNS-Cache: Namen zu Adressen, damit A38 nicht bei jeder Zeichnung
-- dieselben hunderte Anfragen stellt.
--
-- Der eigentliche Kostenfaktor sind nicht die Treffer, sondern die
-- FEHLANZEIGEN: in einem OT-Netz hat die Mehrheit der Adressen keinen
-- PTR-Eintrag, und genau die laufen jedes Mal in die volle Zeitüberschreitung.
-- Deshalb wird auch „kein Eintrag" festgehalten (name IS NULL) — nur kürzer,
-- weil aus einer Fehlanzeige eher ein Eintrag wird als umgekehrt.
--
-- Gecacht wird ausdrücklich NUR die Rückwärtsrichtung. Ein veralteter Name an
-- einer Adresse beschriftet falsch; eine veraltete Adresse zu einem Namen
-- würde den Pfad-Tracker den falschen Weg prüfen lassen, ohne dass es auffällt.
CREATE TABLE IF NOT EXISTS dns_cache (
    ip          text        PRIMARY KEY,
    name        text,                   -- NULL = geprüft, kein PTR-Eintrag
    checked_at  timestamptz NOT NULL DEFAULT now(),
    first_seen  timestamptz NOT NULL DEFAULT now(),
    hits        integer     NOT NULL DEFAULT 0
);

-- Aufräumen nach Alter.
CREATE INDEX IF NOT EXISTS dns_cache_checked_idx ON dns_cache (checked_at);
