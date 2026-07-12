-- SAML/SSO: users-Tabelle um Föderations-Felder erweitern + saml-Config-Default.
-- Bestehende (lokale) User bekommen source='local', active=true.

-- SAML-User haben kein Passwort → password_hash muss nullable sein.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

ALTER TABLE users ADD COLUMN IF NOT EXISTS email        TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS source       TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS active       BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login   TIMESTAMPTZ;

-- source auf lokal|saml einschränken (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_source_check'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT users_source_check
            CHECK (source IN ('local', 'saml'));
    END IF;
END $$;

-- SAML-Konfiguration (deaktiviert bis der Admin sie im UI einträgt).
INSERT INTO system_config (key, value) VALUES
    ('saml', '{"enabled": false, "default_role": "viewer", "attribute_username": "uid", "attribute_email": "email", "attribute_display_name": "displayName"}')
ON CONFLICT (key) DO NOTHING;
