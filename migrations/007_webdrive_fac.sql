-- Webdrive-Dashboard: Userliste aus der FortiAuthenticator-REST-API
-- (/api/v1/ldapusers/), damit fehlende AD-Attribute vor der Erstanmeldung
-- auffallen. Vorhandene Werte bleiben erhalten (Defaults links vom ||).
UPDATE system_config
SET value = '{"fac_url": "", "fac_user": "", "fac_api_key": "", "fac_ssl_verify": true,
              "fac_dn_filter": ""}'::jsonb || value
WHERE key = 'webdrive';
