import { CheckCircle2, KeyRound, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fetchSamlConfig, saveSamlConfig } from '../../api';
import { de } from '../../i18n/de';
import type { SamlConfig } from '../../types';

const DEFAULTS: SamlConfig = {
  enabled: false,
  idp_entity_id: '', idp_sso_url: '', idp_slo_url: '', idp_x509_cert: '',
  sp_entity_id: '', acs_url: '', slo_url: '',
  attribute_username: 'uid', attribute_email: 'email',
  attribute_display_name: 'displayName', default_role: 'viewer',
};

// IdP-Metadaten-XML im Browser parsen → befüllt die IdP-Felder.
function parseIdpMetadataXml(xml: string): Partial<SamlConfig> {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  if (doc.querySelector('parsererror')) throw new Error('Ungültiges XML.');
  const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
  const DS = 'http://www.w3.org/2000/09/xmldsig#';
  const ed = doc.getElementsByTagNameNS(MD, 'EntityDescriptor')[0]
    || doc.documentElement;
  const out: Partial<SamlConfig> = {};
  const entityId = ed?.getAttribute('entityID');
  if (entityId) out.idp_entity_id = entityId;

  const pick = (tag: string, bindingEnds: string) => {
    const els = Array.from(doc.getElementsByTagNameNS(MD, tag));
    const match = els.find((e) => (e.getAttribute('Binding') || '').endsWith(bindingEnds));
    return (match || els[0])?.getAttribute('Location') || '';
  };
  const sso = pick('SingleSignOnService', 'HTTP-Redirect');
  const slo = pick('SingleLogoutService', 'HTTP-POST');
  if (sso) out.idp_sso_url = sso;
  if (slo) out.idp_slo_url = slo;

  const cert = doc.getElementsByTagNameNS(DS, 'X509Certificate')[0];
  if (cert?.textContent) out.idp_x509_cert = cert.textContent.replace(/\s+/g, '');
  if (!out.idp_entity_id && !out.idp_sso_url) throw new Error('Keine IdP-Felder im XML gefunden.');
  return out;
}

export default function SamlPanel() {
  const [cfg, setCfg] = useState<SamlConfig>(DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [xml, setXml] = useState('');
  const [showCert, setShowCert] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    fetchSamlConfig().then(setCfg).catch(() => {}).finally(() => setLoading(false));
  }, []);

  function flash(ok: boolean, text: string) {
    setMsg({ ok, text });
    setTimeout(() => setMsg(null), 5000);
  }
  const set = (k: keyof SamlConfig, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  function importXml() {
    try {
      setCfg((c) => ({ ...c, ...parseIdpMetadataXml(xml) }));
      setXml('');
      flash(true, 'IdP-Metadaten importiert.');
    } catch (e) {
      flash(false, e instanceof Error ? e.message : 'Parse-Fehler.');
    }
  }

  async function save() {
    setBusy(true);
    try {
      await saveSamlConfig(cfg);
      flash(true, de.settings.saved);
    } catch (e) {
      flash(false, e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  const inp = (label: string, key: keyof SamlConfig, ph = '') => (
    <div>
      <label className="mb-1 block text-xs text-slate-400">{label}</label>
      <input className="fwpt-input font-mono text-xs" placeholder={ph}
        value={String(cfg[key] ?? '')} onChange={(e) => set(key, e.target.value)} />
    </div>
  );

  if (loading) return <div className="fwpt-card text-sm text-slate-500">Lädt …</div>;

  return (
    <div className="fwpt-card space-y-4">
      <div className="flex items-center gap-2">
        <KeyRound size={16} className="text-purple-400" />
        <h2 className="font-medium text-slate-100">{de.settings.saml}</h2>
        <label className="ml-auto flex cursor-pointer items-center gap-2 text-xs">
          <input type="checkbox" checked={cfg.enabled}
            onChange={(e) => set('enabled', e.target.checked)} />
          <span className={cfg.enabled ? 'font-medium text-purple-300' : 'text-slate-500'}>
            SAML aktiviert
          </span>
        </label>
      </div>

      {/* IdP-Metadaten importieren */}
      <div className="rounded border border-slate-700/60 bg-slate-950/50 p-3 space-y-2">
        <p className="text-xs font-medium text-slate-300">IdP-Metadaten importieren</p>
        <p className="text-[11px] text-slate-500">
          XML aus dem IdP (z.B. FortiAuthenticator) einfügen — füllt die IdP-Felder automatisch.
        </p>
        <textarea className="fwpt-input h-24 w-full resize-none font-mono text-[11px]"
          placeholder={'<?xml version="1.0"?>\n<md:EntityDescriptor …'}
          value={xml} onChange={(e) => setXml(e.target.value)} />
        <button type="button" className="fwpt-btn-ghost text-xs" disabled={!xml.trim()} onClick={importXml}>
          XML parsen &amp; Felder befüllen
        </button>
      </div>

      <div className={cfg.enabled ? 'space-y-4' : 'space-y-4 opacity-50'}>
        {/* IdP */}
        <div>
          <p className="mb-2 text-xs font-medium text-slate-400">Identity Provider (IdP)</p>
          <div className="grid gap-3 sm:grid-cols-2">
            {inp('Entity-ID des IdP', 'idp_entity_id', 'http://idp.firma.de/saml/metadata')}
            {inp('SSO-URL (HTTP-Redirect)', 'idp_sso_url', 'http://idp.firma.de/saml/login/')}
            {inp('SLO-URL (Logout)', 'idp_slo_url', 'http://idp.firma.de/saml/logout/')}
          </div>
          <div className="mt-3">
            <div className="flex items-center justify-between">
              <label className="text-xs text-slate-400">X.509-Zertifikat des IdP (Base64)</label>
              <button type="button" className="text-[10px] text-slate-500 hover:text-slate-300"
                onClick={() => setShowCert((v) => !v)}>{showCert ? 'Verbergen' : 'Zeigen'}</button>
            </div>
            {showCert
              ? <textarea className="fwpt-input h-20 w-full resize-none font-mono text-[11px]"
                  value={cfg.idp_x509_cert} onChange={(e) => set('idp_x509_cert', e.target.value)} />
              : <p className="truncate font-mono text-[11px] text-slate-600">
                  {cfg.idp_x509_cert ? `${cfg.idp_x509_cert.slice(0, 60)}…` : '(nicht gesetzt)'}
                </p>}
          </div>
        </div>

        {/* SP */}
        <div>
          <p className="mb-2 text-xs font-medium text-slate-400">
            Service Provider (SP) — diese Werte beim IdP eintragen
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs text-slate-400">SP Entity-ID (Basis-URL)</label>
              <input className="fwpt-input font-mono text-xs" placeholder="https://tracker.firma.de"
                value={cfg.sp_entity_id}
                onChange={(e) => {
                  const base = e.target.value.replace(/\/$/, '');
                  setCfg((c) => ({
                    ...c, sp_entity_id: e.target.value,
                    acs_url: base ? `${base}/api/auth/saml/acs` : c.acs_url,
                    slo_url: base ? `${base}/api/auth/saml/sls` : c.slo_url,
                  }));
                }} />
            </div>
            {inp('ACS-URL (Login)', 'acs_url')}
            {inp('SLS-URL (Logout)', 'slo_url')}
          </div>
          {cfg.sp_entity_id && (
            <a className="mt-2 inline-block text-xs text-cyan-400 hover:underline"
              href="/api/auth/saml/metadata">↓ SP-Metadata XML herunterladen</a>
          )}
        </div>

        {/* Attribut-Mapping */}
        <div>
          <p className="mb-2 text-xs font-medium text-slate-400">Attribut-Mapping</p>
          <div className="grid gap-3 sm:grid-cols-3">
            {inp('Benutzername-Attribut', 'attribute_username', 'uid')}
            {inp('E-Mail-Attribut', 'attribute_email', 'email')}
            {inp('Anzeigename-Attribut', 'attribute_display_name', 'displayName')}
          </div>
          <div className="mt-3 w-48">
            <label className="mb-1 block text-xs text-slate-400">Standard-Rolle neuer SAML-User</label>
            <select className="fwpt-input" value={cfg.default_role}
              onChange={(e) => set('default_role', e.target.value)}>
              <option value="viewer">viewer</option>
              <option value="admin">admin</option>
            </select>
          </div>
        </div>
      </div>

      {msg && (
        <div className={`flex items-start gap-2 text-sm ${msg.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {msg.ok ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <span>{msg.text}</span>
        </div>
      )}

      <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>
        {de.settings.save}
      </button>
    </div>
  );
}
