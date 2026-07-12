import { CheckCircle2, Lock, XCircle } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import {
  fetchSslStatus, getSslHostname, setSslHostname,
  sslSelfSigned, uploadSslCert, uploadSslPfx,
} from '../../api';
import { de } from '../../i18n/de';
import type { SslStatus } from '../../types';

type Mode = 'self-signed' | 'upload';
type UploadFormat = 'pem' | 'pfx';

export default function SslPanel() {
  const [status, setStatus] = useState<SslStatus>({ mode: 'none', active: false });
  const [hostname, setHostname] = useState('');
  const [mode, setMode] = useState<Mode>('self-signed');
  const [fmt, setFmt] = useState<UploadFormat>('pem');
  const [ss, setSs] = useState({ common_name: '', days: 365, country: 'DE', org: 'FW Path Tracker' });
  const [pfxPassword, setPfxPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const certRef = useRef<HTMLInputElement>(null);
  const keyRef = useRef<HTMLInputElement>(null);
  const caRef = useRef<HTMLInputElement>(null);
  const pfxRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetchSslStatus().then((s) => {
      setStatus(s);
      if (s.mode !== 'none') setMode(s.mode === 'upload' ? 'upload' : 'self-signed');
      if (s.hostname) setHostname(s.hostname);
    }).catch(() => {});
    getSslHostname().then((h) => h.hostname && setHostname(h.hostname)).catch(() => {});
  }, []);

  function flash(ok: boolean, text: string) {
    setMsg({ ok, text });
    setTimeout(() => setMsg(null), 6000);
  }

  async function saveHostname() {
    setBusy(true);
    try {
      await setSslHostname(hostname.trim());
      flash(true, 'Hostname gespeichert — nginx übernimmt ihn beim nächsten Reload (~10 s).');
    } catch (e) {
      flash(false, e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  async function apply() {
    setBusy(true);
    setMsg(null);
    try {
      let s: SslStatus;
      if (mode === 'self-signed') {
        if (!ss.common_name.trim()) { flash(false, 'Common Name (CN) ist erforderlich.'); return; }
        s = await sslSelfSigned(ss);
      } else if (fmt === 'pfx') {
        const pfx = pfxRef.current?.files?.[0];
        if (!pfx) { flash(false, 'PFX-Datei ist erforderlich.'); return; }
        s = await uploadSslPfx(pfx, pfxPassword);
      } else {
        const cert = certRef.current?.files?.[0];
        const key = keyRef.current?.files?.[0];
        if (!cert || !key) { flash(false, 'Zertifikat und Schlüssel sind erforderlich.'); return; }
        s = await uploadSslCert(cert, key, caRef.current?.files?.[0] ?? null);
      }
      setStatus(s);
      flash(true, 'Zertifikat gespeichert — nginx aktiviert HTTPS beim nächsten Reload (~10 s).');
    } catch (e) {
      flash(false, e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  const tab = (m: Mode, label: string) => (
    <button type="button" onClick={() => setMode(m)}
      className={`rounded px-3 py-1 text-xs ${mode === m ? 'bg-cyan-600 text-white' : 'bg-slate-800 text-slate-400'}`}>
      {label}
    </button>
  );

  return (
    <div className="fwpt-card space-y-4">
      <div className="flex items-center gap-2">
        <Lock size={16} className="text-cyan-400" />
        <h2 className="font-medium text-slate-100">{de.settings.ssl}</h2>
        <span className={`ml-auto rounded-full px-2 py-0.5 text-[11px] font-medium ${
          status.active ? 'bg-emerald-900/70 text-emerald-300' : 'bg-slate-800 text-slate-400'
        }`}>
          {status.active ? 'TLS aktiv' : 'Kein TLS'}
        </span>
      </div>

      {/* Hostname */}
      <div>
        <label className="mb-1 block text-xs text-slate-400">Server-Hostname (nginx server_name)</label>
        <div className="flex gap-2">
          <input className="fwpt-input flex-1" value={hostname}
            placeholder="tracker.firma.de oder 192.168.1.230"
            onChange={(e) => setHostname(e.target.value)} />
          <button type="button" className="fwpt-btn-ghost" onClick={saveHostname} disabled={busy}>
            {de.settings.save}
          </button>
        </div>
      </div>

      {/* Aktives Zertifikat */}
      {status.active && (
        <div className="rounded border border-slate-700 bg-slate-950/60 p-3 text-xs text-slate-400 space-y-1">
          <p><span className="text-slate-500">Subject:</span> <span className="font-mono text-slate-300">{status.subject}</span></p>
          {status.issuer && <p><span className="text-slate-500">Issuer:</span> <span className="font-mono text-slate-300">{status.issuer}</span></p>}
          {status.not_after && <p><span className="text-slate-500">Gültig bis:</span> {new Date(status.not_after).toLocaleString()}</p>}
          {status.domains && <p><span className="text-slate-500">Domains:</span> {status.domains.join(', ')}</p>}
          <p><span className="text-slate-500">Modus:</span> {status.mode}</p>
        </div>
      )}

      {/* Modus-Tabs */}
      <div className="flex gap-2">
        {tab('self-signed', 'Self-Signed generieren')}
        {tab('upload', 'Zertifikat hochladen')}
      </div>

      {mode === 'self-signed' && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs text-slate-400">Common Name (CN) / Hostname *</label>
            <input className="fwpt-input" value={ss.common_name} placeholder="tracker.firma.de"
              onChange={(e) => setSs({ ...ss, common_name: e.target.value })} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Gültigkeit (Tage)</label>
            <input className="fwpt-input" inputMode="numeric" value={ss.days}
              onChange={(e) => setSs({ ...ss, days: Number(e.target.value) || 365 })} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Land (2-stellig)</label>
            <input className="fwpt-input" value={ss.country}
              onChange={(e) => setSs({ ...ss, country: e.target.value })} />
          </div>
          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs text-slate-400">Organisation</label>
            <input className="fwpt-input" value={ss.org}
              onChange={(e) => setSs({ ...ss, org: e.target.value })} />
          </div>
        </div>
      )}

      {mode === 'upload' && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <button type="button" onClick={() => setFmt('pem')}
              className={`rounded px-2 py-0.5 text-[11px] ${fmt === 'pem' ? 'bg-slate-700 text-slate-100' : 'bg-slate-800 text-slate-500'}`}>PEM</button>
            <button type="button" onClick={() => setFmt('pfx')}
              className={`rounded px-2 py-0.5 text-[11px] ${fmt === 'pfx' ? 'bg-slate-700 text-slate-100' : 'bg-slate-800 text-slate-500'}`}>PFX / PKCS#12</button>
          </div>
          {fmt === 'pem' ? (
            <div className="space-y-2 text-xs text-slate-400">
              <label className="block">Zertifikat (cert.pem) *
                <input ref={certRef} type="file" accept=".pem,.crt,.cer" className="mt-1 block w-full text-slate-300" /></label>
              <label className="block">Privater Schlüssel (key.pem) *
                <input ref={keyRef} type="file" accept=".pem,.key" className="mt-1 block w-full text-slate-300" /></label>
              <label className="block">CA-Chain (optional)
                <input ref={caRef} type="file" accept=".pem,.crt,.cer" className="mt-1 block w-full text-slate-300" /></label>
            </div>
          ) : (
            <div className="space-y-2 text-xs text-slate-400">
              <label className="block">PFX-Datei *
                <input ref={pfxRef} type="file" accept=".pfx,.p12" className="mt-1 block w-full text-slate-300" /></label>
              <label className="block">Passwort (leer lassen wenn keins)
                <input type="password" className="fwpt-input mt-1" value={pfxPassword}
                  onChange={(e) => setPfxPassword(e.target.value)} /></label>
            </div>
          )}
        </div>
      )}

      {msg && (
        <div className={`flex items-start gap-2 text-sm ${msg.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {msg.ok ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <span>{msg.text}</span>
        </div>
      )}

      <button type="button" className="fwpt-btn" onClick={apply} disabled={busy}>
        {busy ? 'Wird angewendet …' : 'Anwenden'}
      </button>
    </div>
  );
}
