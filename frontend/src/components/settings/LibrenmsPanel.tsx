import { CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, librenmsRefresh, librenmsTest, patchConfig } from '../../api';
import { de } from '../../i18n/de';

export default function LibrenmsPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getConfig('librenms').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('librenms', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true);
    setTest(null);
    try {
      const r = await librenmsTest();
      setTest({ ok: true, text: `OK — LibreNMS ${r.version}, ${r.devices} Geräte` });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  async function refresh() {
    setBusy(true);
    setTest(null);
    try {
      await librenmsRefresh();
      setTest({ ok: true, text: de.settings.librenmsRefreshed });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.librenms}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.librenmsHint}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">Base-URL</label>
          <input className="fwpt-input" value={(cfg.base_url as string) ?? ''}
            placeholder="https://librenms.example.net"
            onChange={(e) => set('base_url', e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">
            API-Token (LibreNMS → Settings → API → API Access)
          </label>
          <input className="fwpt-input" type="password" value={(cfg.token as string) ?? ''}
            onChange={(e) => set('token', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">
            {de.settings.librenmsAccessMax}
          </label>
          <input className="fwpt-input" type="number" min={1}
            value={(cfg.access_max_macs as number) ?? 8}
            onChange={(e) => set('access_max_macs', Number(e.target.value))} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">
            {de.settings.librenmsStaleAfter}
          </label>
          <input className="fwpt-input" type="number" min={60} step={60}
            value={(cfg.stale_after_s as number) ?? 21600}
            onChange={(e) => set('stale_after_s', Number(e.target.value))} />
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.ssl_verify as boolean) ?? true}
          onChange={(e) => set('ssl_verify', e.target.checked)} />
        TLS-Zertifikat prüfen
      </label>
      {test && (
        <div className={`flex items-start gap-2 text-sm ${test.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {test.ok ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <span>{test.text}</span>
        </div>
      )}
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={runTest} disabled={busy}>{de.settings.test}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={refresh} disabled={busy}>
          <RefreshCw size={14} /> {de.settings.itopRefresh}
        </button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
