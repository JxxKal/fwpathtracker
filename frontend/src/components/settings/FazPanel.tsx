import { CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fazRefresh, fazTest, getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

export default function FazPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string; fields?: string[] } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getConfig('faz').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('faz', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true);
    setTest(null);
    try {
      const r = await fazTest();
      setTest({ ok: true, text: de.settings.fazTestOk(r.endpoints, r.hosts, r.with_mac, r.with_last_seen),
        fields: r.fields });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  async function refresh() {
    setBusy(true);
    setTest(null);
    try {
      await fazRefresh();
      setTest({ ok: true, text: de.settings.fazRefreshed });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.faz}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.fazHint}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">Base-URL</label>
          <input className="fwpt-input" value={(cfg.base_url as string) ?? ''}
            placeholder="https://faz.example.net"
            onChange={(e) => set('base_url', e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">API-Token</label>
          <input className="fwpt-input" type="password" value={(cfg.token as string) ?? ''}
            onChange={(e) => set('token', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.fazAdom}</label>
          <input className="fwpt-input" value={(cfg.adom as string) ?? 'root'}
            onChange={(e) => set('adom', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.fazMaxAge}</label>
          <input className="fwpt-input" type="number" min={0}
            value={(cfg.max_age_days as number) ?? 7}
            onChange={(e) => set('max_age_days', Number(e.target.value))} />
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
          <div>
            <span>{test.text}</span>
            {test.fields && test.fields.length > 0 && (
              <p className="mt-0.5 font-mono text-[11px] text-slate-500">
                {de.settings.fazFields}: {test.fields.join(', ')}
              </p>
            )}
          </div>
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
