import { CheckCircle2, Download, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, patchConfig, winInvImport, winInvTest } from '../../api';
import { de } from '../../i18n/de';

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString('de-DE') : '—');

export default function WinInvPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const t = de.settings.wininv;

  useEffect(() => { getConfig('wininv').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('wininv', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function run(kind: 'test' | 'import') {
    setBusy(true);
    setTest(null);
    try {
      if (kind === 'test') {
        const r = await winInvTest();
        const kinds = Object.entries(r.kinds).map(([k, n]) => `${k} ${n}`).join(', ');
        setTest({ ok: r.files > 0, text: t.testResult(r.files, r.hosts, fmt(r.oldest), fmt(r.newest))
          + (kinds ? ` (${kinds})` : '')
          + (r.sample ? ` · Probe: ${r.sample.hostname}, ${r.sample.os ?? '?'}, ${r.sample.ips.join(', ') || 'ohne IP'}` : '')
          + (r.foreign ? ` · ${r.foreign} andere Dateien ignoriert` : '') });
      } else {
        const r = await winInvImport();
        setTest({ ok: !(r.errors ?? []).length,
          text: t.importResult(r.files ?? 0, r.hosts ?? 0, r.read ?? 0, r.changed ?? 0)
            + ((r.errors ?? []).length ? ` · Fehler: ${(r.errors ?? []).slice(0, 3).join('; ')}` : '') });
      }
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  const num = (k: string, d: number) => (cfg[k] as number | undefined) ?? d;
  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{t.title}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{t.hint}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">{t.path}</label>
          <input className="fwpt-input font-mono" value={(cfg.path as string) ?? ''}
            placeholder="\\svo3001-ot\Inventory$" onChange={(e) => set('path', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.user}</label>
          <input className="fwpt-input" value={(cfg.username as string) ?? ''}
            placeholder="OP-TECH\svc.a38-inventory" autoComplete="off"
            onChange={(e) => set('username', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.password}</label>
          <input className="fwpt-input" type="password" value={(cfg.password as string) ?? ''}
            autoComplete="new-password" onChange={(e) => set('password', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.interval}</label>
          <input className="fwpt-input" type="number" min={15} value={num('interval_min', 60)}
            onChange={(e) => set('interval_min', Number(e.target.value))} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.stale}</label>
          <input className="fwpt-input" type="number" min={1} value={num('stale_days', 3)}
            onChange={(e) => set('stale_days', Number(e.target.value))} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.history}</label>
          <input className="fwpt-input" type="number" min={30} value={num('history_days', 400)}
            onChange={(e) => set('history_days', Number(e.target.value))} />
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.enabled as boolean) ?? false}
          onChange={(e) => set('enabled', e.target.checked)} />
        {t.enabled}
      </label>
      <p className="text-xs text-amber-400/90">{t.trust}</p>
      {test && (
        <div className={`flex items-start gap-2 text-sm ${test.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {test.ok ? <CheckCircle2 size={16} className="mt-0.5 shrink-0" /> : <XCircle size={16} className="mt-0.5 shrink-0" />}
          <span>{test.text}</span>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={() => run('test')} disabled={busy}>{de.settings.test}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={() => run('import')} disabled={busy}>
          <Download size={14} /> {t.importNow}
        </button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
