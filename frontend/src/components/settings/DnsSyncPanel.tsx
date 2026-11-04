import { useEffect, useState } from 'react';
import { getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

const DAYS = ['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'];

export default function DnsSyncPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const t = de.settings.dnssync;
  useEffect(() => { getConfig('dnssync').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try { setCfg(await patchConfig('dnssync', cfg)); setStatus(de.settings.saved); }
    catch (e) { setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`); }
    finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{t.title}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{t.hint}</p>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.enabled as boolean) ?? false} onChange={(e) => set('enabled', e.target.checked)} />
        {t.enabled}
      </label>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.weekday}</label>
          <select className="fwpt-input" value={(cfg.weekday as number) ?? 0} onChange={(e) => set('weekday', Number(e.target.value))}>
            {DAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{t.time}</label>
          <input className="fwpt-input" type="time" value={(cfg.time as string) ?? '06:00'} onChange={(e) => set('time', e.target.value)} />
        </div>
      </div>
      <div className="space-y-2 rounded-md border border-amber-900/60 bg-amber-950/20 p-3">
        <label className="flex items-center gap-2 text-sm text-amber-200">
          <input type="checkbox" checked={(cfg.write_enabled as boolean) ?? false} onChange={(e) => set('write_enabled', e.target.checked)} />
          {t.writeEnabled}
        </label>
        <p className="text-xs text-slate-400">{t.writeHint}</p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label className="mb-1 block text-xs text-slate-400">{t.writeUser}</label>
            <input className="fwpt-input" value={(cfg.write_user as string) ?? ''} autoComplete="off" onChange={(e) => set('write_user', e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">{t.writePassword}</label>
            <input className="fwpt-input" type="password" autoComplete="new-password" value={(cfg.write_password as string) ?? ''} onChange={(e) => set('write_password', e.target.value)} />
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
