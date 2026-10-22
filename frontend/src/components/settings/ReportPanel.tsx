import { useEffect, useState } from 'react';
import { getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

const WEEKDAYS = ['Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'];

export default function ReportPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [groups, setGroups] = useState('');

  useEffect(() => {
    getConfig('report').then((c) => {
      setCfg(c);
      setGroups(((c.privileged_groups as string[] | undefined) ?? []).join(', '));
    });
  }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    try {
      const list = groups.split(',').map((g) => g.trim()).filter(Boolean);
      setCfg(await patchConfig('report', { ...cfg, privileged_groups: list.length ? list : null }));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.report}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.reportHint}</p>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={Boolean(cfg.enabled)}
          onChange={(e) => set('enabled', e.target.checked)} />
        {de.settings.reportEnabled}
      </label>
      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.reportWeekday}</label>
          <select className="fwpt-input" value={Number(cfg.weekday ?? 4)}
            onChange={(e) => set('weekday', Number(e.target.value))}>
            {WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.reportTime}</label>
          <input className="fwpt-input" type="time" value={(cfg.time as string) ?? '06:30'}
            onChange={(e) => set('time', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.reportWorkHours}</label>
          <input className="fwpt-input" value={(cfg.work_hours as string) ?? '06-20'} placeholder="06-20"
            onChange={(e) => set('work_hours', e.target.value)} />
        </div>
        <div className="sm:col-span-3">
          <label className="mb-1 block text-xs text-slate-400">{de.settings.reportGroups}</label>
          <input className="fwpt-input" value={groups} placeholder="Domain Admins, Enterprise Admins, …"
            onChange={(e) => setGroups(e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">{de.settings.reportFazFilter}</label>
          <input className="fwpt-input font-mono text-xs" value={(cfg.faz_change_filter as string) ?? 'subtype==system'}
            onChange={(e) => set('faz_change_filter', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.reportRetention}</label>
          <input className="fwpt-input" type="number" min={30} value={Number(cfg.retention_days ?? 365)}
            onChange={(e) => set('retention_days', Number(e.target.value))} />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save}>{de.settings.save}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
