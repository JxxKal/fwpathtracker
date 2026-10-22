import { CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, patchConfig, zabbixRefresh, zabbixTest } from '../../api';
import { de } from '../../i18n/de';

export default function ZabbixPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getConfig('zabbix').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));
  const groups = ((cfg.groupids as string[] | undefined) ?? []).join(', ');

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('zabbix', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true);
    setTest(null);
    try {
      const r = await zabbixTest();
      const list = r.groups.map((g) => `${g.name} (${g.hosts})`).join(', ');
      setTest({ ok: true,
        text: `OK — Zabbix ${r.version}, ${r.hosts} Hosts, ${r.problems} aktive Probleme. `
          + `Sichtbar ${r.filtered ? '(gefiltert) ' : ''}in ${r.groups.length} Host-Gruppen: `
          + `${list || '—'}. Fehlen Hosts, fehlt dem API-User das Leserecht auf ihre Gruppe.` });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  async function refresh() {
    setBusy(true);
    setTest(null);
    try {
      await zabbixRefresh();
      setTest({ ok: true, text: de.settings.zabbixRefreshed });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.zabbix}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.zabbixHint}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">Base-URL</label>
          <input className="fwpt-input" value={(cfg.base_url as string) ?? ''}
            placeholder="https://zabbix.example.net"
            onChange={(e) => set('base_url', e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">
            API-Token (Zabbix → Benutzer → API-Token; Rolle mit Leserechten genügt)
          </label>
          <input className="fwpt-input" type="password" value={(cfg.token as string) ?? ''}
            onChange={(e) => set('token', e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">{de.settings.zabbixGroups}</label>
          <input className="fwpt-input" value={groups} placeholder="z. B. 2, 15"
            onChange={(e) => set('groupids', e.target.value.split(/[,\s]+/)
              .map((g) => g.trim()).filter(Boolean))} />
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.enabled as boolean) ?? true}
          onChange={(e) => set('enabled', e.target.checked)} />
        {de.settings.zabbixEnabled}
      </label>
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
