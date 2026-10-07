import { CheckCircle2, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, patchConfig, webdrivePoller, webdriveTest } from '../../api';
import { de } from '../../i18n/de';
import type { WebdrivePollerState } from '../../types';

const TEXT_FIELDS: [key: string, label: string, placeholder: string][] = [
  ['base_url', 'Base-URL', 'https://graylog.example:9000'],
  ['fac_query', de.settings.webdriveFacQuery, 'source:fac01'],
  ['oc_query', de.settings.webdriveOcQuery, 'source:opencloud'],
  ['stream_id', de.settings.webdriveStream, ''],
  ['oc_ip', de.settings.webdriveOcIp, '10.180.18.69'],
  ['sync_rule', de.settings.webdriveSyncRule, 'Webdrive-User'],
];

const NUMBER_FIELDS: [key: string, label: string, fallback: number, min: number][] = [
  ['active_window_min', de.settings.webdriveActive, 15, 1],
  ['poll_interval_s', de.settings.webdriveInterval, 60, 60],
  ['retention_days', de.settings.webdriveRetention, 7, 1],
];

export default function WebdrivePanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [poll, setPoll] = useState<WebdrivePollerState | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getConfig('webdrive').then(setCfg);
    webdrivePoller().then(setPoll).catch(() => setPoll(null));
  }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('webdrive', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true);
    setTest(null);
    try {
      const r = await webdriveTest();
      setTest({ ok: true, text: `OK — Graylog ${r.version}` });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  const s = poll?.stats ?? {};
  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.webdrive}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.webdriveHint}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {TEXT_FIELDS.map(([key, label, placeholder]) => (
          <div key={key} className={key === 'base_url' ? 'sm:col-span-2' : ''}>
            <label className="mb-1 block text-xs text-slate-400">{label}</label>
            <input className="fwpt-input" value={(cfg[key] as string) ?? ''} placeholder={placeholder}
              onChange={(e) => set(key, e.target.value)} />
          </div>
        ))}
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">{de.settings.webdriveToken}</label>
          <input className="fwpt-input" type="password" value={(cfg.token as string) ?? ''}
            onChange={(e) => set('token', e.target.value)} />
        </div>
        {NUMBER_FIELDS.map(([key, label, fallback, min]) => (
          <div key={key}>
            <label className="mb-1 block text-xs text-slate-400">{label}</label>
            <input className="fwpt-input" type="number" min={min}
              value={(cfg[key] as number) ?? fallback}
              onChange={(e) => set(key, Number(e.target.value))} />
          </div>
        ))}
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
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
      {poll && (
        <div className="rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-400">
          <p>{poll.last_ok
            ? de.settings.webdriveLastPoll(new Date(poll.last_ok).toLocaleString('de-DE'))
            : de.settings.webdriveNeverPolled}</p>
          {poll.last_ok && (
            <p className="mt-0.5 text-slate-500">
              {de.settings.webdrivePollStats(s.fac_events ?? 0, s.fac_dropped ?? 0, s.oc_events ?? 0, s.oc_dropped ?? 0)}
            </p>
          )}
          {poll.last_error && <p className="mt-0.5 text-red-400">{poll.last_error}</p>}
        </div>
      )}
    </div>
  );
}
