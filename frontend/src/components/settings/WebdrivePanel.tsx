import { Check, CheckCircle2, Copy, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  getConfig, patchConfig, webdriveFacTest, webdrivePoller, webdriveProbe, webdriveReload, webdriveTest,
  type WebdriveProbe, type WebdriveProbeSource,
} from '../../api';
import { de } from '../../i18n/de';
import type { WebdrivePollerState } from '../../types';

const TEXT_FIELDS: [key: string, label: string, placeholder: string][] = [
  ['base_url', 'Base-URL', 'https://graylog.example:9000'],
  ['stream_id', de.settings.webdriveStream, '6ac65d19981aaf2334c18dd7'],
  ['fac_query', de.settings.webdriveFacQuery, 'source:svo3038-ot'],
  ['oc_query', de.settings.webdriveOcQuery, 'source:svo3120-ot'],
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
  const [probe, setProbe] = useState<WebdriveProbe | null>(null);

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

  async function runProbe() {
    setBusy(true);
    setProbe(null);
    try {
      setProbe(await webdriveProbe());
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  async function facTest() {
    setBusy(true);
    setTest(null);
    try {
      const r = await webdriveFacTest();
      setTest({ ok: true, text: de.settings.webdriveFacOk(r.ldapusers) });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  async function reload() {
    setBusy(true);
    setTest(null);
    try {
      const r = await webdriveReload();
      setTest({ ok: true, text: de.settings.webdriveReloaded(r.stats.fac_events ?? 0, r.stats.oc_events ?? 0) });
      setPoll(await webdrivePoller());
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
      <div className="space-y-3 border-t border-slate-800 pt-3">
        <div>
          <h3 className="text-sm font-medium text-slate-200">{de.settings.webdriveFac}</h3>
          <p className="mt-0.5 text-xs text-slate-500">{de.settings.webdriveFacHint}</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs text-slate-400">{de.settings.webdriveFacUrl}</label>
            <input className="fwpt-input" value={(cfg.fac_url as string) ?? ''} placeholder="https://svo3038-ot.op-tech.com"
              onChange={(e) => set('fac_url', e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">{de.settings.webdriveFacUser}</label>
            <input className="fwpt-input" value={(cfg.fac_user as string) ?? ''}
              onChange={(e) => set('fac_user', e.target.value)} />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">{de.settings.webdriveFacKey}</label>
            <input className="fwpt-input" type="password" value={(cfg.fac_api_key as string) ?? ''}
              onChange={(e) => set('fac_api_key', e.target.value)} />
          </div>
          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs text-slate-400">{de.settings.webdriveFacDn}</label>
            <input className="fwpt-input" value={(cfg.fac_dn_filter as string) ?? ''}
              onChange={(e) => set('fac_dn_filter', e.target.value)} />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={(cfg.fac_ssl_verify as boolean) ?? true}
            onChange={(e) => set('fac_ssl_verify', e.target.checked)} />
          TLS-Zertifikat des FAC prüfen
        </label>
      </div>
      {test && (
        <div className={`flex items-start gap-2 text-sm ${test.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {test.ok ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <span>{test.text}</span>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={runTest} disabled={busy}>{de.settings.test}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={runProbe} disabled={busy}
          title={de.settings.webdriveProbeHint}>{de.settings.webdriveProbe}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={facTest} disabled={busy}>
          {de.settings.webdriveFacTest}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={reload} disabled={busy}>
          {de.settings.webdriveReload}</button>
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
      {probe && (
        <div className="space-y-2 rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs">
          <div className="flex items-start justify-between gap-2">
            {probe.stream_id
              ? <p className="text-slate-400">Stream: <span className="font-mono">{probe.stream_id}</span></p>
              : <span />}
            <CopyButton text={JSON.stringify(probe, null, 2)} />
          </div>
          {probe.queries.map((q) => <p key={q} className="font-mono text-slate-500">{q}</p>)}
          {probe.error && <p className="text-red-400">{probe.error}</p>}
          <ProbeBlock title="FortiAuthenticator" src={probe.fac} />
          <ProbeBlock title="OpenCloud" src={probe.oc} />
        </div>
      )}
    </div>
  );
}

function ProbeBlock({ title, src }: { title: string; src: WebdriveProbeSource }) {
  const rec = Object.entries(src.recognized);
  return (
    <div>
      <p className="font-medium text-slate-300">{title}</p>
      <p className="text-slate-400">
        {de.settings.webdriveProbeHits(src.hits)}
        {rec.length > 0 && ` · ${de.settings.webdriveProbeRecognized}: ${rec.map(([k, n]) => `${k} ${n}`).join(', ')}`}
      </p>
      {src.dropped_samples.length > 0 && (
        <details className="mt-1">
          <summary className="cursor-pointer text-slate-400">
            {de.settings.webdriveProbeDropped} ({src.dropped_samples.length})
          </summary>
          <pre className="mt-1 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-900 p-2 text-[11px] text-slate-300">
            {JSON.stringify(src.dropped_samples, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

/** Kopiert in die Zwischenablage — auch ohne HTTPS, wo navigator.clipboard fehlt. */
function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setDone(true);
    window.setTimeout(() => setDone(false), 2000);
  }

  return (
    <button type="button" className="fwpt-btn-ghost shrink-0" onClick={copy}>
      {done ? <Check size={13} /> : <Copy size={13} />} {done ? de.settings.webdriveCopied : de.settings.webdriveCopy}
    </button>
  );
}
