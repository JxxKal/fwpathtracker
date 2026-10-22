import { CheckCircle2, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, graylogTest, patchConfig, type GraylogTestResult } from '../../api';
import { de } from '../../i18n/de';

type Roles = Record<string, { filter?: string }>;

const DEFAULT_FILTER: Record<string, string> = { ad: '{p}winlog_channel:Security', ifix: '' };

export default function GraylogPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<GraylogTestResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getConfig('graylog').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));
  const roles = (cfg.roles as Roles | undefined) ?? {};
  const filter = (role: string) => roles[role]?.filter ?? DEFAULT_FILTER[role];
  const setFilter = (role: string, v: string) =>
    set('roles', { ...roles, [role]: { ...roles[role], filter: v } });
  const prefix = cfg.field_prefix as string | undefined;

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('graylog', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true); setErr(null); setRes(null);
    try { setRes(await graylogTest()); } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.graylog}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.graylogHint}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">Base-URL</label>
          <input className="fwpt-input" value={(cfg.base_url as string) ?? ''}
            placeholder="https://graylog.example:9000"
            onChange={(e) => set('base_url', e.target.value)} />
        </div>
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">{de.settings.graylogToken}</label>
          <input className="fwpt-input" type="password" value={(cfg.token as string) ?? ''}
            onChange={(e) => set('token', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.graylogStream}</label>
          <input className="fwpt-input" value={(cfg.stream_id as string) ?? ''}
            placeholder="000000000000000000000001"
            onChange={(e) => set('stream_id', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.graylogPrefix}</label>
          <select className="fwpt-input" value={prefix === undefined || prefix === null ? 'auto' : prefix || 'none'}
            onChange={(e) => set('field_prefix', e.target.value === 'auto' ? null
              : e.target.value === 'none' ? '' : e.target.value)}>
            <option value="auto">{de.settings.graylogPrefixAuto}</option>
            <option value="winlogbeat_">winlogbeat_winlog_event_id</option>
            <option value="none">winlog_event_id</option>
          </select>
        </div>
        {(['ad', 'ifix'] as const).map((role) => (
          <div key={role} className="sm:col-span-2">
            <label className="mb-1 block text-xs text-slate-400">
              {role === 'ad' ? de.settings.graylogFilterAd : de.settings.graylogFilterIfix}
            </label>
            <input className="fwpt-input font-mono text-xs" value={filter(role)}
              placeholder={role === 'ifix' ? '{p}winlog_provider_name:"…"' : ''}
              onChange={(e) => setFilter(role, e.target.value)} />
          </div>
        ))}
        <p className="text-[11px] text-slate-500 sm:col-span-2">{de.settings.graylogFilterHint}</p>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.ssl_verify as boolean) ?? true}
          onChange={(e) => set('ssl_verify', e.target.checked)} />
        TLS-Zertifikat prüfen
      </label>
      {err && (
        <div className="flex items-start gap-2 text-sm text-red-400">
          <XCircle size={16} className="mt-0.5" /><span>{err}</span>
        </div>
      )}
      {res && <TestResult res={res} onPick={(name) =>
        setFilter('ifix', `{p}winlog_provider_name:"${name}"`)} />}
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={runTest} disabled={busy}>{de.settings.test}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}

function TestResult({ res, onPick }: { res: GraylogTestResult; onPick: (name: string) => void }) {
  const fmt = (n: number) => n.toLocaleString('de-DE');
  return (
    <div className="space-y-2 rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs">
      <div className="flex items-start gap-2 text-sm text-emerald-400">
        <CheckCircle2 size={16} className="mt-0.5" />
        <span>
          OK — Graylog {res.version} ·{' '}
          {res.winlogbeat
            ? <>Winlogbeat erkannt, Felder <code>{res.prefix || '(ohne Präfix)'}winlog_…</code></>
            : <span className="text-amber-400">keine Winlogbeat-Nachrichten in 24 h</span>}
        </span>
      </div>
      <p className="text-slate-400">
        Lesbare Streams: {res.streams_error ? <span className="text-red-400">{res.streams_error}</span>
          : res.streams.map((s) => s.title + (s.removes_from_default ? ' ⚠' : '')).join(', ') || '—'}
      </p>
      {res.streams.some((s) => s.removes_from_default) && (
        <p className="text-amber-400">⚠ = entfernt seine Nachrichten aus „All messages“ — die fehlen dort.</p>
      )}
      {Object.entries(res.roles).map(([key, r]) => (
        <p key={key} className={r.error || !r.hits ? 'text-amber-400' : 'text-slate-300'}>
          <b>{r.label}:</b>{' '}
          {r.error ?? `${fmt(r.hits ?? 0)} Treffer in 24 h`}
          {r.computers.length > 0 && <span className="text-slate-500"> · {r.computers.join(', ')}</span>}
          {r.query && <> · <code className="text-slate-500">{r.query}</code></>}
        </p>
      ))}
      <p className={res.aggregation.ok ? 'text-slate-400' : 'text-amber-400'}>
        Aggregation (Views-API): {res.aggregation.ok ? 'ok' : `nicht möglich — ${res.aggregation.error}`}
      </p>
      {res.providers.length > 0 && (
        <div>
          <p className="mb-1 text-slate-400">{de.settings.graylogProviders}</p>
          <div className="flex flex-wrap gap-1">
            {res.providers.map((p) => (
              <button key={p.name} type="button" className="fwpt-btn-ghost px-2 py-0.5 text-[11px]"
                onClick={() => onPick(p.name)}>
                {p.name} <span className="text-slate-500">{fmt(p.hits)}{p.sampled ? '*' : ''}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
