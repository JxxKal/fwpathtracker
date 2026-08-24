import { CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  arpCacheStatus, arpCacheSweep, getConfig, librenmsRefresh, librenmsTest,
  patchConfig, type ArpCacheStatus,
} from '../../api';
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

      <ArpCacheBlock />
    </div>
  );
}

/** IP↔MAC-Historie: Bestand und letzter Sweep.
 *  Gehört hierher, weil sie genau die Lücke der Switchport-Suche schließt —
 *  ohne sie endet die Suche bei einem abgeschalteten Host ohne MAC. */
function ArpCacheBlock() {
  const [st, setSt] = useState<ArpCacheStatus | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try { setSt(await arpCacheStatus()); } catch { /* Panel bleibt leer */ }
  }
  useEffect(() => { void load(); }, []);

  async function sweep() {
    setBusy(true);
    try { await arpCacheSweep(); await load(); } finally { setBusy(false); }
  }

  if (!st) return null;
  const s = st.stats;
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/40 p-3">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-[11px] font-medium uppercase tracking-wide text-slate-400">
          {de.settings.arpCache}
        </span>
        <button type="button" className="fwpt-btn-ghost" onClick={sweep} disabled={busy}>
          <RefreshCw size={13} className={st.sweep.phase === 'running' || busy ? 'animate-spin' : ''} />
          {de.settings.arpSweepNow}
        </button>
      </div>
      <p className="text-xs text-slate-500">{de.settings.arpCacheHint}</p>
      {s.error ? (
        <p className="mt-1 text-xs text-red-400">{s.error}</p>
      ) : (
        <p className="mt-1 text-xs text-slate-400">
          {de.settings.arpCacheStats(s.bindings ?? 0, s.macs ?? 0, s.ips ?? 0)}
          {' · '}
          {de.settings.arpCacheKeep(st.retention_days, Math.round(st.interval_s / 60))}
        </p>
      )}
      {st.sweep.finished_at && (
        <p className="mt-0.5 text-xs text-slate-500">
          {de.settings.arpLastSweep(
            new Date(st.sweep.finished_at).toLocaleString('de-DE'),
            st.sweep.vdoms, st.sweep.observations)}
        </p>
      )}
      {st.sweep.phase === 'error' && st.sweep.log.length > 0 && (
        <p className="mt-0.5 text-xs text-red-400">{st.sweep.log[st.sweep.log.length - 1]}</p>
      )}
    </div>
  );
}
