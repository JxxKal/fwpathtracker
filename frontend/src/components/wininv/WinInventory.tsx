import { RefreshCw, Search } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { winInvHost, winInvHosts, type WinInvHost, type WinInvHostDetail, type WinInvRisk } from '../../api';
import { de } from '../../i18n/de';

const t = de.wininv;
const KIND_ORDER = ['groups', 'users', 'secpol', 'services', 'tasks', 'ports', 'shares', 'software',
  'features', 'certificates'];
const fmtDate = (iso: string) => new Date(iso).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });

function RiskChip({ r }: { r: WinInvRisk }) {
  const cls = r.level === 'red' ? 'border-red-700 bg-red-950/50 text-red-300'
    : r.level === 'orange' ? 'border-amber-700 bg-amber-950/40 text-amber-300'
      : 'border-slate-700 text-slate-400';
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] ${cls}`}>{r.text}</span>;
}

function Detail({ name }: { name: string }) {
  const [d, setD] = useState<WinInvHostDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [kind, setKind] = useState('groups');
  const [q, setQ] = useState('');

  useEffect(() => {
    setD(null); setErr(null);
    winInvHost(name).then(setD).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [name]);

  const kinds = useMemo(() => KIND_ORDER.filter((k) => d?.data[k]), [d]);
  useEffect(() => { if (kinds.length && !kinds.includes(kind)) setKind(kinds[0]); }, [kinds, kind]);
  if (err) return <p className="text-sm text-red-400">{err}</p>;
  if (!d) return <p className="text-sm text-slate-400">{de.common.loading}</p>;

  const rows = (d.data[kind] ?? []).filter((r) => !q
    || Object.values(r).some((v) => v.toLowerCase().includes(q.toLowerCase())));
  const cols = Array.from(new Set((d.data[kind] ?? []).flatMap((r) => Object.keys(r))));
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h3 className="text-lg font-medium text-slate-100">{d.hostname}</h3>
        <span className="text-sm text-slate-300">{d.os ?? '—'}</span>
        <span className="font-mono text-xs text-slate-400">{d.ips.join(', ')}</span>
        <span className="text-xs text-slate-500">
          {d.cpu ?? '?'} CPU · {d.ram_gb ?? '?'} GB RAM · {t.fileTime} {fmtDate(d.file_time)}
        </span>
      </div>
      {d.risks.length > 0 && <div className="flex flex-wrap gap-1.5">{d.risks.map((r) => <RiskChip key={r.text} r={r} />)}</div>}
      <div className="flex flex-wrap items-center gap-1.5">
        {kinds.map((k) => (
          <button key={k} type="button" onClick={() => setKind(k)}
            className={`rounded-md border px-2.5 py-1 text-xs ${kind === k
              ? 'border-cyan-600 bg-cyan-950/60 text-cyan-200' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}>
            {t.kinds[k as keyof typeof t.kinds] ?? k} ({d.data[k].length})
          </button>
        ))}
        <div className="relative ml-auto">
          <Search size={13} className="absolute left-2 top-2 text-slate-500" />
          <input className="fwpt-input w-56 pl-7 text-xs" value={q} placeholder={t.filterRows}
            onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      <div className="max-h-[480px] overflow-auto rounded-md border border-slate-800">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-slate-900 text-slate-400">
            <tr>{cols.map((c) => <th key={c} className="px-2 py-1.5 font-medium">{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-t border-slate-800/70 align-top text-slate-300">
                {cols.map((c) => <td key={c} className="max-w-[420px] break-words px-2 py-1">{r[c]}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="p-3 text-xs text-slate-500">{t.noRows}</p>}
      </div>
    </div>
  );
}

export default function WinInventory() {
  const [hosts, setHosts] = useState<WinInvHost[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [onlyRisks, setOnlyRisks] = useState(false);
  const [onlyStale, setOnlyStale] = useState(false);
  const [pick, setPick] = useState<string | null>(null);

  function load() {
    setErr(null);
    winInvHosts().then((r) => setHosts(r.hosts))
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }
  useEffect(load, []);

  const shown = useMemo(() => (hosts ?? []).filter((h) => {
    if (onlyRisks && !h.risks.some((r) => r.level !== 'info')) return false;
    if (onlyStale && !h.stale) return false;
    if (!q) return true;
    const n = q.toLowerCase();
    return h.hostname.toLowerCase().includes(n) || (h.os ?? '').toLowerCase().includes(n)
      || h.ips.some((ip) => ip.startsWith(n));
  }), [hosts, q, onlyRisks, onlyStale]);

  const stats = useMemo(() => {
    const all = hosts ?? [];
    return { total: all.length, stale: all.filter((h) => h.stale).length,
      red: all.filter((h) => h.risks.some((r) => r.level === 'red')).length };
  }, [hosts]);

  return (
    <div className="space-y-4">
      <div className="fwpt-card space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 className="font-medium text-slate-100">{t.title}</h2>
            <p className="mt-0.5 text-xs text-slate-500">{t.hint}</p>
          </div>
          <button type="button" className="fwpt-btn-ghost" onClick={load}><RefreshCw size={14} /> {t.reload}</button>
        </div>
        {err && <p className="text-sm text-red-400">{err}</p>}
        {hosts && (
          <>
            <p className="text-xs text-slate-400">{t.stats(stats.total, stats.red, stats.stale)}</p>
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative">
                <Search size={13} className="absolute left-2 top-2.5 text-slate-500" />
                <input className="fwpt-input w-72 pl-7" value={q} placeholder={t.search}
                  onChange={(e) => setQ(e.target.value)} />
              </div>
              <label className="flex items-center gap-1.5 text-xs text-slate-300">
                <input type="checkbox" checked={onlyRisks} onChange={(e) => setOnlyRisks(e.target.checked)} />
                {t.onlyRisks}
              </label>
              <label className="flex items-center gap-1.5 text-xs text-slate-300">
                <input type="checkbox" checked={onlyStale} onChange={(e) => setOnlyStale(e.target.checked)} />
                {t.onlyStale}
              </label>
              <span className="text-xs text-slate-500">{t.shown(shown.length)}</span>
            </div>
            {hosts.length === 0 ? <p className="text-sm text-slate-400">{t.empty}</p> : (
              <div className="max-h-[420px] overflow-auto rounded-md border border-slate-800">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-900 text-slate-400">
                    <tr>
                      <th className="px-2 py-1.5 font-medium">{t.colHost}</th>
                      <th className="px-2 py-1.5 font-medium">{t.colOs}</th>
                      <th className="px-2 py-1.5 font-medium">{t.colIps}</th>
                      <th className="px-2 py-1.5 font-medium">{t.colRisks}</th>
                      <th className="px-2 py-1.5 font-medium">{t.colTime}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((h) => (
                      <tr key={h.hostname} onClick={() => setPick(h.hostname)}
                        className={`cursor-pointer border-t border-slate-800/70 align-top hover:bg-slate-800/40 ${pick === h.hostname ? 'bg-cyan-950/30' : ''}`}>
                        <td className="px-2 py-1 font-medium text-slate-100">{h.hostname}</td>
                        <td className="px-2 py-1 text-slate-300">{(h.os ?? '—').replace('Microsoft ', '')}</td>
                        <td className="px-2 py-1 font-mono text-slate-400">{h.ips.join(', ')}</td>
                        <td className="px-2 py-1">
                          <div className="flex flex-wrap gap-1">{h.risks.map((r) => <RiskChip key={r.text} r={r} />)}</div>
                        </td>
                        <td className={`whitespace-nowrap px-2 py-1 ${h.stale ? 'text-amber-400' : 'text-slate-400'}`}
                          title={h.stale ? t.staleHint : undefined}>{fmtDate(h.file_time)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
      {pick && <div className="fwpt-card"><Detail name={pick} /></div>}
    </div>
  );
}
