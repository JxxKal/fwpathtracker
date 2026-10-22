import { Check, ClipboardCopy, ListChecks } from 'lucide-react';
import { FormEvent, useState } from 'react';
import { reconcileNetwork, type ReconcileCode, type ReconcileResult, type ReconcileRow } from '../api';
import { copyText } from '../checkLink';
import { de } from '../i18n/de';
import { WhenAgo } from './faz/common';

// Bestandsabgleich: iTop (Soll) gegen ARP-Historie, FortiAnalyzer und DNS
// (Ist). Die Liste ist zum Abarbeiten gedacht — deshalb Filter je Befund und
// ein CSV für die Kollegen, die im iTop nachpflegen.

const CODES: ReconcileCode[] = [
  'ip_conflict', 'not_in_itop', 'itop_released', 'stale_in_itop', 'mac_changed', 'name_mismatch',
];

const sevStyle: Record<string, string> = {
  error: 'bg-red-900/70 text-red-300',
  warn: 'bg-amber-900/70 text-amber-300',
  info: 'bg-sky-900/70 text-sky-300',
};

const CODE_SEVERITY: Record<ReconcileCode, string> = {
  ip_conflict: 'error', not_in_itop: 'warn', itop_released: 'warn',
  stale_in_itop: 'info', mac_changed: 'info', name_mismatch: 'info',
};

function csv(rows: ReconcileRow[]): string {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const head = ['IP', 'Name', 'iTop', 'DNS', 'FortiAnalyzer', 'MAC', 'zuletzt gesehen', 'Befunde'];
  const body = rows.map((r) => [
    r.ip, r.display_name, r.names.itop ?? r.names.itop_ip, r.names.dns, r.names.faz,
    [...new Set(r.macs.map((m) => m.mac))].join(' '), r.last_seen,
    r.findings.map((f) => `${de.reconcile.code[f.code]}: ${f.text}`).join(' | '),
  ].map(esc).join(';'));
  return [head.map(esc).join(';'), ...body].join('\n');
}

const dtShort = (iso: string | null) => (iso ? new Date(iso).toLocaleString('de-DE', {
  day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—');

/** MACs einer IP — bei Konflikt oder Wechsel gleich mit Herkunft: wer hat sie
 *  wann gesehen, an welchen IPs steht sie noch, was verrät das Präfix. */
function MacCell({ row }: { row: ReconcileRow }) {
  const suspicious = row.findings.some((f) => f.code === 'ip_conflict' || f.code === 'mac_changed');
  const [open, setOpen] = useState(suspicious);
  const byMac = new Map<string, ReconcileRow['macs']>();
  for (const m of row.macs) byMac.set(m.mac, [...(byMac.get(m.mac) ?? []), m]);
  if (byMac.size === 0) return null;
  return (
    <div className="space-y-1">
      {[...byMac.entries()].map(([mac, entries]) => {
        const v = entries.find((e) => e.vendor)?.vendor;
        const others = entries.find((e) => e.other_ips?.length)?.other_ips ?? [];
        return (
          <div key={mac}>
            <button type="button" className="font-mono text-slate-300 hover:text-cyan-300"
              onClick={() => setOpen(!open)} title={de.reconcile.macDetails}>
              {mac}
            </button>
            {v && (
              <span className={`ml-1 rounded px-1 text-[9px] ${v.kind === 'shared' ? 'bg-amber-900/60 text-amber-300'
                : v.kind === 'virtual' ? 'bg-violet-900/60 text-violet-300' : 'bg-slate-800 text-slate-300'}`}>
                {v.label}
              </span>
            )}
            {open && (
              <div className="ml-2 mt-0.5 space-y-0.5 border-l border-slate-700 pl-2 text-[10px] leading-snug text-slate-400">
                {entries.map((e, i) => (
                  <div key={i}>
                    {e.source === 'faz'
                      ? <>{de.reconcile.seenFaz} · {de.reconcile.lastSeen} {dtShort(e.last_seen)}</>
                      : <>
                        {de.reconcile.seenBy}{' '}
                        <span className="text-slate-300">
                          {[e.device, e.vdom && `VDOM ${e.vdom}`, e.interface].filter(Boolean).join(' · ') || '?'}
                        </span>
                        {e.seen_by && <> ({de.reconcile.via[e.seen_by] ?? e.seen_by})</>}
                        <br />{dtShort(e.first_seen)} – {dtShort(e.last_seen)}
                        {e.seen_count ? <> · {de.reconcile.times(e.seen_count)}</> : null}
                      </>}
                  </div>
                ))}
                {others.length > 0 && (
                  <div className="text-amber-300/90">{de.reconcile.alsoAt} {others.join(', ')}</div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function Reconcile() {
  const [q, setQ] = useState('');
  const [activeDays, setActiveDays] = useState(7);
  const [staleDays, setStaleDays] = useState(30);
  const [res, setRes] = useState<ReconcileResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<ReconcileCode | 'findings' | 'all'>('findings');
  const [copied, setCopied] = useState(false);

  async function run(e: FormEvent) {
    e.preventDefault();
    if (!q.trim()) return;
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await reconcileNetwork(q.trim(), activeDays, staleDays));
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : String(ex));
    } finally { setBusy(false); }
  }

  const rows = res ? res.rows.filter((r) => (
    filter === 'all' ? true
      : filter === 'findings' ? r.findings.length > 0
        : r.findings.some((f) => f.code === filter))) : [];

  return (
    <div className="space-y-4">
      <form onSubmit={run} className="fwpt-card space-y-3">
        <div className="flex items-start gap-2">
          <ListChecks size={18} className="mt-0.5 text-cyan-400" />
          <div>
            <h2 className="font-medium text-slate-100">{de.reconcile.title}</h2>
            <p className="max-w-3xl text-xs text-slate-500">{de.reconcile.hint}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-64 flex-1">
            <input className="fwpt-input" value={q} placeholder={de.reconcile.placeholder}
              onChange={(e) => setQ(e.target.value)} />
          </div>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.reconcile.activeDays}</span>
            <input className="fwpt-input w-24" type="number" min={1} max={90} value={activeDays}
              onChange={(e) => setActiveDays(Number(e.target.value) || 7)} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.reconcile.staleDays}</span>
            <input className="fwpt-input w-24" type="number" min={1} max={365} value={staleDays}
              onChange={(e) => setStaleDays(Number(e.target.value) || 30)} />
          </label>
          <button type="submit" className="fwpt-btn" disabled={busy || !q.trim()}>
            {busy ? de.reconcile.running : de.reconcile.run}
          </button>
        </div>
      </form>

      {err && <div className="rounded-md border border-red-800 bg-red-950/60 p-3 text-sm text-red-300">{err}</div>}

      {res && (
        <div className="fwpt-card space-y-3">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="font-mono text-slate-100">{de.reconcile.network(res.network, res.origin)}</span>
            <span className="text-xs text-slate-500">{de.reconcile.stats(res.stats)}</span>
            <button type="button" className="fwpt-btn-ghost ml-auto text-xs"
              onClick={async () => {
                if (await copyText(csv(rows))) { setCopied(true); setTimeout(() => setCopied(false), 1500); }
              }}>
              {copied ? <Check size={13} className="text-emerald-400" /> : <ClipboardCopy size={13} />}
              {copied ? de.reconcile.copied : de.reconcile.copy}
            </button>
          </div>
          {res.warnings.map((w) => <p key={w} className="text-xs text-amber-300/90">{w}</p>)}

          <div className="flex flex-wrap gap-1.5 text-xs">
            {(['findings', 'all'] as const).map((f) => (
              <button key={f} type="button" onClick={() => setFilter(f)}
                className={`rounded-full border px-2.5 py-0.5 ${filter === f
                  ? 'border-cyan-600 text-cyan-300' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}>
                {f === 'all' ? `${de.reconcile.all} (${res.rows.length})`
                  : `${de.reconcile.onlyFindings} (${res.stats.with_findings})`}
              </button>
            ))}
            {CODES.filter((c) => res.counts[c]).map((c) => (
              <button key={c} type="button" onClick={() => setFilter(c)}
                className={`rounded-full px-2.5 py-0.5 ${sevStyle[CODE_SEVERITY[c]]} ${
                  filter === c ? 'ring-1 ring-cyan-400' : 'opacity-80 hover:opacity-100'}`}>
                {de.reconcile.code[c]} ({res.counts[c]})
              </button>
            ))}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-[11px] uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="py-1 pr-3 font-medium">{de.reconcile.col.ip}</th>
                  <th className="py-1 pr-3 font-medium">{de.reconcile.col.name}</th>
                  <th className="py-1 pr-3 font-medium">{de.reconcile.col.sources}</th>
                  <th className="py-1 pr-3 font-medium">{de.reconcile.col.mac}</th>
                  <th className="py-1 pr-3 font-medium">{de.reconcile.col.seen}</th>
                  <th className="py-1 font-medium">{de.reconcile.col.findings}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 align-top">
                {rows.map((r) => (
                  <tr key={r.ip}>
                    <td className="py-1.5 pr-3 font-mono text-xs">{r.ip}</td>
                    <td className="py-1.5 pr-3 text-xs">
                      <div className="text-slate-200">{r.display_name ?? '—'}</div>
                      {(r.kind || r.os) && (
                        <div className="text-[11px] text-slate-500">
                          {[r.kind, r.os].filter(Boolean).join(' · ')}
                        </div>
                      )}
                    </td>
                    <td className="py-1.5 pr-3">
                      <div className="flex flex-wrap gap-1">
                        {r.sources.map((s) => (
                          <span key={s} className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                            {de.reconcile.source[s] ?? s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-1.5 pr-3 text-[11px] text-slate-400">
                      <MacCell row={r} />
                    </td>
                    <td className="py-1.5 pr-3 text-xs">
                      {r.last_seen ? <WhenAgo iso={r.last_seen} /> : <span className="text-slate-500">{de.reconcile.never}</span>}
                    </td>
                    <td className="py-1.5 text-xs">
                      {r.findings.length === 0
                        ? <span className="text-emerald-400/80">{de.reconcile.ok}</span>
                        : r.findings.map((f) => (
                          <div key={f.code} className="mb-0.5 flex items-start gap-1.5">
                            <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] ${sevStyle[f.severity]}`}>
                              {de.reconcile.code[f.code]}
                            </span>
                            <span className="text-slate-400">{f.text}</span>
                          </div>
                        ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
