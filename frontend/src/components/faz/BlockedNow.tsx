import { ArrowDownLeft, ArrowUpRight, History, Route, ShieldX } from 'lucide-react';
import { FormEvent, useState } from 'react';
import {
  fazBlocked, type BlockedResult, type BlockedRow, type FlowHistoryRequest,
} from '../../api';
import { de } from '../../i18n/de';
import type { TraceRequest } from '../../types';
import EndpointAutocomplete from '../EndpointAutocomplete';
import { Busy, SearchNotes, WhenAgo, WindowSelect, devLabel } from './common';

// „Was wird bei dem Host gerade geblockt?" — der Helpdesk-Fall „die Anwendung
// geht nicht": statt Ports zu raten, steht hier, was die Firewalls verworfen
// haben. Jede Zeile führt in den Pfad-Tracker, der den Regelvorschlag baut.

const WINDOWS = [0.25, 1, 4, 24, 168];
type Direction = 'both' | 'src' | 'dst';

export default function BlockedNow({ onTrace, onHistory }: {
  onTrace: (req: TraceRequest) => void;
  onHistory: (req: FlowHistoryRequest) => void;
}) {
  const [q, setQ] = useState('');
  const [hours, setHours] = useState(1);
  const [direction, setDirection] = useState<Direction>('both');
  const [res, setRes] = useState<BlockedResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(e?: FormEvent) {
    e?.preventDefault();
    if (!q.trim()) return;
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await fazBlocked(q.trim(), hours, direction));
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : String(ex));
    } finally { setBusy(false); }
  }

  const trace = (r: BlockedRow) => onTrace({
    src: r.src ?? '', dst: r.dst ?? '', protocol: r.protocol ?? 'tcp',
    dst_port: r.dst_port, sessions: false,
  });
  const history = (r: BlockedRow) => onHistory({
    src: r.src ?? '', dst: r.dst ?? '', protocol: r.protocol, dst_port: r.dst_port, hours: 48,
  });
  const hits = res ? res.rows.reduce((n, r) => n + r.count, 0) : 0;

  return (
    <div className="space-y-4">
      <form onSubmit={run} className="fwpt-card space-y-3">
        <div className="flex items-start gap-2">
          <ShieldX size={18} className="mt-0.5 text-cyan-400" />
          <div>
            <h2 className="font-medium text-slate-100">{de.blocked.title}</h2>
            <p className="max-w-3xl text-xs text-slate-500">{de.blocked.hint}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-64 flex-1">
            <EndpointAutocomplete value={q} onChange={setQ} placeholder={de.blocked.placeholder}
              onSubmit={() => run()} />
          </div>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.blocked.direction}</span>
            <select className="fwpt-input w-40" value={direction}
              onChange={(e) => setDirection(e.target.value as Direction)}>
              {(['both', 'src', 'dst'] as Direction[]).map((d) => (
                <option key={d} value={d}>{de.blocked.directions[d]}</option>
              ))}
            </select>
          </label>
          <WindowSelect value={hours} options={WINDOWS} onChange={setHours} />
          <button type="submit" className="fwpt-btn" disabled={busy || !q.trim()}>
            {busy ? de.faz.searching : de.faz.search}
          </button>
        </div>
      </form>

      {busy && <Busy />}
      {err && <div className="rounded-md border border-red-800 bg-red-950/60 p-3 text-sm text-red-300">{err}</div>}

      {res && (
        <div className="space-y-3">
          <SearchNotes complete={res.complete} limitHit={res.limit_hit} lines={res.lines} />
          {res.rows.length === 0 ? (
            <p className="text-sm text-slate-400">{de.blocked.empty}</p>
          ) : (
            <div className="fwpt-card space-y-2">
              <div className="flex flex-wrap items-baseline gap-x-3 text-sm">
                <span className="font-mono text-slate-200">{res.ip}</span>
                {res.names[0] && <span className="text-slate-400">{res.names[0]}</span>}
                <span className="text-xs text-slate-500">{de.blocked.summary(res.rows.length, hits)}</span>
              </div>
              {res.implicit > 0 && <p className="text-xs text-amber-300/90">{de.blocked.implicit(res.implicit)}</p>}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-[11px] uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="py-1 pr-2 font-medium" />
                      <th className="py-1 pr-3 font-medium">{de.blocked.peer}</th>
                      <th className="py-1 pr-3 font-medium">{de.blocked.port}</th>
                      <th className="py-1 pr-3 font-medium">{de.faz.device}</th>
                      <th className="py-1 pr-3 font-medium">{de.faz.policy}</th>
                      <th className="py-1 pr-3 text-right font-medium">{de.faz.count}</th>
                      <th className="py-1 pr-3 font-medium">{de.faz.last}</th>
                      <th className="py-1 font-medium" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {res.rows.map((r) => (
                      <tr key={`${r.direction}|${r.peer}|${r.protocol}|${r.dst_port}|${r.device}|${r.vdom}|${r.policyid}`}>
                        <td className="py-1.5 pr-2" title={r.direction === 'src' ? de.blocked.out : de.blocked.in}>
                          {r.direction === 'src'
                            ? <ArrowUpRight size={14} className="text-slate-400" />
                            : <ArrowDownLeft size={14} className="text-slate-400" />}
                        </td>
                        <td className="py-1.5 pr-3">
                          <span className="font-mono text-xs">{r.peer}</span>
                          {r.peer_name && <span className="ml-2 text-xs text-slate-400">{r.peer_name}</span>}
                        </td>
                        <td className="py-1.5 pr-3 font-mono text-xs">
                          {(r.protocol ?? '?').toUpperCase()}{r.dst_port ? `/${r.dst_port}` : ''}
                          {r.service && <span className="ml-1 text-slate-500">{r.service}</span>}
                        </td>
                        <td className="py-1.5 pr-3 font-mono text-xs"
                          title={`${r.srcintf ?? '?'} → ${r.dstintf ?? '?'}`}>
                          {devLabel(r.device, r.vdom)}
                        </td>
                        <td className={`py-1.5 pr-3 font-mono text-xs ${r.policyid === 0 ? 'text-amber-300' : ''}`}>
                          {r.policy}
                        </td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{r.count.toLocaleString('de-DE')}</td>
                        <td className="py-1.5 pr-3 text-xs"><WhenAgo iso={r.last} /></td>
                        <td className="whitespace-nowrap py-1.5 text-right">
                          <button type="button" className="fwpt-btn-ghost px-2 py-1 text-xs"
                            title={de.faz.traceNow} onClick={() => trace(r)}>
                            <Route size={13} />
                          </button>
                          <button type="button" className="fwpt-btn-ghost ml-1 px-2 py-1 text-xs"
                            title={de.yesterday.title} onClick={() => history(r)}>
                            <History size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          <p className="text-xs text-slate-500">{de.faz.loggingHint}</p>
        </div>
      )}
    </div>
  );
}
