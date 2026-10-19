import { ArrowLeftRight, History, Route } from 'lucide-react';
import { FormEvent, useEffect, useState } from 'react';
import { fazFlowHistory, type FlowHistory as Result, type FlowHistoryRequest } from '../../api';
import { de } from '../../i18n/de';
import type { TraceRequest } from '../../types';
import EndpointAutocomplete from '../EndpointAutocomplete';
import { Busy, SearchNotes, WhenAgo, WindowSelect, devLabel, when } from './common';

// „Gestern ging es noch": derselbe Flow in den FAZ-Logs über die Zeit. Der
// Pfad-Tracker sagt, was die Regeln JETZT erlauben — hier steht, was vorher
// war und wann es kippte.

const WINDOWS = [6, 24, 48, 168, 720];

const verdictStyle: Record<string, string> = {
  blocked_since: 'border-red-800 bg-red-950/60 text-red-300',
  always_blocked: 'border-red-800 bg-red-950/60 text-red-300',
  silent_since: 'border-amber-800 bg-amber-950/60 text-amber-300',
  allowed_again: 'border-emerald-800 bg-emerald-950/60 text-emerald-300',
  always_allowed: 'border-emerald-800 bg-emerald-950/60 text-emerald-300',
  none: 'border-slate-700 bg-slate-900/60 text-slate-300',
};

function Timeline({ r }: { r: Result }) {
  const max = Math.max(1, ...r.timeline.map((s) => s.allow + s.deny));
  const first = r.timeline[0]?.start ?? null;
  const last = r.timeline[r.timeline.length - 1]?.start ?? null;
  return (
    <div>
      <div className="mb-1 flex items-center gap-3 text-[11px] text-slate-500">
        <span>{de.yesterday.timeline}</span>
        <span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-emerald-500" />{de.yesterday.allowed}</span>
        <span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-red-500" />{de.yesterday.denied}</span>
      </div>
      <div className="flex h-20 items-end gap-px rounded border border-slate-800 bg-slate-950/60 p-1">
        {r.timeline.map((s) => {
          const total = s.allow + s.deny;
          return (
            <div key={s.start} className="flex h-full min-w-0 flex-1 flex-col justify-end"
              title={`${when(s.start)} · ${s.allow} ${de.yesterday.allowed} · ${s.deny} ${de.yesterday.denied}`}>
              {/* Stille bekommt einen Strich, damit Lücken als Lücken lesbar sind. */}
              {total === 0
                ? <div className="h-px bg-slate-800" />
                : (
                  <div className="flex flex-col justify-end" style={{ height: `${Math.max(6, (total / max) * 100)}%` }}>
                    {s.deny > 0 && <div className="bg-red-500" style={{ flexGrow: s.deny }} />}
                    {s.allow > 0 && <div className="bg-emerald-500" style={{ flexGrow: s.allow }} />}
                  </div>
                )}
            </div>
          );
        })}
      </div>
      <div className="mt-0.5 flex justify-between text-[10px] text-slate-500">
        <span>{when(first)}</span><span>{when(last)}</span>
      </div>
    </div>
  );
}

export default function FlowHistory({ initial, onTrace }: {
  initial?: FlowHistoryRequest | null;
  onTrace: (req: TraceRequest) => void;
}) {
  const [src, setSrc] = useState(initial?.src ?? '');
  const [dst, setDst] = useState(initial?.dst ?? '');
  const [protocol, setProtocol] = useState(initial?.protocol ?? 'tcp');
  const [port, setPort] = useState(initial?.dst_port ? String(initial.dst_port) : '');
  const [hours, setHours] = useState(initial?.hours ?? 48);
  const [res, setRes] = useState<Result | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isIcmp = protocol === 'icmp';

  async function run(req?: FlowHistoryRequest) {
    const body = req ?? {
      src: src.trim(), dst: dst.trim(), protocol: protocol || null,
      dst_port: isIcmp ? null : Number(port) || null, hours,
    };
    if (!body.src || !body.dst) return;
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await fazFlowHistory(body));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  // Aus dem Tracker oder der Deny-Liste kommend: gleich suchen.
  useEffect(() => { if (initial?.src && initial?.dst) run(initial); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function submit(e: FormEvent) { e.preventDefault(); run(); }

  const verdict = res && de.yesterday.verdict[res.verdict](when(res.since));

  return (
    <div className="space-y-4">
      <form onSubmit={submit} className="fwpt-card space-y-3">
        <div className="flex items-start gap-2">
          <History size={18} className="mt-0.5 text-cyan-400" />
          <div>
            <h2 className="font-medium text-slate-100">{de.yesterday.title}</h2>
            <p className="max-w-3xl text-xs text-slate-500">{de.yesterday.hint}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-56 flex-1">
            <span className="mb-1 block text-[11px] text-slate-500">{de.trace.src}</span>
            <EndpointAutocomplete value={src} onChange={setSrc} placeholder="10.1.1.10 / ws0042" />
          </div>
          <button type="button" className="fwpt-btn-ghost mb-0.5" title={de.yesterday.swap}
            onClick={() => { setSrc(dst); setDst(src); }}>
            <ArrowLeftRight size={14} />
          </button>
          <div className="min-w-56 flex-1">
            <span className="mb-1 block text-[11px] text-slate-500">{de.trace.dst}</span>
            <EndpointAutocomplete value={dst} onChange={setDst} placeholder="10.2.1.30 / srv-db" />
          </div>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.trace.protocol}</span>
            <select className="fwpt-input w-24" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option>
            </select>
          </label>
          {!isIcmp && (
            <label className="flex flex-col gap-1">
              <span className="text-[11px] text-slate-500">{de.yesterday.anyPort}</span>
              <input className="fwpt-input w-32" inputMode="numeric" value={port}
                onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} />
            </label>
          )}
          <WindowSelect value={hours} options={WINDOWS} onChange={setHours} />
          <button type="submit" className="fwpt-btn" disabled={busy || !src.trim() || !dst.trim()}>
            {busy ? de.faz.searching : de.faz.search}
          </button>
        </div>
      </form>

      {busy && <Busy />}
      {err && <div className="rounded-md border border-red-800 bg-red-950/60 p-3 text-sm text-red-300">{err}</div>}

      {res && (
        <div className="space-y-4">
          <div className={`rounded-md border p-3 text-sm ${verdictStyle[res.verdict]}`}>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="font-semibold">{verdict}</span>
              <span className="text-slate-400">
                {res.src} → {res.dst}
                {res.protocol ? ` · ${res.protocol.toUpperCase()}` : ''}
                {res.dst_port ? `/${res.dst_port}` : ''} · {de.faz.windows[res.hours] ?? `${res.hours} h`}
              </span>
              <button type="button" className="fwpt-btn-ghost ml-auto text-xs"
                onClick={() => onTrace({ src: res.src, dst: res.dst, protocol: res.protocol ?? 'tcp',
                  dst_port: res.dst_port, sessions: true })}>
                <Route size={13} /> {de.faz.traceNow}
              </button>
            </div>
            <p className="mt-1 text-xs text-slate-300/80">{de.yesterday.explain[res.verdict]}</p>
            <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-300">
              {res.last_allow && <span>{de.yesterday.lastAllow}: <WhenAgo iso={res.last_allow} /></span>}
              {res.last_deny && <span>{de.yesterday.lastDeny}: <WhenAgo iso={res.last_deny} /></span>}
              {res.blocker && (
                <span>
                  {de.yesterday.blocker}: <span className="font-mono">{devLabel(res.blocker.device, res.blocker.vdom)}</span>
                  {' · '}{de.faz.policy} <span className="font-mono">{res.blocker.policy}</span>
                </span>
              )}
            </div>
          </div>

          <SearchNotes complete={res.complete} limitHit={res.limit_hit} lines={res.counts.lines} />

          {res.counts.lines > 0 && (
            <div className="fwpt-card space-y-4">
              <Timeline r={res} />
              <div>
                <p className="mb-1 text-[11px] text-slate-500">
                  {de.yesterday.hops} · {de.yesterday.lines(res.counts.lines)}
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-[11px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="py-1 pr-3 font-medium">{de.faz.device}</th>
                        <th className="py-1 pr-3 font-medium">{de.faz.policy}</th>
                        <th className="py-1 pr-3 font-medium" />
                        <th className="py-1 pr-3 text-right font-medium">{de.faz.count}</th>
                        <th className="py-1 pr-3 font-medium">{de.faz.first}</th>
                        <th className="py-1 pr-3 font-medium">{de.faz.last}</th>
                        <th className="py-1 font-medium">{de.faz.interfaces}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {res.hops.map((h) => (
                        <tr key={`${h.device}|${h.vdom}|${h.policyid}|${h.outcome}`}>
                          <td className="py-1.5 pr-3 font-mono text-xs">{devLabel(h.device, h.vdom)}</td>
                          <td className="py-1.5 pr-3 font-mono text-xs">{h.policy}</td>
                          <td className="py-1.5 pr-3">
                            <span className={`rounded px-1.5 py-0.5 text-[10px] ${
                              h.outcome === 'deny' ? 'bg-red-900/70 text-red-300'
                                : h.outcome === 'allow' ? 'bg-emerald-900/70 text-emerald-300'
                                  : 'bg-slate-700/70 text-slate-300'}`}
                              title={Object.entries(h.actions).map(([a, n]) => `${a}: ${n}`).join(', ')}>
                              {de.yesterday.outcome[h.outcome]}
                            </span>
                          </td>
                          <td className="py-1.5 pr-3 text-right tabular-nums">{h.count.toLocaleString('de-DE')}</td>
                          <td className="py-1.5 pr-3 text-xs"><WhenAgo iso={h.first} /></td>
                          <td className="py-1.5 pr-3 text-xs"><WhenAgo iso={h.last} /></td>
                          <td className="py-1.5 font-mono text-xs text-slate-400">
                            {h.srcintf ?? '?'} → {h.dstintf ?? '?'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
          <p className="text-xs text-slate-500">{de.faz.loggingHint}</p>
        </div>
      )}
    </div>
  );
}
