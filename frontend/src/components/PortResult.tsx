import { AlertTriangle, ArrowRight, Ban, CheckCircle2, XCircle } from 'lucide-react';
import { de } from '../i18n/de';
import type { PortHop, PortLimit, PortRange, PortTraceResult } from '../types';

/** Range-Liste → kompakter Text: "443, 3389, 8000–8100" / "alle (1–65535)" / "keine". */
function fmtRanges(ranges: PortRange[]): string {
  if (!ranges.length) return de.ports.hopNone;
  if (ranges.length === 1 && ranges[0][0] === 1 && ranges[0][1] === 65535) return de.ports.all;
  return ranges
    .map(([lo, hi]) => (lo === hi ? String(lo) : `${lo}–${hi}`))
    .join(', ');
}

function isFullOpen(ranges: PortRange[]): boolean {
  return ranges.length === 1 && ranges[0][0] === 1 && ranges[0][1] === 65535;
}

function Chips({ ranges }: { ranges: PortRange[] }) {
  if (!ranges.length) {
    return <span className="text-sm text-slate-500">{de.ports.none}</span>;
  }
  if (isFullOpen(ranges)) {
    return <span className="rounded bg-emerald-950 px-2 py-1 text-xs font-medium text-emerald-300">{de.ports.all}</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {ranges.map(([lo, hi]) => (
        <span key={`${lo}-${hi}`} className="rounded border border-emerald-800 bg-emerald-950/50 px-2 py-1 font-mono text-xs text-emerald-300">
          {lo === hi ? lo : `${lo}–${hi}`}
        </span>
      ))}
    </div>
  );
}

/** Limits je Proto nach blockierendem Hop gruppieren (kompakte „wo stirbt Port X"-Sicht). */
function limitsByHop(limits: PortLimit[] | undefined): { hop: string; ranges: PortRange[] }[] {
  const by = new Map<string, PortRange[]>();
  for (const l of limits ?? []) {
    const key = l.hop ?? '—';
    if (!by.has(key)) by.set(key, []);
    by.get(key)!.push(l.range);
  }
  return [...by.entries()].map(([hop, ranges]) => ({ hop, ranges }));
}

function LimitLines({ proto, limits }: { proto: string; limits?: PortLimit[] }) {
  const groups = limitsByHop(limits);
  if (!groups.length) return null;
  return (
    <>
      {groups.map((g) => (
        <div key={`${proto}-${g.hop}`} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs">
          <span className="font-mono uppercase text-slate-500">{proto}</span>
          <Ban size={12} className="shrink-0 text-red-400" />
          <span className="text-slate-400">{de.ports.blockedAt}</span>
          <span className="font-medium text-slate-300">{g.hop}</span>
          <span className="font-mono text-slate-500">{fmtRanges(g.ranges)}</span>
        </div>
      ))}
    </>
  );
}

function HopRow({ hop }: { hop: PortHop }) {
  if (!hop.reachable) {
    return (
      <tr className="border-t border-slate-800">
        <td className="py-2 pr-3 font-medium text-slate-300">{hop.label}</td>
        <td className="py-2 pr-3 text-slate-500">{hop.egress ?? '—'}</td>
        <td className="py-2 text-amber-400" colSpan={2}>{de.ports.unreachable}</td>
      </tr>
    );
  }
  return (
    <tr className="border-t border-slate-800 align-top">
      <td className="py-2 pr-3 font-medium text-slate-300">{hop.label}</td>
      <td className="py-2 pr-3 text-slate-500">{hop.egress ?? '—'}</td>
      <td className="py-2 pr-3">
        <span className="font-mono uppercase text-slate-500">tcp</span>{' '}
        <span className={hop.tcp.length ? 'text-emerald-300' : 'text-slate-500'}>{fmtRanges(hop.tcp)}</span>
      </td>
      <td className="py-2">
        <span className="font-mono uppercase text-slate-500">udp</span>{' '}
        <span className={hop.udp.length ? 'text-emerald-300' : 'text-slate-500'}>{fmtRanges(hop.udp)}</span>
      </td>
    </tr>
  );
}

export default function PortResult({ result }: { result: PortTraceResult }) {
  const open = result.tcp.length > 0 || result.udp.length > 0;
  const hasLimits = (result.limits.tcp?.length ?? 0) + (result.limits.udp?.length ?? 0) > 0;

  return (
    <div className="space-y-4">
      {/* Status-Banner */}
      <div className={`flex flex-wrap items-center gap-3 rounded-md border p-3 text-sm ${
        result.reachable && open
          ? 'border-emerald-800 bg-emerald-950/60 text-emerald-300'
          : result.reachable
            ? 'border-amber-800 bg-amber-950/60 text-amber-300'
            : 'border-red-800 bg-red-950/60 text-red-300'
      }`}>
        {result.reachable
          ? (open ? <CheckCircle2 size={16} /> : <Ban size={16} />)
          : <XCircle size={16} />}
        <span className="font-semibold">
          {result.reachable ? de.ports.reachable : de.ports.unreachable}
        </span>
        <span className="flex items-center gap-1.5 text-slate-400">
          {result.src.ip} <ArrowRight size={13} /> {result.dst.ip} · {result.duration_ms} ms
        </span>
      </div>

      {result.warnings.length > 0 && (
        <div className="space-y-1 rounded-md border border-amber-800 bg-amber-950/40 p-3 text-xs text-amber-300">
          {result.warnings.map((w) => (
            <div key={w} className="flex items-start gap-2">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />{w}
            </div>
          ))}
        </div>
      )}

      {/* End-to-end offene Ports */}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="fwpt-card space-y-2">
          <h3 className="text-xs font-medium uppercase text-slate-500">{de.ports.openTcp}</h3>
          <Chips ranges={result.tcp} />
        </div>
        <div className="fwpt-card space-y-2">
          <h3 className="text-xs font-medium uppercase text-slate-500">{de.ports.openUdp}</h3>
          <Chips ranges={result.udp} />
        </div>
      </div>

      {/* Blockade je Bereich (wo stirbt was) */}
      {hasLimits && (
        <div className="fwpt-card space-y-1.5">
          <h3 className="mb-1 text-xs font-medium uppercase text-slate-500">{de.ports.limits}</h3>
          <LimitLines proto="tcp" limits={result.limits.tcp} />
          <LimitLines proto="udp" limits={result.limits.udp} />
        </div>
      )}

      {/* Pro-Hop-Aufschlüsselung */}
      <div className="fwpt-card">
        <h3 className="mb-2 text-xs font-medium uppercase text-slate-500">{de.ports.perHop}</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase text-slate-600">
                <th className="pb-1 pr-3 font-medium">VDOM</th>
                <th className="pb-1 pr-3 font-medium">{de.ports.egress}</th>
                <th className="pb-1 pr-3 font-medium">TCP</th>
                <th className="pb-1 font-medium">UDP</th>
              </tr>
            </thead>
            <tbody>
              {result.hops.map((h) => <HopRow key={h.index} hop={h} />)}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
