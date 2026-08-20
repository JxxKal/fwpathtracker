import { MapPin, Server } from 'lucide-react';
import { useState } from 'react';
import {
  locateHost, type LocateCandidate, type LocateResult, type MatchReason, type PortKind,
} from '../api';
import { de } from '../i18n/de';
import EndpointAutocomplete from './EndpointAutocomplete';

// Wo steckt das Gerät physisch? IP→MAC von der FortiGate (live, über den
// FMG-Proxy), MAC→Port aus der LibreNMS-FDB. Die Kandidatenliste bleibt
// einsehbar, weil dieselbe MAC auf jedem Switch im Pfad steht — der Weg dorthin
// ist die Kontrolle, ob der oberste Treffer plausibel ist. Standardmäßig
// eingeklappt, weil sie in großen Ringen dreistellig wird.

const VISIBLE_ROWS = 8;

const confidenceStyle: Record<LocateResult['confidence'], string> = {
  high: 'border-emerald-800 bg-emerald-950/60 text-emerald-300',
  medium: 'border-amber-800 bg-amber-950/60 text-amber-300',
  low: 'border-orange-800 bg-orange-950/60 text-orange-300',
  none: 'border-slate-700 bg-slate-900/60 text-slate-400',
};

// Access und Edge sind beide plausible Anschlusspunkte (Edge = Hypervisor/AP am
// LLDP), Trunk ist möglich, Uplink praktisch ausgeschlossen — es sei denn, der
// Topologie-Abgleich sagt etwas anderes, dann ist die Klasse belanglos.
const kindStyle: Record<PortKind, string> = {
  access: 'bg-emerald-900/70 text-emerald-300',
  edge: 'bg-emerald-900/70 text-emerald-300',
  trunk: 'bg-amber-900/70 text-amber-300',
  uplink: 'bg-slate-700/70 text-slate-400',
  unknown: 'bg-slate-700/70 text-slate-500',
};

const matchStyle: Record<'lldp_peer' | 'description', string> = {
  lldp_peer: 'bg-cyan-900/80 text-cyan-200',
  description: 'bg-sky-900/80 text-sky-200',
};

function age(seconds: number | null): string {
  if (seconds == null) return '—';
  if (seconds < 90) return `vor ${seconds} s`;
  if (seconds < 5400) return `vor ${Math.round(seconds / 60)} min`;
  return `vor ${Math.round(seconds / 3600)} h`;
}

function MatchBadge({ reason }: { reason: MatchReason }) {
  if (!reason) return <span className="text-slate-600">—</span>;
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] ${matchStyle[reason]}`}
      title={de.locate.matchTitle[reason]}>
      {de.locate.matchReason[reason]}
    </span>
  );
}

export default function LocateHost() {
  const [q, setQ] = useState('');
  const [res, setRes] = useState<LocateResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState(false);

  async function search() {
    setBusy(true); setErr(null); setRes(null); setExpanded(false);
    try {
      setRes(await locateHost(q.trim()));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const isBest = (c: LocateCandidate) => res?.best != null && c.port_id === res.best.port_id;
  const rows = res
    ? (expanded ? res.candidates : res.candidates.slice(0, VISIBLE_ROWS))
    : [];
  const hidden = res ? res.candidates.length - rows.length : 0;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <MapPin size={16} className="text-cyan-400" /> {de.locate.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.locate.hint}</p>
      </div>

      <div className="flex gap-2">
        <div className="flex-1">
          <EndpointAutocomplete value={q} onChange={setQ}
            placeholder={de.locate.placeholder}
            onSubmit={() => q.trim() && search()} />
        </div>
        <button type="button" className="fwpt-btn" onClick={search} disabled={busy || !q.trim()}>
          {busy ? de.locate.searching : de.locate.search}
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res?.self_device && (
        <div className="rounded-md border border-sky-800 bg-sky-950/60 p-3 text-sm text-sky-300">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <Server size={15} />
            <span className="font-semibold">{de.locate.selfDevice}</span>
            <span className="text-slate-300">
              {res.self_device.hostname ?? res.self_device.sys_name}
            </span>
            {res.self_device.hardware && (
              <span className="text-slate-500">· {res.self_device.hardware}</span>
            )}
          </div>
          <p className="mt-1 text-xs text-slate-400">{de.locate.selfDeviceHint}</p>
          {res.self_device.uplinks.length > 0 ? (
            <table className="mt-1.5 text-left text-xs">
              <tbody>
                {res.self_device.uplinks.map((u, i) => (
                  <tr key={`${u.local_port_id}-${i}`}>
                    <td className="py-0.5 pr-3 font-mono text-slate-500">
                      {u.local_port ?? `#${u.local_port_id}`}
                    </td>
                    <td className="py-0.5 pr-2 text-slate-600">→</td>
                    <td className="py-0.5 pr-3 font-mono text-slate-200">
                      {u.remote_hostname}
                      {u.remote_port && <span className="text-slate-500"> / {u.remote_port}</span>}
                    </td>
                    <td className="py-0.5 text-slate-600">{u.remote_platform ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="mt-1 text-xs text-amber-400">{de.locate.selfDeviceNoLldp}</p>
          )}
        </div>
      )}

      {res && (
        <>
          <div className={`rounded-md border p-3 text-sm ${confidenceStyle[res.confidence]}`}>
            {res.best ? (
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="font-semibold text-slate-100">
                  {res.best.hostname ?? `Gerät ${res.best.device_id}`}
                </span>
                <span className="text-slate-500">·</span>
                <span className="font-mono font-semibold">{res.best.if_name ?? '—'}</span>
                {res.best.if_alias && res.best.if_alias !== res.best.if_name && (
                  <span className="text-slate-400">„{res.best.if_alias}“</span>
                )}
                {res.best.match_reason && <MatchBadge reason={res.best.match_reason} />}
                <span className="ml-auto rounded px-1.5 py-0.5 text-[11px] uppercase tracking-wide">
                  {de.locate.confidence[res.confidence]}
                </span>
              </div>
            ) : (
              <span>{de.locate.none}</span>
            )}
          </div>

          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-slate-500">{de.locate.mac}</dt>
            <dd className="font-mono text-slate-300">{res.mac_readable ?? '—'}</dd>
            <dt className="text-slate-500">{de.locate.arpFrom}</dt>
            <dd className="text-slate-300">
              {res.arp
                ? <>
                    {de.locate.provenance[res.arp.provenance]}
                    {res.arp.device && <span className="text-slate-400"> · {res.arp.device}</span>}
                    {res.arp.vdom && <span className="text-slate-500">/{res.arp.vdom}</span>}
                    {res.arp.interface && (
                      <span className="font-mono text-slate-500"> · {res.arp.interface}</span>
                    )}
                  </>
                : '—'}
            </dd>
            {res.best && (
              <>
                <dt className="text-slate-500">{de.locate.seen}</dt>
                <dd className={res.best.stale ? 'text-amber-400' : 'text-slate-300'}>
                  {age(res.best.age_s)}
                  {res.best.stale && <span> · {de.locate.stale}</span>}
                </dd>
              </>
            )}
            {res.aliases.length > 0 && (
              <>
                <dt className="text-slate-500">{de.locate.aliases}</dt>
                <dd className="font-mono text-slate-500">{res.aliases.join(', ')}</dd>
              </>
            )}
          </dl>

          {res.warnings.map((w) => (
            <p key={w} className="text-xs text-amber-400">⚠ {w}</p>
          ))}

          {res.candidates.length > 0 && (
            <div>
              <p className="mb-1 text-xs text-slate-500">{de.locate.candidatesHint}</p>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="px-3 py-1.5 font-medium">{de.locate.device}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.port}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.match}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.klass}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.macs}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.neighbor}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.seen}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((c) => (
                      <tr key={`${c.device_id}-${c.port_id}`}
                        className={isBest(c)
                          ? 'bg-cyan-950/60 text-cyan-200 ring-1 ring-inset ring-cyan-700'
                          : 'text-slate-400'}>
                        <td className="whitespace-nowrap px-3 py-1.5">
                          <span className="text-slate-200">{c.hostname ?? c.device_id}</span>
                          {c.sys_name && c.sys_name !== c.hostname && (
                            <span className="text-slate-500"> ({c.sys_name})</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5 font-mono">
                          {c.if_name ?? '—'}
                          {c.if_alias && c.if_alias !== c.if_name && (
                            <span className="text-slate-500"> · {c.if_alias}</span>
                          )}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5">
                          <MatchBadge reason={c.match_reason} />
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5">
                          <span className={`rounded px-1.5 py-0.5 text-[10px] ${kindStyle[c.port_kind]}`}
                            title={de.locate.kindTitle[c.port_kind]}>
                            {de.locate.kind[c.port_kind]}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5">
                          {c.mac_count > 0 ? c.mac_count : '—'}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-slate-500">
                          {c.neighbor ?? '—'}
                          {c.neighbor && !c.neighbor_monitored && (
                            <span className="ml-1 text-slate-600">(nicht überwacht)</span>
                          )}
                        </td>
                        <td className={`whitespace-nowrap px-3 py-1.5 ${
                          c.stale ? 'text-amber-400' : ''
                        }`}>
                          {age(c.age_s)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {(hidden > 0 || expanded) && (
                <button type="button" className="fwpt-btn-ghost mt-2 text-xs"
                  onClick={() => setExpanded((v) => !v)}>
                  {expanded
                    ? de.locate.showLess
                    : de.locate.showAll.replace('{n}', String(res.candidates.length))}
                </button>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
