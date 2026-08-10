import { MapPin } from 'lucide-react';
import { useState } from 'react';
import { locateHost, type LocateCandidate, type LocateResult } from '../api';
import { de } from '../i18n/de';

// Wo steckt das Gerät physisch? IP→MAC von der FortiGate (live, über den
// FMG-Proxy), MAC→Port aus der LibreNMS-FDB. Die Kandidatenliste bleibt sichtbar,
// weil dieselbe MAC auf jedem Switch im Pfad steht — der Weg dorthin ist die
// Kontrolle, ob der oberste Treffer plausibel ist.

const confidenceStyle: Record<LocateResult['confidence'], string> = {
  high: 'border-emerald-800 bg-emerald-950/60 text-emerald-300',
  medium: 'border-amber-800 bg-amber-950/60 text-amber-300',
  low: 'border-orange-800 bg-orange-950/60 text-orange-300',
  none: 'border-slate-700 bg-slate-900/60 text-slate-400',
};

function age(seconds: number | null): string {
  if (seconds == null) return '—';
  if (seconds < 90) return `vor ${seconds} s`;
  if (seconds < 5400) return `vor ${Math.round(seconds / 60)} min`;
  return `vor ${Math.round(seconds / 3600)} h`;
}

export default function LocateHost() {
  const [q, setQ] = useState('');
  const [res, setRes] = useState<LocateResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function search() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await locateHost(q.trim()));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const isBest = (c: LocateCandidate) => res?.best != null && c.port_id === res.best.port_id;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <MapPin size={16} className="text-cyan-400" /> {de.locate.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.locate.hint}</p>
      </div>

      <div className="flex gap-2">
        <input
          className="fwpt-input" placeholder={de.locate.placeholder} value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && q.trim() && search()}
        />
        <button type="button" className="fwpt-btn" onClick={search} disabled={busy || !q.trim()}>
          {busy ? de.locate.searching : de.locate.search}
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

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
                {res.best.if_alias && (
                  <span className="text-slate-400">„{res.best.if_alias}"</span>
                )}
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
                      <th className="px-3 py-1.5 font-medium">{de.locate.macs}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.neighbor}</th>
                      <th className="px-3 py-1.5 font-medium">{de.locate.seen}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {res.candidates.map((c) => (
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
                          {c.if_alias && <span className="text-slate-500"> · {c.if_alias}</span>}
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5">
                          {c.mac_count > 0 ? c.mac_count : '—'}
                          <span className="ml-2 rounded bg-slate-700/70 px-1.5 py-0.5 text-[10px]">
                            {c.has_neighbor || c.mac_count > 32
                              ? de.locate.uplink : de.locate.access}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-slate-500">
                          {c.neighbor ?? '—'}
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
            </div>
          )}
        </>
      )}
    </div>
  );
}
