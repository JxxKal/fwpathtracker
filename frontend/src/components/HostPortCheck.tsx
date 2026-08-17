import { Network, Router, Server } from 'lucide-react';
import { useState } from 'react';
import { hostPorts, type HostPortFinding, type HostPortsResult } from '../api';
import { de } from '../i18n/de';

// Netzwerkport-Check: das vollständige VLAN-Bild eines Hosts. Anders als die
// Switchport-Suche wird hier nichts verengt — jede Fundstelle bleibt sichtbar,
// weil ein Host durchaus in mehreren VLANs und auf mehreren Ports steht
// (Teaming, Hypervisor-Trunk, zweite NIC).

const DEVICE_ROWS = 10;

function VlanChip({ number, name, tone = 'cyan' }: {
  number: number; name?: string | null; tone?: 'cyan' | 'slate';
}) {
  const style = tone === 'cyan'
    ? 'bg-cyan-900/70 text-cyan-200' : 'bg-slate-700/70 text-slate-300';
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] ${style}`} title={name ?? undefined}>
      {number}{name ? ` · ${name}` : ''}
    </span>
  );
}

/** Konfigurierte Mitgliedschaft (ports_vlans) — untagged zuerst, dann tagged. */
function PortVlanCell({ f }: { f: HostPortFinding }) {
  if (!f.port_vlans) return <span className="text-slate-600">—</span>;
  const { untagged, tagged } = f.port_vlans;
  return (
    <div className="flex flex-wrap gap-1">
      {untagged.map((v) => <VlanChip key={`u${v}`} number={v} />)}
      {tagged.map((v) => (
        <span key={`t${v}`} className="rounded px-1.5 py-0.5 text-[10px] text-slate-400"
          title={de.hostPorts.tagged}>
          {v}
        </span>
      ))}
    </div>
  );
}

export default function HostPortCheck() {
  const [q, setQ] = useState('');
  const [res, setRes] = useState<HostPortsResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [allPorts, setAllPorts] = useState(false);

  async function search() {
    setBusy(true); setErr(null); setRes(null); setAllPorts(false);
    try {
      setRes(await hostPorts(q.trim()));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const ports = res?.device
    ? (allPorts ? res.device.ports : res.device.ports.slice(0, DEVICE_ROWS))
    : [];
  const hiddenPorts = res?.device ? res.device.ports.length - ports.length : 0;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Network size={16} className="text-cyan-400" /> {de.hostPorts.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.hostPorts.hint}</p>
      </div>

      <div className="flex gap-2">
        <input
          className="fwpt-input" placeholder={de.hostPorts.placeholder} value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && q.trim() && search()}
        />
        <button type="button" className="fwpt-btn" onClick={search} disabled={busy || !q.trim()}>
          {busy ? de.hostPorts.searching : de.hostPorts.search}
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res && (
        <>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
            <span className="text-slate-200">{res.ip}</span>
            {res.names.length > 0 && <span>{res.names.join(' · ')}</span>}
            {res.mac_readable && <span className="font-mono">{res.mac_readable}</span>}
          </div>

          {/* Die eigentliche Antwort: in welchen VLANs hängt der Host. */}
          {res.vlan_summary.length > 0 && (
            <div className="rounded-md border border-cyan-900 bg-cyan-950/40 p-2">
              <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-cyan-400">
                {de.hostPorts.summary}
              </p>
              <div className="space-y-1">
                {res.vlan_summary.map((v) => (
                  <div key={v.vlan} className="flex flex-wrap items-center gap-2 text-xs">
                    <VlanChip number={v.vlan} name={v.name} />
                    <span className="text-slate-400">{v.where.join(' · ')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {res.findings.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-500">
                  <tr>
                    <th className="py-1 pr-2">{de.hostPorts.colSwitch}</th>
                    <th className="py-1 pr-2">{de.hostPorts.colPort}</th>
                    <th className="py-1 pr-2">{de.hostPorts.colVlanSeen}</th>
                    <th className="py-1 pr-2">{de.hostPorts.colVlanConfigured}</th>
                    <th className="py-1">{de.hostPorts.colStatus}</th>
                  </tr>
                </thead>
                <tbody>
                  {res.findings.map((f) => (
                    <tr key={`${f.device_id}-${f.port_id}`}
                      className={`border-t border-slate-800 ${f.best ? 'bg-slate-800/40' : ''}`}>
                      <td className="py-1 pr-2 text-slate-300">{f.hostname ?? '—'}</td>
                      <td className="py-1 pr-2">
                        <span className="text-slate-200">{f.if_name ?? '—'}</span>
                        {f.if_alias && (
                          <span className="ml-1 text-slate-500">„{f.if_alias}“</span>
                        )}
                      </td>
                      <td className="py-1 pr-2">
                        {f.vlan
                          ? <VlanChip number={f.vlan.number} name={f.vlan.name} />
                          : <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-1 pr-2"><PortVlanCell f={f} /></td>
                      <td className="py-1 text-slate-400">
                        {f.oper_status ?? '—'}
                        {f.stale && <span className="ml-1 text-amber-500">·{de.hostPorts.stale}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-1 text-[11px] text-slate-500">{de.hostPorts.vlanSourceHint}</p>
            </div>
          )}

          {/* Host ist selbst ein überwachtes Gerät → seine komplette Portliste. */}
          {res.device && (
            <div className="rounded-md border border-sky-900 bg-sky-950/40 p-2">
              <p className="mb-1 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-sky-400">
                <Server size={13} /> {de.hostPorts.devicePorts}
                <span className="normal-case text-slate-400">
                  {res.device.hostname ?? res.device.sys_name} · {res.device.ports.length}
                </span>
              </p>
              <table className="w-full text-left text-xs">
                <tbody>
                  {ports.map((p) => (
                    <tr key={p.port_id} className="border-t border-slate-800/60">
                      <td className="py-1 pr-2 text-slate-200">{p.if_name ?? '—'}</td>
                      <td className="py-1 pr-2 text-slate-500">{p.if_alias ?? ''}</td>
                      <td className="py-1 pr-2">
                        <div className="flex flex-wrap gap-1">
                          {p.vlans_observed.map((v) => (
                            <VlanChip key={v} number={v} tone="slate" />
                          ))}
                        </div>
                      </td>
                      <td className="py-1 text-right text-slate-500">
                        {p.mac_count > 0 && `${p.mac_count} MAC`}
                        <span className={`ml-2 ${p.oper_status === 'up' ? 'text-emerald-500' : 'text-slate-600'}`}>
                          {p.oper_status ?? '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {hiddenPorts > 0 && (
                <button type="button" className="mt-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  onClick={() => setAllPorts(true)}>
                  {de.hostPorts.showAll(hiddenPorts)}
                </button>
              )}
              <p className="mt-1 text-[11px] text-slate-500">{de.hostPorts.observedHint}</p>
            </div>
          )}

          {res.l3.length > 0 && (
            <div className="rounded-md border border-slate-800 bg-slate-950/60 p-2">
              <p className="mb-1 flex items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-slate-400">
                <Router size={13} /> {de.hostPorts.l3}
              </p>
              {res.l3.map((i) => (
                <div key={`${i.device}-${i.interface}`}
                  className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-400">
                  {i.vlan != null
                    ? <VlanChip number={i.vlan} name={i.alias} />
                    : <span className="text-slate-600">{de.hostPorts.noVlanTag}</span>}
                  <span className="text-slate-200">{i.device}/{i.vdom}</span>
                  <span>{i.interface}</span>
                  {i.zone !== i.interface && <span className="text-slate-500">{i.zone}</span>}
                  <span className="font-mono text-slate-500">{i.ip ?? i.network}</span>
                </div>
              ))}
            </div>
          )}

          {res.warnings.length > 0 && (
            <ul className="space-y-1 text-xs text-amber-400">
              {res.warnings.map((w) => <li key={w}>{w}</li>)}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
