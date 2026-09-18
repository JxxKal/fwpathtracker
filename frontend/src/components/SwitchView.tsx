import { Network } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  switchViewDevices, switchViewFilters, switchViewLoad,
  type PhysicalFilters, type SwitchEntry, type SwitchPort, type SwitchViewResult,
} from '../api';
import { de } from '../i18n/de';

// Switch-Ansicht: was hängt an welchem Port.
//
// Die draw.io-Datei ist der Weg aufs Papier. Beim Nachsehen im Alltag will man
// klicken: Switch wählen, Blech sehen, auf eine Buchse klicken und lesen, was
// daran hängt. Ist für das Modell ein Bild mit zugeordneten Buchsen hinterlegt,
// zeigt die Ansicht dieselbe Frontblende wie der Plan; sonst ein Raster.

const PORT_W = 54;
const PORT_H = 30;
const PER_ROW = 24;

/** Gemeinsames Präfix der Portnamen — „Ten-GigabitEthernet1/0/24" ist auf
 *  einem Kästchen nicht zu lesen, „24" schon. Voller Name im Tooltip. */
function commonPrefix(names: string[]): string {
  if (names.length < 3) return '';
  let p = names[0];
  for (const n of names.slice(1)) {
    while (p && !n.toUpperCase().startsWith(p.toUpperCase())) p = p.slice(0, -1);
    if (!p) return '';
  }
  const atNumber = /[A-Za-z]$/.test(p) && names.every((n) => /^\d/.test(n.slice(p.length)));
  if (!atNumber) {
    const cut = Math.max(p.lastIndexOf('-'), p.lastIndexOf('_'),
      p.lastIndexOf('.'), p.lastIndexOf('/'));
    p = cut > 0 ? p.slice(0, cut + 1) : '';
  }
  return p.length >= 4 && names.every((n) => n.length > p.length) ? p : '';
}

function portColor(p: SwitchPort): string {
  if (p.uplink) return 'bg-purple-900/70 border-purple-600 text-purple-100';
  if (p.hosts.length) return 'bg-emerald-900/70 border-emerald-600 text-emerald-100';
  if (!p.up) return 'bg-slate-900 border-slate-800 text-slate-600';
  return 'bg-slate-800 border-slate-700 text-slate-400';
}

function age(seconds: number | null | undefined): string {
  if (seconds == null) return '';
  if (seconds < 90) return `${seconds} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} d`;
}

export default function SwitchView() {
  const [filters, setFilters] = useState<PhysicalFilters | null>(null);
  const [location, setLocation] = useState('');
  const [group, setGroup] = useState('');
  const [devices, setDevices] = useState<SwitchEntry[]>([]);
  const [deviceId, setDeviceId] = useState('');
  const [data, setData] = useState<SwitchViewResult | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    switchViewFilters().then(setFilters)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    switchViewDevices(location || undefined, group || undefined).then((r) => {
      setDevices(r.devices);
      setDeviceId((d) => (r.devices.some((x) => x.device_id === d)
        ? d : r.devices[0]?.device_id ?? ''));
    }).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [location, group]);

  useEffect(() => {
    if (!deviceId) { setData(null); return; }
    setBusy(true); setErr(null); setSelected(null);
    switchViewLoad(deviceId)
      .then(setData)
      .catch((e) => { setData(null); setErr(e instanceof Error ? e.message : String(e)); })
      .finally(() => setBusy(false));
  }, [deviceId]);

  const port = useMemo(
    () => data?.ports.find((p) => p.port_id === selected) ?? null,
    [data, selected],
  );
  const prefix = useMemo(
    () => commonPrefix((data?.ports ?? []).map((p) => p.name)),
    [data],
  );
  const short = (name: string) =>
    (prefix && name.toUpperCase().startsWith(prefix.toUpperCase())
      ? name.slice(prefix.length) : name);
  const shown = data?.shape ? Math.min(data.shape.width, 1100) : 0;
  const scale = data?.shape ? shown / data.shape.width : 1;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Network size={16} className="text-cyan-400" /> {de.switchView.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.switchView.hint}</p>
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.diagram.location}</span>
          <select className="fwpt-input w-56 disabled:opacity-40" value={location}
            disabled={!!group} onChange={(e) => setLocation(e.target.value)}>
            <option value="">{de.diagram.filterAll}</option>
            {(filters?.locations ?? []).map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.diagram.group}</span>
          <select className="fwpt-input w-48 disabled:opacity-40" value={group}
            disabled={!!location} onChange={(e) => setGroup(e.target.value)}>
            <option value="">{de.diagram.filterAll}</option>
            {(filters?.groups ?? []).map((g) => (
              <option key={g.name} value={g.name} title={g.desc ?? undefined}>{g.name}</option>
            ))}
          </select>
        </label>
        <label className="flex flex-1 flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.diagram.switchPick}</span>
          <select className="fwpt-input font-mono" value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}>
            {devices.map((d) => (
              <option key={d.device_id} value={d.device_id}
                title={[d.hardware, d.location].filter(Boolean).join(' · ') || undefined}>
                {d.name}{d.ip ? ` — ${d.ip}` : ''}
              </option>
            ))}
          </select>
        </label>
      </div>

      {(filters?.warnings ?? []).map((w) => <p key={w} className="text-sm text-amber-400">{w}</p>)}
      {err && <p className="text-sm text-red-400">{err}</p>}
      {busy && <p className="text-sm text-slate-500">{de.common.loading}</p>}
      {!busy && devices.length === 0 && !err && (
        <p className="text-sm text-amber-400">{de.diagram.noSwitches}</p>
      )}

      {data && (
        <>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
            <span className="text-sm text-slate-200">{data.device.name}</span>
            {data.device.ip && <span className="font-mono">{data.device.ip}</span>}
            {data.device.hardware && <span>{data.device.hardware}</span>}
            {data.device.location && <span>{data.device.location}</span>}
            <span>{de.switchView.ports(data.ports.length)}</span>
            {prefix && <span className="text-slate-600">{prefix}…</span>}
            {data.logical > 0 && <span>{de.switchView.logical(data.logical)}</span>}
          </div>
          {data.warnings.map((w) => <p key={w} className="text-xs text-amber-400">{w}</p>)}

          {data.units.map((unit) => {
            const ports = data.ports.filter((p) => p.unit === unit);
            const withSpot = ports.filter((p) => p.spot);
            return (
              <div key={unit} className="space-y-1">
                {data.units.length > 1 && (
                  <p className="text-[11px] uppercase tracking-wide text-slate-500">
                    {de.switchView.unit(unit)}
                  </p>
                )}
                {data.shape && withSpot.length > 0 ? (
                  // Echtes Blech: Buchsen liegen dort, wo sie am Gerät sitzen.
                  <div className="relative inline-block overflow-auto bg-white"
                    style={{ width: shown }}>
                    <img src={data.shape.image} alt="" style={{ width: shown }} className="block" />
                    {withSpot.map((p) => (
                      <button key={p.port_id} type="button" title={p.name}
                        onClick={() => setSelected(p.port_id)}
                        className={`absolute rounded-sm border-2 ${
                          p.port_id === selected ? 'border-cyan-400 bg-cyan-400/40'
                            : p.uplink ? 'border-purple-500 bg-purple-400/30'
                              : p.hosts.length ? 'border-emerald-500 bg-emerald-400/30'
                                : 'border-slate-400/60'}`}
                        style={{
                          left: (p.spot!.x - p.spot!.w / 2) * scale,
                          top: (p.spot!.y - p.spot!.h / 2) * scale,
                          width: p.spot!.w * scale, height: p.spot!.h * scale,
                        }} />
                    ))}
                  </div>
                ) : null}

                {/* Raster — für alles ohne zugeordnete Buchse, und als Ganzes,
                    wenn für das Modell kein Blech hinterlegt ist. */}
                <div className="flex flex-wrap gap-1"
                  style={{ maxWidth: PER_ROW * (PORT_W + 4) }}>
                  {(data.shape ? ports.filter((p) => !p.spot) : ports).map((p) => (
                    <button key={p.port_id} type="button" onClick={() => setSelected(p.port_id)}
                      title={[p.name, p.alias, p.uplink ? `Uplink ${p.neighbour}` : null]
                        .filter(Boolean).join(' · ')}
                      className={`truncate rounded border px-1 text-[10px] ${portColor(p)} ${
                        p.port_id === selected ? 'ring-2 ring-cyan-400' : ''}`}
                      style={{ width: PORT_W, height: PORT_H }}>
                      {short(p.name)}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}

          {port ? (
            <div className="rounded-md border border-cyan-900 bg-cyan-950/30 p-3">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                <span className="font-mono text-cyan-300">{port.name}</span>
                {port.alias && <span className="text-slate-300">{port.alias}</span>}
                <span className={port.up ? 'text-emerald-400' : 'text-slate-500'}>
                  {port.up ? de.switchView.up : de.switchView.down}
                </span>
                {port.uplink && (
                  <span className="text-purple-300">
                    {de.switchView.uplinkTo} {port.neighbour}
                  </span>
                )}
                <span className="text-xs text-slate-500">
                  {de.switchView.macs(port.mac_count)}
                </span>
              </div>
              {port.uplink ? (
                <p className="mt-2 text-xs text-slate-500">{de.switchView.uplinkHint}</p>
              ) : port.hosts.length === 0 ? (
                <p className="mt-2 text-xs text-slate-500">{de.switchView.empty}</p>
              ) : (
                <table className="mt-2 w-full text-left text-xs">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="py-1 pr-3">{de.switchView.colName}</th>
                      <th className="py-1 pr-3">{de.switchView.colIp}</th>
                      <th className="py-1 pr-3">{de.switchView.colMac}</th>
                      <th className="py-1">{de.switchView.colSeen}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {port.hosts.map((h) => (
                      <tr key={h.mac} className="border-t border-slate-800/60">
                        <td className="py-1 pr-3 text-slate-200">{h.name ?? '—'}</td>
                        <td className="py-1 pr-3 font-mono text-slate-300">{h.ip ?? '—'}</td>
                        <td className="py-1 pr-3 font-mono text-slate-400">{h.mac_readable}</td>
                        <td className="py-1 text-slate-500">{age(h.age_s)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500">{de.switchView.pick}</p>
          )}

          <details className="text-xs">
            <summary className="cursor-pointer text-slate-500">{de.switchView.allPorts}</summary>
            <table className="mt-2 w-full text-left">
              <thead className="text-slate-500">
                <tr>
                  <th className="py-1 pr-3">{de.switchView.colPort}</th>
                  <th className="py-1 pr-3">{de.switchView.colAlias}</th>
                  <th className="py-1 pr-3">{de.switchView.colState}</th>
                  <th className="py-1">{de.switchView.colDevices}</th>
                </tr>
              </thead>
              <tbody>
                {data.ports.map((p) => (
                  <tr key={p.port_id}
                    onClick={() => setSelected(p.port_id)}
                    className={`cursor-pointer border-t border-slate-800/60 hover:bg-slate-800/50 ${
                      p.port_id === selected ? 'bg-cyan-950/40' : ''}`}>
                    <td className="py-1 pr-3 font-mono text-slate-300">{p.name}</td>
                    <td className="py-1 pr-3 text-slate-500">{p.alias ?? ''}</td>
                    <td className="py-1 pr-3">
                      {p.uplink ? <span className="text-purple-300">Uplink</span>
                        : p.up ? <span className="text-emerald-400">up</span>
                          : <span className="text-slate-600">down</span>}
                    </td>
                    <td className="py-1 text-slate-400">
                      {p.hosts.map((h) => h.name ?? h.ip ?? h.mac_readable).join(', ')
                        || (p.mac_count ? de.switchView.macs(p.mac_count) : '')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </>
      )}
    </div>
  );
}
