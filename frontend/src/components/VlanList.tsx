import { Layers, RefreshCw } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { vlanOverview, type VlanOverview, type VlanRow } from '../api';
import { de } from '../i18n/de';

// Globale VLAN-Übersicht: welche Nummer ist wofür vergeben — und was ist frei.
// Zusammengeführt über die VLAN-NUMMER, weil Switch und Firewall dasselbe VLAN
// regelmäßig unterschiedlich benennen. „Frei" heißt: in keiner der beiden
// Quellen gesehen; das ist eine Aussage über den bekannten Bestand, keine
// Reservierungs-Datenbank.

const VISIBLE_ROWS = 15;

function matches(row: VlanRow, needle: string): boolean {
  if (!needle) return true;
  const n = needle.toLowerCase();
  if (String(row.vlan).includes(n)) return true;
  if (row.names.some((x) => x.toLowerCase().includes(n))) return true;
  if (row.networks.some((x) => x.toLowerCase().includes(n))) return true;
  if (row.switches.some((s) => (s.hostname ?? '').toLowerCase().includes(n))) return true;
  return row.firewall_interfaces.some(
    (i) => `${i.device} ${i.vdom} ${i.interface}`.toLowerCase().includes(n));
}

function SourceDot({ row }: { row: VlanRow }) {
  const both = row.sources.length === 2;
  const label = both ? de.vlans.sourceBoth
    : row.sources[0] === 'fmg' ? de.vlans.sourceFmg : de.vlans.sourceLibrenms;
  const style = both ? 'bg-emerald-500' : row.sources[0] === 'fmg' ? 'bg-cyan-500' : 'bg-sky-500';
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${style}`} title={label} />;
}

export default function VlanList() {
  const [res, setRes] = useState<VlanOverview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState('');
  const [expanded, setExpanded] = useState(false);
  const [showFree, setShowFree] = useState(false);

  async function load() {
    setBusy(true); setErr(null);
    try {
      setRes(await vlanOverview());
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { void load(); }, []);

  const filtered = useMemo(
    () => (res ? res.vlans.filter((r) => matches(r, q.trim())) : []), [res, q]);
  // Gefilterte Treffer immer vollständig zeigen: Wer gezielt sucht, darf sein
  // VLAN nicht hinter einem "weitere anzeigen" verlieren — genau so entsteht der
  // Eindruck, ein VLAN fehle in der Übersicht.
  const truncate = !expanded && q.trim().length === 0;
  const rows = truncate ? filtered.slice(0, VISIBLE_ROWS) : filtered;
  const hidden = filtered.length - rows.length;

  return (
    <div className="fwpt-card space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-2 font-medium text-slate-100">
            <Layers size={16} className="text-cyan-400" /> {de.vlans.title}
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">{de.vlans.hint}</p>
        </div>
        <button type="button" className="text-slate-500 hover:text-slate-300"
          onClick={load} disabled={busy} title={de.vlans.reload}>
          <RefreshCw size={15} className={busy ? 'animate-spin' : ''} />
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <input className="fwpt-input" placeholder={de.vlans.filter} value={q}
              onChange={(e) => { setQ(e.target.value); setExpanded(false); }} />
          </div>

          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
            <span>{de.vlans.used}: <span className="text-slate-200">{res.used_count}</span></span>
            <span>{de.vlans.free}: <span className="text-slate-200">{res.free_count}</span></span>
            <span>{de.vlans.shown}: <span className="text-slate-200">
              {rows.length}/{res.vlans.length}</span></span>
            {/* Fehlt ein VLAN, ist die erste Frage, ob sein Switch überhaupt
                VLANs geliefert hat — LibreNMS gibt nur zurück, was seine
                VLAN-Discovery gefunden und das Token sehen darf. */}
            <span title={res.stats.contributing_devices.join(', ')}>
              {de.vlans.fromDevices(res.stats.librenms_devices,
                res.stats.librenms_devices_known)}
            </span>
            <button type="button" className="text-cyan-400 hover:text-cyan-300"
              onClick={() => setShowFree((v) => !v)}>
              {showFree ? de.vlans.hideFree : de.vlans.showFree}
            </button>
          </div>

          {showFree && (
            <p className="rounded-md bg-slate-950/60 p-2 font-mono text-[11px] leading-relaxed text-emerald-400">
              {res.free.map(([lo, hi]) => (lo === hi ? `${lo}` : `${lo}–${hi}`)).join(', ')
                || de.vlans.noneFree}
            </p>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-500">
                <tr>
                  <th className="py-1 pr-2">{de.vlans.colVlan}</th>
                  <th className="py-1 pr-2">{de.vlans.colName}</th>
                  <th className="py-1 pr-2">{de.vlans.colNetwork}</th>
                  <th className="py-1 pr-2">{de.vlans.colSwitches}</th>
                  <th className="py-1">{de.vlans.colFirewall}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.vlan} className="border-t border-slate-800 align-top">
                    <td className="py-1 pr-2">
                      <span className="flex items-center gap-1.5">
                        <SourceDot row={r} />
                        <span className="font-mono text-slate-200">{r.vlan}</span>
                      </span>
                    </td>
                    <td className="py-1 pr-2 text-slate-300">
                      {r.names.length > 0 ? r.names.join(' · ') : (
                        // Kein echter Name: den LibreNMS-Platzhalter NICHT als
                        // Bezeichnung ausgeben — er verdeckt sonst, dass am
                        // Switch nichts hinterlegt ist.
                        <span className="text-slate-600" title={de.vlans.unnamedTitle}>
                          {de.vlans.unnamed}
                        </span>
                      )}
                    </td>
                    <td className="py-1 pr-2 font-mono text-slate-400">
                      {r.networks.join(', ') || '—'}
                    </td>
                    <td className="py-1 pr-2 text-slate-400"
                      title={r.switches
                        .map((s) => `${s.hostname ?? s.device_id}: ${s.placeholder
                          ? de.vlans.unnamed : (s.name ?? de.vlans.unnamed)}`)
                        .join('\n')}>
                      {r.switch_count || '—'}
                    </td>
                    <td className="py-1 text-slate-400">
                      {r.firewall_interfaces.map((i) => (
                        <div key={`${i.device}-${i.interface}`}>
                          {i.interface}
                          <span className="ml-1 text-slate-600">{i.device}/{i.vdom}</span>
                        </div>
                      ))}
                      {r.firewall_interfaces.length === 0 && '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && (
              <p className="py-2 text-xs text-slate-500">{de.vlans.empty}</p>
            )}
            {hidden > 0 && (
              <button type="button" className="mt-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                onClick={() => setExpanded(true)}>
                {de.vlans.showAll(hidden)}
              </button>
            )}
          </div>

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
