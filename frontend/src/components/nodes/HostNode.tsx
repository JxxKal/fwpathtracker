import { Handle, Position } from '@xyflow/react';
import { Cloud, Monitor, Network } from 'lucide-react';
import { de } from '../../i18n/de';
import type { SwitchportState } from '../../switchports';
import type { NameEntry } from '../../types';
import { ProvenanceIcon } from '../EndpointAutocomplete';

export interface HostNodeData {
  ip: string;
  names: NameEntry[];
  role: 'src' | 'dst' | 'internet';
  // Optional und nachgeladen — der Trace wartet nicht darauf.
  switchport?: SwitchportState;
  [key: string]: unknown;
}

const confidenceColor: Record<string, string> = {
  high: 'text-emerald-400',
  medium: 'text-amber-400',
  low: 'text-orange-400',
  none: 'text-slate-600',
};

function Switchport({ state }: { state: SwitchportState }) {
  if (state.loading) {
    return <p className="text-[11px] text-slate-600">{de.locate.graphSearching}</p>;
  }
  const best = state.result?.best;
  if (!best) {
    // Kein Treffer ist kein Fehler — Zugangsswitch evtl. nicht in LibreNMS.
    return state.result
      ? <p className="text-[11px] text-slate-600">{de.locate.graphNone}</p>
      : null;
  }
  const color = confidenceColor[state.result?.confidence ?? 'none'];
  return (
    <>
      <p className="flex items-center gap-1 truncate text-[11px] text-slate-400"
        title={de.locate.confidence[state.result?.confidence ?? 'none']}>
        <Network size={11} className={`shrink-0 ${color}`} />
        {best.hostname ?? best.sys_name ?? `#${best.device_id}`}
      </p>
      <p className="truncate font-mono text-[11px] text-slate-200"
        title={best.if_alias ?? undefined}>
        {best.if_name ?? '—'}
        {best.if_alias && best.if_alias !== best.if_name && (
          <span className="text-slate-500"> · {best.if_alias}</span>
        )}
      </p>
      {best.stale && <p className="text-[10px] text-amber-500">{de.locate.stale}</p>}
    </>
  );
}

export default function HostNode({ data }: { data: HostNodeData }) {
  const isInternet = data.role === 'internet';
  return (
    <div className="w-52 rounded-lg border border-slate-700 bg-slate-900 p-3 shadow-lg">
      {data.role !== 'src' && <Handle type="target" position={Position.Left} className="!bg-cyan-600" />}
      {data.role === 'src' && <Handle type="source" position={Position.Right} className="!bg-cyan-600" />}
      <div className="flex items-center gap-2">
        {isInternet
          ? <Cloud size={18} className="text-slate-400" />
          : <Monitor size={18} className="text-cyan-400" />}
        <div className="min-w-0">
          <p className="truncate font-mono text-sm text-slate-100">{data.ip}</p>
          {data.names.slice(0, 2).map((n) => (
            <p key={n.provenance + n.name} className="flex items-center gap-1 truncate text-xs text-slate-400">
              <ProvenanceIcon provenance={n.provenance} />
              {n.name}
            </p>
          ))}
        </div>
      </div>
      {/* Nur zeichnen, wenn es etwas zu zeigen gibt — ohne LibreNMS bleibt der
          Knoten unverändert, statt einen leeren Trennstrich zu bekommen. */}
      {!isInternet && data.switchport
        && (data.switchport.loading || data.switchport.result) && (
        <div className="mt-2 min-w-0 border-t border-slate-800 pt-2">
          <Switchport state={data.switchport} />
        </div>
      )}
    </div>
  );
}
