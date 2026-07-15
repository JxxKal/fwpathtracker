import { X } from 'lucide-react';
import { useState } from 'react';
import type { Hop, TraceResult } from '../types';
import HopDetailPanel from './HopDetailPanel';
import PathGraph from './PathGraph';

// Grafischer Trace eines Checks als Overlay — inkl. Klick auf Hops (Treffer-Regel /
// bei Deny die Policy-/VDOM-Details + Regelvorschlag). Deny-Hop ist vorausgewählt.
export default function CheckResultModal({ result, onClose }: {
  result: TraceResult; onClose: () => void;
}) {
  const denyHop = result.hops.find((h) => h.verdict === 'DENY') ?? null;
  const [sel, setSel] = useState<Hop | null>(denyHop);

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-black/60 p-4"
      onClick={onClose}>
      <div className="w-full max-w-[1400px] space-y-3 rounded-lg border border-slate-700 bg-slate-950 p-4 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-medium text-slate-100">
            {result.src.ip} → {result.dst.ip} · {result.protocol.toUpperCase()}
            {result.dst_port ? `/${result.dst_port}` : ''}
          </h3>
          {result.dst.names[0] && (
            <span className="text-xs text-slate-500">({result.dst.names[0].name})</span>
          )}
          <button type="button" onClick={onClose} className="ml-auto text-slate-500 hover:text-slate-300"
            aria-label="Schließen">
            <X size={18} />
          </button>
        </div>
        <PathGraph result={result} onSelect={setSel} selectedIndex={sel?.index ?? null} />
        {sel && <HopDetailPanel hop={sel} onClose={() => setSel(null)} />}
      </div>
    </div>
  );
}
