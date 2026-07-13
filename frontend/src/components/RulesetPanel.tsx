import { X } from 'lucide-react';
import { de } from '../i18n/de';
import type { Hop } from '../types';
import RulesetTable from './RulesetTable';

// Kandidaten-Regeln eines Hops in voller Breite (statt eingequetscht im Node).
export default function RulesetPanel({ hop, onClose }: { hop: Hop; onClose: () => void }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2">
        <h3 className="text-sm font-medium text-slate-200">
          <span className="text-cyan-400">{hop.device}/{hop.vdom}</span>
          {' — '}{de.hop.candidates} ({hop.candidates.length})
          {hop.srcintf && (
            <span className="ml-2 text-xs font-normal text-slate-500">
              {hop.srcintf} → {hop.egress ?? '?'}
            </span>
          )}
        </h3>
        <button type="button" onClick={onClose} className="text-slate-500 hover:text-slate-300"
          aria-label="Schließen">
          <X size={16} />
        </button>
      </div>
      <p className="border-b border-slate-800/60 px-4 py-2 text-xs text-slate-500">
        {de.hop.candidatesHint}
      </p>
      <RulesetTable candidates={hop.candidates} wide />
    </div>
  );
}
