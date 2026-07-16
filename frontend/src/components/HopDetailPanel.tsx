import { X } from 'lucide-react';
import { de } from '../i18n/de';
import type { Hop } from '../types';
import PolicyCard from './PolicyCard';
import SuggestionCard from './SuggestionCard';

const verdictStyles: Record<string, string> = {
  ALLOW: 'bg-emerald-900/70 text-emerald-300 ring-emerald-700',
  DENY: 'bg-red-900/70 text-red-300 ring-red-700',
  UNKNOWN: 'bg-amber-900/70 text-amber-300 ring-amber-700',
};

// Vorschau pro geklickter Firewall/VDOM: die EINE greifende Regel — und an einer
// Deny-VDOM zusätzlich der Regelvorschlag (+ FortiManager-Link).
export default function HopDetailPanel({ hop, onClose }: { hop: Hop; onClose: () => void }) {
  return (
    <div className="space-y-3">
      <div className="fwpt-card space-y-3">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <h3 className="text-sm font-medium">
            <span className="text-cyan-400">{hop.device}/{hop.vdom}</span>
            <span className="ml-2 text-xs font-normal text-slate-500">
              {hop.srcintf} → {hop.egress ?? '?'}
            </span>
          </h3>
          <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${
            verdictStyles[hop.verdict]
          }`}>
            {de.verdict[hop.verdict]}
          </span>
          <button type="button" onClick={onClose} className="ml-auto text-slate-500 hover:text-slate-300"
            aria-label="Schließen">
            <X size={16} />
          </button>
        </div>

        <p className="text-xs font-medium uppercase text-slate-500">{de.hopDetail.matchedRule}</p>
        {hop.matched_policy ? (
          <PolicyCard policy={hop.matched_policy} />
        ) : (
          <p className="text-sm text-red-400">{de.hopDetail.implicitDeny}</p>
        )}
      </div>

      {hop.verdict === 'DENY' && hop.suggestion && (
        <SuggestionCard suggestion={hop.suggestion} />
      )}
    </div>
  );
}
