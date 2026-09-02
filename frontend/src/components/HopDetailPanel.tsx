import { Activity, X } from 'lucide-react';
import { de } from '../i18n/de';
import type { Hop, SessionProbe } from '../types';
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

      {hop.sessions && <SessionCard probe={hop.sessions} />}

      {hop.verdict === 'DENY' && hop.suggestion && (
        <SuggestionCard suggestion={hop.suggestion} />
      )}
    </div>
  );
}

// Ist-Nachweis: was auf diesem VDOM gerade wirklich läuft. Bewusst mit den
// Metadaten (gelesene Einträge, abgeschnitten, serverseitig gefiltert) — ohne
// die ist ein "keine Session" nicht interpretierbar.
function SessionCard({ probe }: { probe: SessionProbe }) {
  const meta: string[] = [de.sessions.scanned(probe.returned)];
  if (probe.truncated) meta.push(de.sessions.truncated);
  if (probe.returned > 0 && probe.server_filtered === false) meta.push(de.sessions.unfiltered);

  return (
    <div className="fwpt-card space-y-2">
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <Activity size={15} className="text-cyan-400" />
        <h3 className="text-sm font-medium">{de.sessions.title}</h3>
        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${
          probe.match_count > 0
            ? 'bg-emerald-900/70 text-emerald-300 ring-emerald-700'
            : 'bg-slate-800 text-slate-400 ring-slate-700'
        }`}>
          {de.sessions.found(probe.match_count)}
        </span>
      </div>
      <p className="text-xs text-slate-500">{de.sessions.hint}</p>

      {probe.samples.length > 0 ? (
        <table className="w-full text-left text-xs">
          <thead className="text-slate-500">
            <tr>
              <th className="py-1 font-normal">{de.sessions.flow}</th>
              <th className="py-1 font-normal">{de.sessions.intf}</th>
              <th className="py-1 font-normal">{de.sessions.rule}</th>
              <th className="py-1 text-right font-normal">{de.sessions.age}</th>
            </tr>
          </thead>
          <tbody className="font-mono text-slate-300">
            {probe.samples.map((s, i) => (
              <tr key={i} className="border-t border-slate-800/70">
                <td className="py-1">
                  {s.src}:{s.srcport} → {s.dst}:{s.dstport}
                  <span className="ml-1 text-slate-500">{s.protocol}</span>
                  {s.nat_dst && <span className="ml-1 text-amber-400">NAT → {s.nat_dst}</span>}
                </td>
                <td className="py-1 text-slate-400">{s.srcintf || '?'} → {s.dstintf || '?'}</td>
                <td className="py-1">{s.policyid !== null ? `#${s.policyid}` : '—'}</td>
                <td className="py-1 text-right text-slate-400">
                  {s.duration !== null ? de.sessions.seconds(s.duration) : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-sm text-slate-400">{de.sessions.none}</p>
      )}

      <p className="text-[11px] text-slate-500">{meta.join(' · ')}</p>
    </div>
  );
}
