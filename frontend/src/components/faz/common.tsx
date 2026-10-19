import { AlertTriangle } from 'lucide-react';
import { de } from '../../i18n/de';

// Gemeinsames der drei Ist-Zustand-Ansichten: Zeitangaben, Zeitraum-Auswahl,
// Hinweise zu unvollständigen Suchen.

export function when(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

export function ago(iso: string | null): string {
  if (!iso) return '';
  return de.faz.ago(Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000));
}

/** „19.10., 14:03 (vor 2 h)" — absolut zum Nachschlagen, relativ zum Verstehen. */
export function WhenAgo({ iso }: { iso: string | null }) {
  if (!iso) return <span className="text-slate-600">—</span>;
  return (
    <span title={new Date(iso).toLocaleString('de-DE')}>
      {when(iso)} <span className="text-slate-500">({ago(iso)})</span>
    </span>
  );
}

export function WindowSelect({ value, options, onChange }: {
  value: number; options: number[]; onChange: (v: number) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] text-slate-500">{de.faz.window}</span>
      <select className="fwpt-input w-36" value={value}
        onChange={(e) => onChange(Number(e.target.value))}>
        {options.map((h) => <option key={h} value={h}>{de.faz.windows[h] ?? `${h} h`}</option>)}
      </select>
    </label>
  );
}

export function SearchNotes({ complete, limitHit, lines }: {
  complete: boolean; limitHit: boolean; lines: number;
}) {
  if (complete && !limitHit) return null;
  return (
    <div className="flex items-start gap-2 rounded-md border border-amber-800 bg-amber-950/50 p-2 text-xs text-amber-300">
      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
      <span>{!complete ? de.faz.incomplete : de.faz.limitHit(lines)}</span>
    </div>
  );
}

export function Busy() {
  return (
    <p className="animate-pulse text-sm text-slate-400">
      {de.faz.searching} <span className="text-xs text-slate-500">{de.faz.searchingHint}</span>
    </p>
  );
}

export function devLabel(device: string | null, vdom: string | null): string {
  return `${device ?? '?'}${vdom ? `/${vdom}` : ''}`;
}
