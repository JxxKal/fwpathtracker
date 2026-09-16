import type { ReactNode } from 'react';
import { de } from '../i18n/de';

// Seitenleiste für Bereiche mit mehreren Ansichten (Tracker, Network Tools).
// Eine Komponente für beide, damit die Navigation überall gleich aussieht und
// sich gleich anfühlt — und damit eine Änderung nur an einer Stelle passiert.

export interface NavItem { id: string; label: string; hint?: string }
export interface NavGroup { id: string; label?: string; items: NavItem[] }

export default function SideNav({ groups, active, onSelect, footer, label }: {
  groups: NavGroup[];
  active: string;
  onSelect: (id: string) => void;
  footer?: ReactNode;
  /** Beschriftung der Auswahlliste in der schmalen Ansicht. */
  label?: string;
}) {
  return (
    <>
      {/* Schmale Ansicht: eine Auswahlliste statt der Leiste. */}
      <label className="flex flex-col gap-1 lg:hidden">
        <span className="text-[11px] text-slate-500">{label ?? de.nav.pick}</span>
        <select className="fwpt-input" value={active} onChange={(e) => onSelect(e.target.value)}>
          {groups.map((g) => (
            g.label
              ? (
                <optgroup key={g.id} label={g.label}>
                  {g.items.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
                </optgroup>
              )
              : g.items.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)
          ))}
        </select>
      </label>

      <nav className="hidden w-56 shrink-0 space-y-4 lg:block">
        {groups.map((g) => (
          <div key={g.id}>
            {g.label && (
              <p className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
                {g.label}
              </p>
            )}
            <div className="space-y-0.5">
              {g.items.map((i) => (
                <button
                  key={i.id} type="button" title={i.hint}
                  onClick={() => onSelect(i.id)}
                  className={`w-full rounded-md px-2 py-1.5 text-left text-sm transition-colors ${
                    i.id === active
                      ? 'bg-slate-800 font-medium text-cyan-400'
                      : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                  }`}
                >
                  {i.label}
                </button>
              ))}
            </div>
          </div>
        ))}
        {footer}
      </nav>
    </>
  );
}
