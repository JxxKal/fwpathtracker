import { Check, Link2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { copyText } from '../checkLink';
import { de } from '../i18n/de';
import FreeIp from './FreeIp';
import FreeSubnet from './FreeSubnet';
import HostPortCheck from './HostPortCheck';
import IpCalc from './IpCalc';
import LocateHost from './LocateHost';
import NetDiagram from './NetDiagram';
import NetOwnership from './NetOwnership';
import VlanList from './VlanList';

// Werkzeugkasten: links die Liste nach Aufgabe gruppiert, rechts EIN Werkzeug
// über die volle Breite. Vorher lagen alle acht nebeneinander auf der
// Tracker-Seite — die VLAN-Tabelle und der IPAM-Baum bekamen dort eine halbe
// Bildschirmbreite, und neben einer 700px-Karte stand 600px Leerraum.

export type ToolId =
  | 'netz' | 'switchport' | 'ports' | 'vlans' | 'netzplan' | 'subnetz' | 'freieip' | 'ipcalc';

// `label` ist der kurze Name in der Seitenleiste, nicht der Titel der Karte:
// „Martin Lehmann, wo hängt das Gerät?" ist ein guter Kartentitel und eine
// schlechte Navigationszeile.
interface Tool { id: ToolId; label: string; hint: string; render: () => JSX.Element }
interface Group { id: string; label: string; tools: Tool[] }

export const TOOL_GROUPS: Group[] = [
  {
    id: 'diagnose',
    label: de.tools.groupDiagnose,
    tools: [
      { id: 'netz', label: de.tools.navNetz, hint: de.tools.hintNetz, render: () => <NetOwnership /> },
      { id: 'switchport', label: de.tools.navSwitchport, hint: de.tools.hintSwitchport, render: () => <LocateHost /> },
      { id: 'ports', label: de.tools.navPorts, hint: de.tools.hintPorts, render: () => <HostPortCheck /> },
    ],
  },
  {
    id: 'bestand',
    label: de.tools.groupInventory,
    tools: [
      { id: 'vlans', label: de.tools.navVlans, hint: de.tools.hintVlans, render: () => <VlanList /> },
      { id: 'netzplan', label: de.tools.navDiagram, hint: de.tools.hintDiagram, render: () => <NetDiagram /> },
    ],
  },
  {
    id: 'planung',
    label: de.tools.groupPlanning,
    tools: [
      { id: 'subnetz', label: de.tools.navSubnet, hint: de.tools.hintSubnet, render: () => <FreeSubnet /> },
      { id: 'freieip', label: de.tools.navFreeIp, hint: de.tools.hintFreeIp, render: () => <FreeIp /> },
      { id: 'ipcalc', label: de.tools.navIpCalc, hint: de.tools.hintIpCalc, render: () => <IpCalc /> },
    ],
  },
];

const ALL: Tool[] = TOOL_GROUPS.flatMap((g) => g.tools);
const STORAGE_KEY = 'fwpt-tool';

export function isToolId(v: string | null): v is ToolId {
  return v !== null && ALL.some((t) => t.id === v);
}

/** Teilbarer Link auf ein Werkzeug — dasselbe Muster wie bei den Checks. */
export function buildToolLink(id: ToolId): string {
  const url = new URL(window.location.href);
  url.search = '';
  url.hash = '';
  url.searchParams.set('tab', 'werkzeuge');
  url.searchParams.set('tool', id);
  return url.toString();
}

function remembered(): ToolId {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (isToolId(v)) return v;
  } catch { /* privater Modus: dann eben das erste Werkzeug */ }
  return ALL[0].id;
}

/** Link auf genau dieses Werkzeug — zum Verschicken, wie bei den Checks. */
function CopyToolLink({ id }: { id: ToolId }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button" className="fwpt-btn-ghost w-full justify-center text-xs"
      onClick={async () => {
        if (await copyText(buildToolLink(id))) {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }
      }}
    >
      {done ? <Check size={13} className="text-emerald-400" /> : <Link2 size={13} />}
      {done ? de.tools.linkCopied : de.tools.link}
    </button>
  );
}

export default function ToolsPanel({ initial }: { initial?: ToolId | null }) {
  const [active, setActive] = useState<ToolId>(() => initial ?? remembered());

  useEffect(() => { if (initial) setActive(initial); }, [initial]);
  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, active); } catch { /* egal */ }
  }, [active]);

  const tool = ALL.find((t) => t.id === active) ?? ALL[0];

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
      {/* Schmale Ansicht: eine Auswahlliste statt der Seitenleiste. */}
      <label className="flex flex-col gap-1 lg:hidden">
        <span className="text-[11px] text-slate-500">{de.tools.pick}</span>
        <select className="fwpt-input" value={active}
          onChange={(e) => setActive(e.target.value as ToolId)}>
          {TOOL_GROUPS.map((g) => (
            <optgroup key={g.id} label={g.label}>
              {g.tools.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </optgroup>
          ))}
        </select>
      </label>

      <nav className="hidden w-60 shrink-0 space-y-4 lg:block">
        {TOOL_GROUPS.map((g) => (
          <div key={g.id}>
            <p className="mb-1 px-2 text-[11px] font-medium uppercase tracking-wide text-slate-500">
              {g.label}
            </p>
            <div className="space-y-0.5">
              {g.tools.map((t) => (
                <button
                  key={t.id} type="button" title={t.hint}
                  onClick={() => setActive(t.id)}
                  className={`w-full rounded-md px-2 py-1.5 text-left text-sm transition-colors ${
                    t.id === active
                      ? 'bg-slate-800 font-medium text-cyan-400'
                      : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
        ))}
        <CopyToolLink id={active} />
      </nav>

      <div className="min-w-0 flex-1">{tool.render()}</div>
    </div>
  );
}
