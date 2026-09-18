import { useEffect, useState } from 'react';
import { de } from '../../i18n/de';
import ErrorBoundary from '../ErrorBoundary';
import SideNav, { type NavGroup } from '../SideNav';
import DnsPanel from './DnsPanel';
import DrawioPanel from './DrawioPanel';
import FmgPanel from './FmgPanel';
import ItopPanel from './ItopPanel';
import LibrenmsPanel from './LibrenmsPanel';
import SamlPanel from './SamlPanel';
import ShapesPanel from './ShapesPanel';
import SiteSupernetsPanel from './SiteSupernetsPanel';
import SitesPanel from './SitesPanel';
import SslPanel from './SslPanel';
import TitleBlockPanel from './TitleBlockPanel';
import UsersPanel from './UsersPanel';

// Zwölf Panels untereinander waren eine Scrollstrecke. Dieselbe Seitenleiste
// wie im Tracker und in den Network Tools, nach Aufgabe gruppiert: woher die
// Daten kommen, wie die Zeichnungen aussehen, was ein Standort ist, wer rein
// darf.

const STORAGE_KEY = 'fwpt-settings';

const PANELS: Record<string, () => JSX.Element> = {
  fmg: () => <FmgPanel />,
  itop: () => <ItopPanel />,
  librenms: () => <LibrenmsPanel />,
  dns: () => <DnsPanel />,
  drawio: () => <DrawioPanel />,
  titleblock: () => <TitleBlockPanel />,
  shapes: () => <ShapesPanel />,
  sites: () => <SitesPanel />,
  supernets: () => <SiteSupernetsPanel />,
  users: () => <UsersPanel />,
  ssl: () => <SslPanel />,
  saml: () => <SamlPanel />,
};

const GROUPS: NavGroup[] = [
  {
    id: 'quellen', label: de.settingsNav.groupSources,
    items: [
      { id: 'fmg', label: de.settingsNav.fmg },
      { id: 'itop', label: de.settingsNav.itop },
      { id: 'librenms', label: de.settingsNav.librenms },
      { id: 'dns', label: de.settingsNav.dns },
    ],
  },
  {
    id: 'zeichnungen', label: de.settingsNav.groupDrawings,
    items: [
      { id: 'drawio', label: de.settingsNav.drawio },
      { id: 'titleblock', label: de.settingsNav.titleblock },
      { id: 'shapes', label: de.settingsNav.shapes },
    ],
  },
  {
    id: 'standorte', label: de.settingsNav.groupSites,
    items: [
      { id: 'sites', label: de.settingsNav.sites },
      { id: 'supernets', label: de.settingsNav.supernets },
    ],
  },
  {
    id: 'zugang', label: de.settingsNav.groupAccess,
    items: [
      { id: 'users', label: de.settingsNav.users },
      { id: 'ssl', label: de.settingsNav.ssl },
      { id: 'saml', label: de.settingsNav.saml },
    ],
  },
];

function remembered(): string {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && v in PANELS) return v;
  } catch { /* privater Modus */ }
  return 'fmg';
}

export default function SettingsPanel() {
  const [active, setActive] = useState(remembered);

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, active); } catch { /* egal */ }
  }, [active]);

  const render = PANELS[active] ?? PANELS.fmg;
  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
      <SideNav groups={GROUPS} active={active} onSelect={setActive}
        label={de.settingsNav.pick} />
      <div className="min-w-0 flex-1">
        <ErrorBoundary key={active}>{render()}</ErrorBoundary>
      </div>
    </div>
  );
}
