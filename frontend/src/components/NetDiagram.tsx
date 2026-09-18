import { Download, ExternalLink, Map, Play } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { buildDiagram, diagramFilters, diagramScopes, type PhysicalFilters, type DiagramHosts, type DiagramResult, type DiagramScope, type DiagramScopes, type DiagramView } from '../api';
import { de } from '../i18n/de';

// Netzplan als draw.io: Scope wählen, Datei bauen lassen, herunterladen.
// Die Datei wird im Browser aus der API-Antwort erzeugt — kein Server-Download,
// kein zweiter Request mit Token in der URL.
// draw.io öffnet ein Diagramm aus dem URL-Hash (#R = rohes XML, URI-kodiert).
// Bei sehr großen Zeichnungen wird der Link unhandlich — dann Datei-Weg.
const MAX_LINK_BYTES = 1_500_000;
function openInDrawio(base: string, filename: string, xml: string) {
  const url = `${base}/?title=${encodeURIComponent(filename)}#R${encodeURIComponent(xml)}`;
  window.open(url, '_blank', 'noopener');
}

function download(filename: string, xml: string) {
  const blob = new Blob([xml], { type: 'application/xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export default function NetDiagram() {
  const [scopes, setScopes] = useState<DiagramScopes | null>(null);
  const [scope, setScope] = useState<DiagramScope>('vdom');
  const [device, setDevice] = useState('');
  const [vdom, setVdom] = useState('');
  const [site, setSite] = useState('');
  const [hosts, setHosts] = useState<DiagramHosts>('auto');
  const [expand, setExpand] = useState(false);
  const [view, setView] = useState<DiagramView>('struktur');
  // Standort und Gerätegruppe sind Alternativen, keine Filterkette: eine
  // Zeichnung zeigt einen Standort ODER eine Gruppe.
  const [filters, setFilters] = useState<PhysicalFilters | null>(null);
  const [location, setLocation] = useState('');
  const [group, setGroup] = useState('');
  // Die physischen Sichten kommen aus LibreNMS und kennen weder Scope noch
  // Detailstufe — die Felder dafür bleiben ausgeblendet.
  const physical = view.startsWith('physisch');
  const [res, setRes] = useState<DiagramResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    diagramScopes().then((s) => {
      setScopes(s);
      if (s.devices.length > 0) { setDevice(s.devices[0].device); setVdom(s.devices[0].vdoms[0] ?? 'root'); }
      if (s.sites.length > 0) setSite(s.sites[0].name);
    }).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  // Standorte und Gruppen erst holen, wenn eine physische Sicht gewählt ist —
  // sie kosten LibreNMS-Aufrufe und interessieren in den L3-Sichten niemanden.
  useEffect(() => {
    if (!physical || filters) return;
    diagramFilters().then(setFilters)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [physical, filters]);

  const vdoms = useMemo(() => scopes?.devices.find((d) => d.device === device)?.vdoms ?? [], [scopes, device]);
  useEffect(() => { if (vdoms.length > 0 && !vdoms.includes(vdom)) setVdom(vdoms[0]); }, [vdoms, vdom]);

  async function build() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await buildDiagram(
        scope, scope === 'vdom' || scope === 'firewall' ? device : null,
        scope === 'vdom' ? vdom : null, scope === 'site' ? site : null, hosts, expand, view,
        physical ? location || null : null, physical ? group || null : null));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Map size={16} className="text-cyan-400" /> {de.diagram.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.diagram.hint}</p>
      </div>

      {scopes && scopes.devices.length === 0 && <p className="text-sm text-amber-400">{de.diagram.noDevices}</p>}

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.diagram.view}</span>
          <select className="fwpt-input w-56" value={view}
            onChange={(e) => setView(e.target.value as DiagramView)}>
            <option value="struktur">{de.diagram.viewStruktur}</option>
            <option value="logisch">{de.diagram.viewLogisch}</option>
            <option value="physisch-l1">{de.diagram.viewPhysL1}</option>
          </select>
        </label>
        <label className={`flex flex-col gap-1 ${physical ? 'hidden' : ''}`}>
          <span className="text-[11px] text-slate-500">{de.diagram.scope}</span>
          <select className="fwpt-input w-52" value={scope} onChange={(e) => setScope(e.target.value as DiagramScope)}>
            <option value="vdom">{de.diagram.scopeVdom}</option>
            <option value="firewall">{de.diagram.scopeFirewall}</option>
            <option value="site">{de.diagram.scopeSite}</option>
            <option value="global">{de.diagram.scopeGlobal}</option>
          </select>
        </label>
        {!physical && (scope === 'vdom' || scope === 'firewall') && (
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.diagram.device}</span>
            <select className="fwpt-input w-44 font-mono" value={device} onChange={(e) => setDevice(e.target.value)}>
              {(scopes?.devices ?? []).map((d) => (
                <option key={d.device} value={d.device} title={d.site_detail ?? undefined}>
                  {d.device}{d.site ? ` — ${d.site}` : ''}
                </option>
              ))}
            </select>
          </label>
        )}
        {!physical && scope === 'vdom' && (
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.diagram.vdom}</span>
            <select className="fwpt-input w-32 font-mono" value={vdom} onChange={(e) => setVdom(e.target.value)}>
              {vdoms.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
        )}
        {!physical && scope === 'site' && (
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.diagram.site}</span>
            <select className="fwpt-input w-52" value={site} onChange={(e) => setSite(e.target.value)}>
              {(scopes?.sites ?? []).map((s) => (
                <option key={s.name} value={s.name}
                  title={[s.cidr, s.description].filter(Boolean).join(' · ')}>
                  {s.name} ({s.devices.length})
                </option>
              ))}
            </select>
          </label>
        )}
        {physical && (
          <>
            <label className="flex flex-col gap-1">
              <span className="text-[11px] text-slate-500">{de.diagram.location}</span>
              <select className="fwpt-input w-60 disabled:opacity-40" value={location}
                disabled={!!group}
                onChange={(e) => { setLocation(e.target.value); setGroup(''); }}>
                <option value="">{de.diagram.filterAll}</option>
                {(filters?.locations ?? []).map((l) => <option key={l} value={l}>{l}</option>)}
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[11px] text-slate-500">{de.diagram.group}</span>
              <select className="fwpt-input w-52 disabled:opacity-40" value={group}
                disabled={!!location}
                onChange={(e) => { setGroup(e.target.value); setLocation(''); }}>
                <option value="">{de.diagram.filterAll}</option>
                {(filters?.groups ?? []).map((g) => (
                  <option key={g.name} value={g.name} title={g.desc ?? undefined}>{g.name}</option>
                ))}
              </select>
            </label>
          </>
        )}
        <label className={`flex flex-col gap-1 ${physical || scope === 'global' ? 'hidden' : ''}`}>
          <span className="text-[11px] text-slate-500">{de.diagram.hosts}</span>
          <select className="fwpt-input w-44" value={hosts} onChange={(e) => setHosts(e.target.value as DiagramHosts)}>
            <option value="auto">{de.diagram.hostsAuto}</option>
            <option value="all">{de.diagram.hostsAll}</option>
            <option value="netdev">{de.diagram.hostsNetdev}</option>
            <option value="none">{de.diagram.hostsNone}</option>
          </select>
        </label>
        <label className={`flex items-center gap-1.5 pb-2 text-xs text-slate-300 ${
          physical || view === 'logisch' || scope === 'global' || hosts === 'none' ? 'hidden' : ''}`} title={de.diagram.expandHint}>
          <input type="checkbox" checked={expand} onChange={(e) => setExpand(e.target.checked)} />
          {de.diagram.expand}
        </label>
        <button type="button" className="fwpt-btn" onClick={build}
          disabled={busy || (physical ? false
            : scope === 'site' ? !site : scope !== 'global' && !device)}>
          <Play size={14} /> {busy ? de.diagram.building : de.diagram.build}
        </button>
      </div>
      <p className="text-[11px] text-slate-600">
        {physical ? `${de.diagram.viewPhysL1Hint} ${de.diagram.filterHint}`
          : view === 'logisch' ? de.diagram.viewLogischHint
          : scope === 'global' ? de.diagram.globalHint
          : de.diagram.hostsHint.replace('{n}', String(scopes?.max_hosts ?? 1500))}
      </p>
      {physical && (filters?.warnings ?? []).map((w) => (
        <p key={w} className="text-sm text-amber-400">{w}</p>
      ))}
      {physical && filters && filters.locations.length === 0
        && filters.groups.length === 0 && filters.warnings.length === 0 && (
        <p className="text-xs text-slate-600">{de.diagram.noFilters}</p>
      )}
      {!physical && scope === 'site' && scopes?.sites.length === 0 && (
        <p className="text-sm text-amber-400">{de.diagram.noSites}</p>
      )}

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res && (
        <div className="space-y-1.5 text-xs">
          {res.warnings.map((w) => <p key={w} className="text-amber-400">{w}</p>)}
          <p className="text-slate-400">
            <span className="text-emerald-300">{de.diagram.done}</span>
            <span className="ml-2 font-mono text-slate-300">{res.filename}</span>
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="fwpt-btn" onClick={() => download(res.filename, res.xml)}>
              <Download size={14} /> {de.diagram.download}
            </button>
            {scopes?.drawio_url && res.xml.length <= MAX_LINK_BYTES && (
              <button type="button" className="fwpt-btn"
                onClick={() => openInDrawio(scopes.drawio_url!, res.filename, res.xml)}>
                <ExternalLink size={14} /> {de.diagram.openDrawio}
              </button>
            )}
          </div>
          {scopes?.drawio_url && (
            res.xml.length <= MAX_LINK_BYTES
              ? <p className="text-slate-600">{de.diagram.openDrawioHint}</p>
              : <p className="text-amber-500">{de.diagram.tooBigForLink}</p>
          )}
          <p className="text-slate-500">
            {res.stats.sites > 0 && `${res.stats.sites} ${de.diagram.statSites} · `}
            {res.stats.devices} {de.diagram.statDevices} · {res.stats.vdoms} {de.diagram.statVdoms} · {res.stats.networks} {de.diagram.statNets}
            {res.hosts_mode !== 'none' && ` · ${res.stats.hosts_shown}/${res.stats.hosts_found} ${de.diagram.statHosts} (${de.diagram.modeShown[res.hosts_mode]})`}
            {' · '}{res.stats.neighbors} {de.diagram.statNeighbors} · {res.stats.switches} {de.diagram.statSwitches}
          </p>
          <p className="text-slate-600">{de.diagram.open}</p>
        </div>
      )}
    </div>
  );
}
