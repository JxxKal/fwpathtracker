import { Download, ExternalLink, Map, Play } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { buildDiagram, diagramScopes, type DiagramHosts, type DiagramResult, type DiagramScopes } from '../api';
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
  const [scope, setScope] = useState<'vdom' | 'firewall'>('vdom');
  const [device, setDevice] = useState('');
  const [vdom, setVdom] = useState('');
  const [hosts, setHosts] = useState<DiagramHosts>('auto');
  const [res, setRes] = useState<DiagramResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    diagramScopes().then((s) => {
      setScopes(s);
      if (s.devices.length > 0) { setDevice(s.devices[0].device); setVdom(s.devices[0].vdoms[0] ?? 'root'); }
    }).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);

  const vdoms = useMemo(() => scopes?.devices.find((d) => d.device === device)?.vdoms ?? [], [scopes, device]);
  useEffect(() => { if (vdoms.length > 0 && !vdoms.includes(vdom)) setVdom(vdoms[0]); }, [vdoms, vdom]);

  async function build() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await buildDiagram(scope, device, scope === 'vdom' ? vdom : null, hosts));
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
          <span className="text-[11px] text-slate-500">{de.diagram.scope}</span>
          <select className="fwpt-input w-40" value={scope} onChange={(e) => setScope(e.target.value as 'vdom' | 'firewall')}>
            <option value="vdom">{de.diagram.scopeVdom}</option>
            <option value="firewall">{de.diagram.scopeFirewall}</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.diagram.device}</span>
          <select className="fwpt-input w-44 font-mono" value={device} onChange={(e) => setDevice(e.target.value)}>
            {(scopes?.devices ?? []).map((d) => <option key={d.device} value={d.device}>{d.device}</option>)}
          </select>
        </label>
        {scope === 'vdom' && (
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.diagram.vdom}</span>
            <select className="fwpt-input w-32 font-mono" value={vdom} onChange={(e) => setVdom(e.target.value)}>
              {vdoms.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
        )}
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.diagram.hosts}</span>
          <select className="fwpt-input w-44" value={hosts} onChange={(e) => setHosts(e.target.value as DiagramHosts)}>
            <option value="auto">{de.diagram.hostsAuto}</option>
            <option value="all">{de.diagram.hostsAll}</option>
            <option value="netdev">{de.diagram.hostsNetdev}</option>
            <option value="none">{de.diagram.hostsNone}</option>
          </select>
        </label>
        <button type="button" className="fwpt-btn" onClick={build} disabled={busy || !device}>
          <Play size={14} /> {busy ? de.diagram.building : de.diagram.build}
        </button>
      </div>
      <p className="text-[11px] text-slate-600">
        {de.diagram.hostsHint.replace('{n}', String(scopes?.max_hosts ?? 1500))}
      </p>

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
            {res.stats.vdoms} {de.diagram.statVdoms} · {res.stats.networks} {de.diagram.statNets} · {res.stats.hosts_shown}/{res.stats.hosts_found} {de.diagram.statHosts}
            {' '}({de.diagram.modeShown[res.hosts_mode]}) · {res.stats.neighbors} {de.diagram.statNeighbors} · {res.stats.switches} {de.diagram.statSwitches}
          </p>
          <p className="text-slate-600">{de.diagram.open}</p>
        </div>
      )}
    </div>
  );
}
