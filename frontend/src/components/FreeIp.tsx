import { Check, ChevronDown, ChevronRight, Copy, Radar } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { freeIps, ipamTree, type FreeIpEntry, type FreeIpResult, type IpamNode } from '../api';
import { de } from '../i18n/de';

// Freie IP-Adresse finden: Bereich aus dem iTop-IPAM (Baum) oder manuell,
// dann Bestand (iTop/FMG) ausschließen und den Rest live prüfen.

const WANTS = [5, 10, 25, 50];

const verdictStyle: Record<FreeIpEntry['verdict'], string> = {
  free: 'bg-emerald-900/80 text-emerald-200',
  suspect: 'bg-amber-900/80 text-amber-200',
  in_use: 'bg-red-900/80 text-red-200',
  unknown: 'bg-slate-800 text-slate-300',
};
const verdictText: Record<FreeIpEntry['verdict'], string> = {
  free: de.freeip.verdictFree, suspect: de.freeip.verdictSuspect,
  in_use: de.freeip.verdictInUse, unknown: de.freeip.verdictUnknown,
};

function age(seconds: number | null): string {
  if (seconds == null) return '';
  if (seconds < 90) return `${seconds} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h`;
  return `${Math.round(seconds / 86400)} d`;
}

function nodeKey(n: IpamNode): string {
  return `${n.kind}:${n.cidr}:${n.first ?? ''}:${n.name}`;
}

// Ein Knoten passt zum Filter, wenn er oder ein Nachfahre passt — so bleibt
// der Pfad zum Treffer sichtbar.
function matches(n: IpamNode, f: string): boolean {
  if (!f) return true;
  const own = `${n.name} ${n.cidr} ${n.first ?? ''} ${n.last ?? ''}`.toLowerCase();
  return own.includes(f) || n.children.some((c) => matches(c, f));
}

interface Selection { cidr: string; start?: string; end?: string; label: string }

function selectionOf(n: IpamNode): Selection | null {
  if (n.kind === 'site') return null;
  if (n.kind === 'range') return { cidr: n.cidr, start: n.first, end: n.last, label: `${n.first}–${n.last}` };
  return { cidr: n.cidr, label: n.cidr };
}

function TreeNode({ node, depth, filter, expanded, toggle, selected, onSelect }: {
  node: IpamNode; depth: number; filter: string; expanded: Set<string>;
  toggle: (k: string) => void; selected: string | null; onSelect: (s: Selection) => void;
}) {
  if (!matches(node, filter)) return null;
  const key = nodeKey(node);
  const kids = node.children.filter((c) => matches(c, filter));
  const open = expanded.has(key) || (filter.length > 0 && kids.length > 0);
  const sel = selectionOf(node);
  const isSel = sel !== null && selected === `${sel.cidr}|${sel.start ?? ''}`;
  return (
    <div>
      <div className={`flex items-center gap-1 rounded px-1 py-0.5 text-xs ${isSel ? 'bg-cyan-900/60 text-cyan-100' : 'hover:bg-slate-800/60'}`}
        style={{ paddingLeft: `${depth * 14 + 4}px` }}>
        {kids.length > 0 ? (
          <button type="button" className="text-slate-500 hover:text-slate-300" onClick={() => toggle(key)}
            aria-label={open ? 'zuklappen' : 'aufklappen'}>
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        ) : <span className="inline-block w-3" />}
        <button type="button" disabled={sel === null}
          className={`flex min-w-0 flex-1 items-center gap-2 text-left ${sel === null ? 'cursor-default text-slate-300' : ''}`}
          onClick={() => sel && onSelect(sel)}>
          {node.cidr !== '0.0.0.0/0' && (
            <span className="font-mono text-slate-200">
              {node.kind === 'range' ? `${node.first} – ${node.last}` : node.cidr}
            </span>
          )}
          {node.name && <span className={`truncate ${node.cidr === '0.0.0.0/0' ? 'text-slate-300' : 'text-slate-500'}`}>{node.name}</span>}
          {node.dhcp && <span className="rounded bg-amber-900/60 px-1 text-[10px] text-amber-200">{de.freeip.dhcp}</span>}
          {node.kind === 'subnet' && node.gateway && (
            <span className="text-[10px] text-slate-600" title={de.freeip.gateway}>GW {node.gateway}</span>
          )}
        </button>
      </div>
      {open && kids.map((c) => (
        <TreeNode key={nodeKey(c)} node={c} depth={depth + 1} filter={filter} expanded={expanded}
          toggle={toggle} selected={selected} onSelect={onSelect} />
      ))}
    </div>
  );
}

function CopyIp({ ip }: { ip: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button type="button" className="text-slate-500 hover:text-slate-200" title={de.freeip.copy}
      onClick={async () => {
        await navigator.clipboard.writeText(ip);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}>
      {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
    </button>
  );
}

export default function FreeIp() {
  const [tree, setTree] = useState<IpamNode[] | null>(null);
  const [treeErr, setTreeErr] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [cidr, setCidr] = useState('');
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [want, setWant] = useState(10);
  const [res, setRes] = useState<FreeIpResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [onlyFree, setOnlyFree] = useState(false);

  useEffect(() => {
    ipamTree()
      .then((r) => {
        setTree(r.nodes);
        // Standorte offen, Subnetze zu — so sieht man den Bestand auf einen Blick.
        setExpanded(new Set(r.nodes.map(nodeKey)));
      })
      .catch((e) => setTreeErr(e instanceof Error ? e.message : String(e)));
  }, []);

  const f = filter.trim().toLowerCase();
  const selected = cidr.trim() ? `${cidr.trim()}|${start.trim()}` : null;

  function toggle(k: string) {
    setExpanded((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  }
  function select(s: Selection) {
    setCidr(s.cidr); setStart(s.start ?? ''); setEnd(s.end ?? '');
  }

  async function find() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await freeIps(cidr.trim(), want, start.trim() || undefined, end.trim() || undefined));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  const rows = useMemo(
    () => (res ? res.results.filter((r) => !onlyFree || r.verdict === 'free') : []),
    [res, onlyFree],
  );

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Radar size={16} className="text-cyan-400" /> {de.freeip.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.freeip.hint}</p>
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="text-[11px] text-slate-500">{de.freeip.tree}</span>
          <input className="fwpt-input !w-44 !py-0.5 text-xs" value={filter}
            onChange={(e) => setFilter(e.target.value)} placeholder={de.freeip.filter} />
        </div>
        <div className="max-h-56 overflow-y-auto rounded-md border border-slate-800 bg-slate-950 p-1">
          {tree === null && !treeErr && <p className="p-2 text-xs text-slate-500">{de.freeip.loadingTree}</p>}
          {treeErr && <p className="p-2 text-xs text-red-400">{treeErr}</p>}
          {tree && tree.length === 0 && <p className="p-2 text-xs text-slate-500">{de.freeip.noTree}</p>}
          {tree && tree.map((n) => (
            <TreeNode key={nodeKey(n)} node={n} depth={0} filter={f} expanded={expanded}
              toggle={toggle} selected={selected} onSelect={select} />
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <label className="flex min-w-[11rem] flex-1 flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.freeip.manual}</span>
          <input className="fwpt-input font-mono" value={cidr} onChange={(e) => setCidr(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && cidr.trim() && find()} placeholder="10.180.5.0/24" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.freeip.start}</span>
          <input className="fwpt-input w-28 font-mono" value={start} onChange={(e) => setStart(e.target.value)} placeholder="optional" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.freeip.end}</span>
          <input className="fwpt-input w-28 font-mono" value={end} onChange={(e) => setEnd(e.target.value)} placeholder="optional" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.freeip.want}</span>
          <select className="fwpt-input w-20" value={want} onChange={(e) => setWant(Number(e.target.value))}>
            {WANTS.map((w) => <option key={w} value={w}>{w}</option>)}
          </select>
        </label>
        <button type="button" className="fwpt-btn" onClick={find} disabled={busy || !cidr.trim()}>
          {busy ? de.freeip.searching : de.freeip.find}
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res && (
        <>
          {res.warnings.map((w) => <p key={w} className="text-xs text-amber-400">{w}</p>)}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
            <span className="font-mono text-slate-300">
              {res.cidr}{res.start && ` · ${res.start} – ${res.end}`}
            </span>
            <span>
              {res.stats.hosts} {de.freeip.stHosts} · {res.stats.itop_used} {de.freeip.stItop} · {res.stats.ci_used} {de.freeip.stCi}
              {res.stats.fw_used > 0 && ` · ${res.stats.fw_used} ${de.freeip.stFw}`}
              {res.stats.dhcp_skipped > 0 && ` · ${res.stats.dhcp_skipped} ${de.freeip.stDhcp}`}
              {' · '}{res.stats.probed} {de.freeip.stProbed}
            </span>
            {res.dns_domain && <span>DNS: {res.dns_domain}</span>}
            <span className={res.exhausted ? '' : 'text-amber-500'}>
              {res.exhausted ? de.freeip.exhausted : de.freeip.more}
            </span>
            <label className="ml-auto flex items-center gap-1 text-slate-400">
              <input type="checkbox" checked={onlyFree} onChange={(e) => setOnlyFree(e.target.checked)} />
              {de.freeip.onlyFree}
            </label>
          </div>

          {res.stats.free === 0 && <p className="text-sm text-amber-400">{de.freeip.none}</p>}

          {rows.length > 0 && (
            <div className="max-h-80 overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-slate-900 text-slate-500">
                  <tr>
                    <th className="py-1 pr-2">{de.freeip.colIp}</th>
                    <th className="py-1 pr-2">{de.freeip.colVerdict}</th>
                    <th className="py-1 pr-2">{de.freeip.colItop}</th>
                    <th className="py-1 pr-2">{de.freeip.colPing}</th>
                    <th className="py-1 pr-2">{de.freeip.colDns}</th>
                    <th className="py-1">{de.freeip.colArp}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.ip} className="border-t border-slate-800/60">
                      <td className="whitespace-nowrap py-1 pr-2 font-mono text-slate-200">
                        <span className="flex items-center gap-1.5">{r.ip}<CopyIp ip={r.ip} /></span>
                      </td>
                      <td className="py-1 pr-2">
                        <span className={`rounded px-1.5 py-0.5 text-[10px] ${verdictStyle[r.verdict]}`}>{verdictText[r.verdict]}</span>
                      </td>
                      <td className="whitespace-nowrap py-1 pr-2 text-slate-400">
                        {r.itop ? `${r.itop.status}${r.itop.name ? ` · ${r.itop.name}` : ''}` : <span className="text-slate-600">{de.freeip.itopFree}</span>}
                      </td>
                      <td className={`whitespace-nowrap py-1 pr-2 ${r.ping ? 'text-red-300' : r.ping === false ? 'text-slate-400' : 'text-slate-600'}`}>
                        {r.ping ? de.freeip.pingYes : r.ping === false ? de.freeip.pingNo : de.freeip.pingNa}
                      </td>
                      <td className="py-1 pr-2 font-mono text-slate-400">{r.dns ?? <span className="text-slate-600">—</span>}</td>
                      <td className="py-1 text-slate-400">
                        {r.arp ? (
                          <span title={`${r.arp.device ?? ''}${r.arp.vdom ? `/${r.arp.vdom}` : ''}`}>
                            <span className="font-mono">{r.arp.mac}</span>
                            {r.arp.age_s != null && <span className="text-slate-500"> · {de.freeip.seenAgo} {age(r.arp.age_s)}</span>}
                          </span>
                        ) : <span className="text-slate-600">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="text-[11px] text-slate-600">{de.freeip.caveat}</p>
        </>
      )}
    </div>
  );
}
