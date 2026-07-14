import { ListPlus } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getChecks, saveChecks, type CheckGroup } from '../api';
import { de } from '../i18n/de';

const uid = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()));

// Aktuellen Trace-Flow in eine Check-Gruppe übernehmen (Soll = aktuelles Verdict).
export default function AddToChecks({ src, dst, protocol, dstPort, verdict }: {
  src: string; dst: string; protocol: string; dstPort: number | null; verdict: string;
}) {
  const [open, setOpen] = useState(false);
  const [groups, setGroups] = useState<CheckGroup[]>([]);
  const [gid, setGid] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    getChecks().then((d) => { setGroups(d.groups); setGid((g) => g || d.groups[0]?.id || ''); })
      .catch(() => undefined);
  }, [open]);

  async function add() {
    setBusy(true); setMsg(null);
    try {
      const doc = await getChecks();              // frisch laden, nicht überschreiben
      const g = doc.groups.find((x) => x.id === gid);
      if (!g) { setMsg(de.checks.noGroups); return; }
      g.checks.push({
        id: uid(), label: `${src} → ${dst}`, src, dst, protocol,
        dst_port: dstPort, expect: verdict === 'DENY' ? 'DENY' : 'ALLOW',
      });
      await saveChecks(doc);
      setMsg(`${de.checks.added} (${g.name})`); setOpen(false);
    } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }

  return (
    <span className="relative">
      <button type="button" className="flex items-center gap-1 hover:text-cyan-400"
        onClick={() => setOpen((o) => !o)} title={de.checks.addToGroup}>
        <ListPlus size={16} />
      </button>
      {open && (
        <span className="absolute right-0 top-7 z-20 flex items-center gap-2 rounded-md border border-slate-700 bg-slate-900 p-2 shadow-xl">
          <select className="fwpt-input py-1" value={gid} onChange={(e) => setGid(e.target.value)}>
            {groups.length === 0 && <option value="">{de.checks.noGroups}</option>}
            {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
          <button type="button" className="fwpt-btn !py-1" onClick={add} disabled={busy || !gid}>
            {de.checks.add}
          </button>
        </span>
      )}
      {msg && <span className="ml-2 text-xs text-slate-400">{msg}</span>}
    </span>
  );
}
