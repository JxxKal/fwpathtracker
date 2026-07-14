import { CheckCircle2, Play, Plus, Trash2, XCircle } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { getChecks, runChecks, saveChecks } from '../api';
import type { CheckGroup, CheckItem, CheckResult, ChecksDoc } from '../api';
import { de } from '../i18n/de';

const uid = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()));

const blankCheck = (): CheckItem => ({
  id: uid(), label: '', src: '', dst: '', protocol: 'tcp', dst_port: 443, expect: 'ALLOW',
});

export default function ChecksPanel({ isAdmin }: { isAdmin: boolean }) {
  const [groups, setGroups] = useState<CheckGroup[]>([]);
  const [selId, setSelId] = useState<string | null>(null);
  const [draft, setDraft] = useState<CheckItem>(blankCheck());
  const [results, setResults] = useState<CheckResult[] | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getChecks().then((d: ChecksDoc) => {
      setGroups(d.groups);
      setSelId((s) => s ?? d.groups[0]?.id ?? null);
    }).catch(() => undefined);
  }, []);

  const group = useMemo(() => groups.find((g) => g.id === selId) ?? null, [groups, selId]);

  function mutate(fn: (gs: CheckGroup[]) => CheckGroup[]) {
    setGroups(fn); setStatus(null); setResults(null);
  }
  function updateGroup(id: string, fn: (g: CheckGroup) => CheckGroup) {
    mutate((gs) => gs.map((g) => (g.id === id ? fn(g) : g)));
  }

  function newGroup() {
    const g: CheckGroup = { id: uid(), name: `Gruppe ${groups.length + 1}`, checks: [] };
    mutate((gs) => [...gs, g]); setSelId(g.id);
  }
  function addCheck() {
    if (!group || !draft.src.trim() || !draft.dst.trim()) return;
    updateGroup(group.id, (g) => ({ ...g, checks: [...g.checks, { ...draft, id: uid() }] }));
    setDraft(blankCheck());
  }

  async function save() {
    setBusy(true);
    try {
      const saved = await saveChecks({ groups });
      setGroups(saved.groups); setStatus(de.checks.saved);
    } catch (e) { setStatus(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }

  async function run() {
    if (!group || group.checks.length === 0) return;
    setBusy(true); setResults(null); setStatus(null);
    try {
      const r = await runChecks(group.checks);
      setResults(r.results);
      setStatus(`${r.passed}/${r.total} ${de.checks.passed}`);
    } catch (e) { setStatus(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }

  const resultFor = (c: CheckItem) => results?.find((r) => r.id === c.id) ?? null;

  return (
    <div className="fwpt-card space-y-4">
      <div>
        <h2 className="font-medium text-slate-100">{de.checks.title}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.checks.hint}</p>
      </div>

      {/* Gruppen-Auswahl */}
      <div className="flex flex-wrap items-center gap-2">
        {groups.map((g) => (
          <button key={g.id} type="button" onClick={() => { setSelId(g.id); setResults(null); }}
            className={`rounded-md px-3 py-1.5 text-sm ${g.id === selId
              ? 'bg-cyan-600 text-white' : 'border border-slate-700 text-slate-300 hover:border-cyan-600'}`}>
            {g.name} <span className="opacity-70">({g.checks.length})</span>
          </button>
        ))}
        {isAdmin && (
          <button type="button" onClick={newGroup} className="fwpt-btn-ghost text-sm">
            <Plus size={14} /> {de.checks.newGroup}
          </button>
        )}
      </div>

      {!group && <p className="text-sm text-slate-500">{de.checks.noGroups}</p>}

      {group && (
        <>
          <div className="flex items-center gap-2">
            {isAdmin ? (
              <input className="fwpt-input max-w-xs" value={group.name}
                onChange={(e) => updateGroup(group.id, (g) => ({ ...g, name: e.target.value }))}
                placeholder={de.checks.groupName} />
            ) : <span className="font-medium text-slate-200">{group.name}</span>}
            <button type="button" className="fwpt-btn ml-auto" onClick={run}
              disabled={busy || group.checks.length === 0}>
              <Play size={14} /> {busy ? de.checks.running : de.checks.run}
            </button>
            {isAdmin && (
              <>
                <button type="button" className="fwpt-btn-ghost" onClick={save} disabled={busy}>
                  {de.checks.save}
                </button>
                <button type="button" className="fwpt-btn-ghost text-red-400"
                  onClick={() => { mutate((gs) => gs.filter((g) => g.id !== group.id)); setSelId(null); }}>
                  <Trash2 size={14} />
                </button>
              </>
            )}
          </div>
          {status && <p className="text-sm text-slate-400">{status}</p>}

          {/* Check-Liste */}
          {group.checks.length === 0 ? (
            <p className="text-sm text-slate-500">{de.checks.empty}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-500">
                  <tr>
                    <th className="px-2 py-1.5 font-medium">{de.checks.label}</th>
                    <th className="px-2 py-1.5 font-medium">Quelle → Ziel</th>
                    <th className="px-2 py-1.5 font-medium">Proto/Port</th>
                    <th className="px-2 py-1.5 font-medium">{de.checks.expect}</th>
                    <th className="px-2 py-1.5 font-medium">{de.checks.actual}</th>
                    <th className="px-2 py-1.5" />
                  </tr>
                </thead>
                <tbody>
                  {group.checks.map((c) => {
                    const r = resultFor(c);
                    return (
                      <tr key={c.id} className="border-t border-slate-800/60 text-slate-300">
                        <td className="px-2 py-1.5">{c.label || '—'}</td>
                        <td className="whitespace-nowrap px-2 py-1.5 font-mono">{c.src} → {c.dst}</td>
                        <td className="whitespace-nowrap px-2 py-1.5 font-mono">
                          {c.protocol.toUpperCase()}{c.dst_port ? `/${c.dst_port}` : ''}
                        </td>
                        <td className="px-2 py-1.5">{c.expect}</td>
                        <td className="px-2 py-1.5">
                          {r ? (
                            <span className={`inline-flex items-center gap-1 ${r.ok ? 'text-emerald-400' : 'text-red-400'}`}
                              title={r.error ?? undefined}>
                              {r.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                              {r.actual ?? (r.error ? 'Fehler' : '—')}
                            </span>
                          ) : <span className="text-slate-600">—</span>}
                        </td>
                        <td className="px-2 py-1.5 text-right">
                          {isAdmin && (
                            <button type="button" className="text-slate-500 hover:text-red-400"
                              onClick={() => updateGroup(group.id, (g) => ({ ...g, checks: g.checks.filter((x) => x.id !== c.id) }))}>
                              <Trash2 size={13} />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Neuen Check hinzufügen */}
          {isAdmin && (
            <div className="flex flex-wrap items-end gap-2 border-t border-slate-800 pt-3">
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">{de.checks.label}</span>
                <input className="fwpt-input w-40" value={draft.label ?? ''}
                  onChange={(e) => setDraft({ ...draft, label: e.target.value })} placeholder="optional" />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">Quelle</span>
                <input className="fwpt-input w-40" value={draft.src}
                  onChange={(e) => setDraft({ ...draft, src: e.target.value })} placeholder="IP/Name" />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">Ziel</span>
                <input className="fwpt-input w-40" value={draft.dst}
                  onChange={(e) => setDraft({ ...draft, dst: e.target.value })} placeholder="IP/Name" />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">Proto</span>
                <select className="fwpt-input w-20" value={draft.protocol}
                  onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}>
                  <option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option>
                </select>
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">Port</span>
                <input className="fwpt-input w-20" type="number" value={draft.dst_port ?? ''}
                  onChange={(e) => setDraft({ ...draft, dst_port: e.target.value ? Number(e.target.value) : null })} />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">{de.checks.expect}</span>
                <select className="fwpt-input w-24" value={draft.expect}
                  onChange={(e) => setDraft({ ...draft, expect: e.target.value as 'ALLOW' | 'DENY' })}>
                  <option value="ALLOW">ALLOW</option><option value="DENY">DENY</option>
                </select>
              </label>
              <button type="button" className="fwpt-btn" onClick={addCheck}
                disabled={!draft.src.trim() || !draft.dst.trim()}>
                <Plus size={14} /> {de.checks.add}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
