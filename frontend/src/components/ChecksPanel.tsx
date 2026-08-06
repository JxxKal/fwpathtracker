import {
  Check, CheckCircle2, Link2, Network, Play, Plus, RotateCcw, Trash2, TriangleAlert, XCircle,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { getChecks, runChecks, saveChecks, updateCheckStatus } from '../api';
import type {
  CheckGroup, CheckItem, CheckResult, ChecksDoc, CheckStatusUpdate,
} from '../api';
import type { TraceResult } from '../types';
import { buildCheckLink, copyText, type CheckDeepLink } from '../checkLink';
import { de } from '../i18n/de';
import CheckResultModal from './CheckResultModal';
import EndpointAutocomplete from './EndpointAutocomplete';

const uid = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()));

const blankCheck = (): CheckItem => ({
  id: uid(), label: '', src: '', dst: '', protocol: 'tcp', dst_port: 443, expect: 'ALLOW',
});

const fmtWhen = (iso: string | null | undefined) =>
  (iso ? new Date(iso).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }) : '');

export default function ChecksPanel({ isAdmin, deepLink }: {
  isAdmin: boolean; deepLink?: CheckDeepLink | null;
}) {
  const [groups, setGroups] = useState<CheckGroup[]>([]);
  const [selId, setSelId] = useState<string | null>(null);
  const [draft, setDraft] = useState<CheckItem>(blankCheck());
  const [results, setResults] = useState<CheckResult[] | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [modal, setModal] = useState<TraceResult | null>(null);
  const [hideDone, setHideDone] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [highlight, setHighlight] = useState<string | null>(deepLink?.checkId ?? null);
  const rowRefs = useRef<Record<string, HTMLTableRowElement | null>>({});

  useEffect(() => {
    getChecks().then((d: ChecksDoc) => {
      setGroups(d.groups);
      // Deep-Link hat Vorrang vor der ersten Gruppe.
      const linked = deepLink && d.groups.find((g) => g.id === deepLink.groupId);
      if (deepLink && !linked) setStatus(de.checks.linkedNotFound);
      setSelId((s) => s ?? (linked ? linked.id : d.groups[0]?.id ?? null));
    }).catch(() => undefined);
  }, [deepLink]);

  const group = useMemo(() => groups.find((g) => g.id === selId) ?? null, [groups, selId]);

  // Verlinkte Zeile anspringen, sobald sie gerendert ist.
  useEffect(() => {
    if (!highlight) return;
    const row = rowRefs.current[highlight];
    if (!row) return;
    row.scrollIntoView({ block: 'center', behavior: 'smooth' });
    const t = setTimeout(() => setHighlight(null), 4000);
    return () => clearTimeout(t);
  }, [highlight, group]);

  function mutate(fn: (gs: CheckGroup[]) => CheckGroup[]) {
    setGroups(fn); setStatus(null); setResults(null);
  }
  function updateGroup(id: string, fn: (g: CheckGroup) => CheckGroup) {
    mutate((gs) => gs.map((g) => (g.id === id ? fn(g) : g)));
  }

  /** Status-Felder aus der Server-Antwort übernehmen, ohne ungespeicherte
   *  Definitionsänderungen (neue/geänderte Checks) zu überschreiben. */
  function mergeStatus(doc: ChecksDoc) {
    setGroups((gs) => gs.map((g) => {
      const sg = doc.groups.find((x) => x.id === g.id);
      if (!sg) return g;
      return { ...g, checks: g.checks.map((c) => {
        const sc = sg.checks.find((x) => x.id === c.id);
        return sc ? { ...c, done: sc.done, done_at: sc.done_at, done_by: sc.done_by,
                      last_run: sc.last_run } : c;
      }) };
    }));
  }

  async function pushStatus(updates: CheckStatusUpdate[], onFail?: string) {
    if (!group || updates.length === 0) return;
    try {
      mergeStatus(await updateCheckStatus(group.id, updates));
    } catch (e) {
      setStatus(onFail ?? (e instanceof Error ? e.message : String(e)));
    }
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
      // Ergebnis festschreiben: bestandene Checks gelten damit als erledigt.
      await pushStatus(
        r.results.filter((x) => x.id).map((x) => ({
          check_id: x.id as string, record_run: true,
          actual: x.actual, ok: x.ok, error: x.error,
        })),
        `${r.passed}/${r.total} ${de.checks.passed} · ${de.checks.statusSaveFailed}`,
      );
    } catch (e) { setStatus(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }

  async function toggleDone(c: CheckItem) {
    if (!c.id) return;
    await pushStatus([{ check_id: c.id, done: !c.done }], de.checks.statusSaveFailed);
  }

  async function copyLink(groupId: string, checkId: string | null, key: string) {
    const ok = await copyText(buildCheckLink(groupId, checkId));
    setStatus(ok ? de.checks.linkCopied : de.checks.copyFailed);
    if (ok) { setCopied(key); setTimeout(() => setCopied((k) => (k === key ? null : k)), 1500); }
  }

  const resultFor = (c: CheckItem) => results?.find((r) => r.id === c.id) ?? null;
  const doneCount = group ? group.checks.filter((c) => c.done).length : 0;
  const visible = group
    ? (hideDone ? group.checks.filter((c) => !c.done) : group.checks)
    : [];

  return (
    <div className="fwpt-card space-y-4">
      <div>
        <h2 className="font-medium text-slate-100">{de.checks.title}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.checks.hint}</p>
      </div>

      {/* Gruppen-Auswahl */}
      <div className="flex flex-wrap items-center gap-2">
        {groups.map((g) => {
          const done = g.checks.filter((c) => c.done).length;
          return (
            <button key={g.id} type="button" onClick={() => { setSelId(g.id); setResults(null); }}
              className={`rounded-md px-3 py-1.5 text-sm ${g.id === selId
                ? 'bg-cyan-600 text-white' : 'border border-slate-700 text-slate-300 hover:border-cyan-600'}`}>
              {g.name}{' '}
              <span className="opacity-70">
                ({done}/{g.checks.length})
              </span>
            </button>
          );
        })}
        {isAdmin && (
          <button type="button" onClick={newGroup} className="fwpt-btn-ghost text-sm">
            <Plus size={14} /> {de.checks.newGroup}
          </button>
        )}
      </div>

      {!group && <p className="text-sm text-slate-500">{de.checks.noGroups}</p>}

      {group && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            {isAdmin ? (
              <input className="fwpt-input max-w-xs" value={group.name}
                onChange={(e) => updateGroup(group.id, (g) => ({ ...g, name: e.target.value }))}
                placeholder={de.checks.groupName} />
            ) : <span className="font-medium text-slate-200">{group.name}</span>}
            <span className="text-xs text-slate-500">
              {doneCount}/{group.checks.length} {de.checks.doneCount}
            </span>
            <button type="button" className="text-slate-500 hover:text-cyan-400"
              title={de.checks.copyGroupLink}
              onClick={() => copyLink(group.id, null, 'group')}>
              {copied === 'group' ? <Check size={15} /> : <Link2 size={15} />}
            </button>
            {group.checks.some((c) => c.done) && (
              <label className="flex items-center gap-1.5 text-xs text-slate-400">
                <input type="checkbox" checked={hideDone}
                  onChange={(e) => setHideDone(e.target.checked)} />
                {de.checks.hideDone}
              </label>
            )}
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
                  title={de.checks.deleteGroup}
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
                    <th className="px-2 py-1.5 font-medium">{de.checks.status}</th>
                    <th className="px-2 py-1.5" />
                  </tr>
                </thead>
                <tbody>
                  {visible.map((c) => {
                    const r = resultFor(c);
                    const last = c.last_run ?? null;
                    // Frischer Lauf schlägt den gespeicherten letzten Lauf.
                    const shown = r
                      ? { actual: r.actual, ok: r.ok, error: r.error, at: null as string | null }
                      : last
                        ? { actual: last.actual, ok: last.ok, error: last.error, at: last.at }
                        : null;
                    const regression = !!c.done && !!shown && !shown.ok;
                    return (
                      <tr key={c.id}
                        ref={(el) => { if (c.id) rowRefs.current[c.id] = el; }}
                        className={`border-t border-slate-800/60 text-slate-300 ${
                          highlight && c.id === highlight ? 'bg-cyan-950/40 outline outline-1 outline-cyan-700' : ''
                        } ${c.done ? 'opacity-70' : ''}`}>
                        <td className="px-2 py-1.5">{c.label || '—'}</td>
                        <td className="whitespace-nowrap px-2 py-1.5 font-mono">{c.src} → {c.dst}</td>
                        <td className="whitespace-nowrap px-2 py-1.5 font-mono">
                          {c.protocol.toUpperCase()}{c.dst_port ? `/${c.dst_port}` : ''}
                        </td>
                        <td className="px-2 py-1.5">{c.expect}</td>
                        <td className="px-2 py-1.5">
                          {shown ? (
                            <span className="inline-flex items-center gap-2">
                              <span className={`inline-flex items-center gap-1 ${shown.ok ? 'text-emerald-400' : 'text-red-400'}`}
                                title={shown.error ?? (shown.at ? `${de.checks.lastRun}: ${fmtWhen(shown.at)}` : undefined)}>
                                {shown.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                                {shown.actual ?? (shown.error ? 'Fehler' : '—')}
                              </span>
                              {shown.at && !r && (
                                <span className="text-[10px] text-slate-600">{fmtWhen(shown.at)}</span>
                              )}
                              {r?.result && (
                                <button type="button" className="text-slate-500 hover:text-cyan-400"
                                  title={de.checks.details} onClick={() => setModal(r.result)}>
                                  <Network size={13} />
                                </button>
                              )}
                            </span>
                          ) : <span className="text-slate-600" title={de.checks.neverRun}>—</span>}
                        </td>
                        <td className="whitespace-nowrap px-2 py-1.5">
                          <span className="inline-flex items-center gap-1.5">
                            {c.done ? (
                              <span className="inline-flex items-center gap-1 rounded border border-emerald-800 bg-emerald-950/60 px-1.5 py-0.5 text-emerald-300"
                                title={`${de.checks.doneSince} ${fmtWhen(c.done_at)}${c.done_by ? ` ${de.checks.doneBy} ${c.done_by}` : ''}`}>
                                <Check size={11} /> {de.checks.done}
                              </span>
                            ) : (
                              <button type="button" className="inline-flex items-center gap-1 rounded border border-slate-700 px-1.5 py-0.5 text-slate-400 hover:border-emerald-700 hover:text-emerald-300"
                                title={de.checks.markDone} onClick={() => toggleDone(c)}>
                                <Check size={11} /> {de.checks.markDone}
                              </button>
                            )}
                            {regression && (
                              <span className="text-amber-400" title={de.checks.regression}>
                                <TriangleAlert size={13} />
                              </span>
                            )}
                            {c.done && (
                              <button type="button" className="text-slate-500 hover:text-slate-300"
                                title={de.checks.reopen} onClick={() => toggleDone(c)}>
                                <RotateCcw size={12} />
                              </button>
                            )}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-2 py-1.5 text-right">
                          <button type="button" className="text-slate-500 hover:text-cyan-400"
                            title={de.checks.copyLink}
                            onClick={() => c.id && copyLink(group.id, c.id, c.id)}>
                            {copied === c.id ? <Check size={13} /> : <Link2 size={13} />}
                          </button>
                          {isAdmin && (
                            <button type="button" className="ml-2 text-slate-500 hover:text-red-400"
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
                <div className="w-44">
                  <EndpointAutocomplete value={draft.src}
                    onChange={(v) => setDraft({ ...draft, src: v })} placeholder="IP/Name/Objekt" />
                </div>
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-slate-500">Ziel</span>
                <div className="w-44">
                  <EndpointAutocomplete value={draft.dst}
                    onChange={(v) => setDraft({ ...draft, dst: v })} placeholder="IP/Name/Objekt" />
                </div>
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

      {modal && <CheckResultModal result={modal} onClose={() => setModal(null)} />}
    </div>
  );
}
