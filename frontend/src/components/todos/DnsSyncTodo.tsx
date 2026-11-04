import { Ban, CheckCircle2, ClipboardCheck, RefreshCw, Trash2, XCircle } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  dnsSyncApply, dnsSyncCreate, dnsSyncDiscard, dnsSyncIgnore, dnsSyncIgnored, dnsSyncOverview,
  dnsSyncRun, dnsSyncToggle, dnsSyncUnignore, type DnsSyncItem, type DnsSyncRun, type DnsSyncSection,
} from '../../api';
import { de } from '../../i18n/de';

const t = de.dnssync;
const SECTIONS: DnsSyncSection[] = ['missing', 'mismatch', 'orphan'];
const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }) : '—');
const err = (e: unknown) => (e instanceof Error ? e.message : String(e));

function StatusBadge({ s }: { s: DnsSyncItem['status'] }) {
  const cls = s === 'confirmed' ? 'border-emerald-800 text-emerald-300'
    : s === 'unconfirmed' ? 'border-amber-800 text-amber-300' : 'border-slate-700 text-slate-400';
  return <span className={`rounded border px-1.5 py-0.5 text-[10px] ${cls}`}>{t.status[s]}</span>;
}

function ResultBadge({ r }: { r: NonNullable<DnsSyncItem['result']> }) {
  const Icon = r.state === 'ok' ? CheckCircle2 : r.state === 'skipped' ? Ban : XCircle;
  const cls = r.state === 'ok' ? 'text-emerald-400' : r.state === 'skipped' ? 'text-amber-400' : 'text-red-400';
  return <span className={`flex items-start gap-1 text-[11px] ${cls}`}><Icon size={12} className="mt-0.5 shrink-0" />{r.text}</span>;
}

export default function DnsSyncTodo() {
  const [runs, setRuns] = useState<DnsSyncRun[] | null>(null);
  const [writeEnabled, setWriteEnabled] = useState(false);
  const [run, setRun] = useState<DnsSyncRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [ignored, setIgnored] = useState<Awaited<ReturnType<typeof dnsSyncIgnored>> | null>(null);

  async function loadAll(pick?: number) {
    setError(null);
    try {
      const o = await dnsSyncOverview();
      setRuns(o.runs); setWriteEnabled(o.write_enabled);
      const id = pick ?? o.runs.find((r) => r.status === 'open')?.id ?? o.runs[0]?.id;
      setRun(id ? await dnsSyncRun(id) : null);
    } catch (e) { setError(err(e)); }
  }
  useEffect(() => { loadAll(); }, []);

  const open = run?.status === 'open';
  const items = run?.items ?? [];
  const selected = items.filter((i) => i.selected && i.selectable);
  const bySection = useMemo(() => SECTIONS.map((s) => [s, items.filter((i) => i.section === s)] as const), [items]);

  async function toggle(ids: string[], value: boolean) {
    if (!run || !open) return;
    setRun({ ...run, items: items.map((i) => (ids.includes(i.id) && i.selectable ? { ...i, selected: value } : i)) });
    try { await dnsSyncToggle(run.id, ids, value); } catch (e) { setError(err(e)); loadAll(run.id); }
  }

  async function act(fn: () => Promise<unknown>, after?: (r: unknown) => void, pick?: number) {
    setBusy(true); setError(null); setMessage(null);
    try { const r = await fn(); after?.(r); await loadAll(pick); } catch (e) { setError(err(e)); } finally { setBusy(false); }
  }

  async function ignore(it: DnsSyncItem) {
    const reason = window.prompt(t.ignorePrompt(it.ip, it.dns_name), '');
    if (reason === null) return;
    await act(() => dnsSyncIgnore(it.id, it.ip, reason || null), undefined, run?.id);
  }

  return (
    <div className="space-y-4">
      <div className="fwpt-card space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 className="flex items-center gap-2 font-medium text-slate-100"><ClipboardCheck size={16} className="text-cyan-400" />{t.title}</h2>
            <p className="mt-0.5 max-w-3xl text-xs text-slate-500">{t.hint}</p>
          </div>
          <button type="button" className="fwpt-btn-ghost" disabled={busy}
            onClick={() => act(dnsSyncCreate, (r) => setMessage(t.created((r as { id: number }).id)), undefined)}>
            <RefreshCw size={14} /> {t.runNow}
          </button>
        </div>
        {!writeEnabled && <p className="text-xs text-amber-400">{t.writeOff}</p>}
        {error && <p className="text-sm text-red-400">{error}</p>}
        {message && <p className="text-sm text-emerald-400">{message}</p>}
        {runs && runs.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {runs.slice(0, 12).map((r) => (
              <button key={r.id} type="button" onClick={() => act(async () => undefined, undefined, r.id)}
                className={`rounded-md border px-2 py-1 text-[11px] ${run?.id === r.id
                  ? 'border-cyan-600 bg-cyan-950/60 text-cyan-200' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}>
                #{r.id} · {fmt(r.created_at)} · {t.runStatus[r.status]}
              </button>
            ))}
          </div>
        )}
        {runs && runs.length === 0 && <p className="text-sm text-slate-400">{t.empty}</p>}
      </div>

      {run && (
        <div className="fwpt-card space-y-4">
          <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
            <h3 className="font-medium text-slate-100">{t.runTitle(run.id, fmt(run.created_at))}</h3>
            <span className="text-xs text-slate-400">{t.stats(run.stats)}</span>
            {run.decided_by && <span className="text-xs text-slate-400">{t.decided(t.runStatus[run.status], run.decided_by, fmt(run.decided_at))}</span>}
            {run.result && <span className="text-xs text-slate-400">{t.result(run.result)}</span>}
          </div>
          {(run.stats.errors ?? []).map((e) => <p key={e} className="text-xs text-amber-400">iTop {e}</p>)}

          {bySection.map(([sec, rows]) => rows.length > 0 && (
            <section key={sec} className="space-y-1.5">
              <div className="flex flex-wrap items-baseline gap-3">
                <h4 className="text-sm font-medium text-slate-200">{t.section[sec]} ({rows.length})</h4>
                <span className="text-[11px] text-slate-500">{t.sectionHint[sec]}</span>
                {open && (
                  <>
                    <button type="button" className="text-[11px] text-cyan-400 hover:underline"
                      onClick={() => toggle(rows.filter((r) => r.status === 'confirmed').map((r) => r.id), true)}>{t.pickConfirmed}</button>
                    <button type="button" className="text-[11px] text-cyan-400 hover:underline"
                      onClick={() => toggle(rows.map((r) => r.id), false)}>{t.pickNone}</button>
                  </>
                )}
              </div>
              <div className="overflow-x-auto rounded-md border border-slate-800">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-900 text-slate-400">
                    <tr>
                      <th className="w-8 px-2 py-1.5" />
                      <th className="px-2 py-1.5 font-medium">{t.col.ip}</th>
                      <th className="px-2 py-1.5 font-medium">{t.col.ci}</th>
                      <th className="px-2 py-1.5 font-medium">{t.col.itop}</th>
                      <th className="px-2 py-1.5 font-medium">{t.col.dns}</th>
                      <th className="px-2 py-1.5 font-medium">{t.col.check}</th>
                      <th className="px-2 py-1.5" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((it) => (
                      <tr key={it.id} className={`border-t border-slate-800/70 align-top ${it.selected ? '' : 'text-slate-400'}`}>
                        <td className="px-2 py-1.5">
                          <input type="checkbox" checked={it.selected} disabled={!open || !it.selectable}
                            title={it.selectable ? undefined : t.notSelectable}
                            onChange={(e) => toggle([it.id], e.target.checked)} />
                        </td>
                        <td className="px-2 py-1.5 font-mono text-slate-300">{it.ip}</td>
                        <td className="px-2 py-1.5">
                          {it.cis.length ? it.cis.map((c) => <div key={c.id}>{c.name} <span className="text-slate-500">({c.class})</span></div>)
                            : <span className="text-slate-500">—</span>}
                        </td>
                        <td className="px-2 py-1.5">{it.itop_name ?? <span className="text-slate-500">{t.noName}</span>}</td>
                        <td className="px-2 py-1.5 font-medium text-slate-200">
                          {it.dns_name}
                          {it.short_name && <div className="text-[10px] font-normal text-slate-500">{t.writes(it.short_name, it.domain ?? '')}</div>}
                        </td>
                        <td className="max-w-[360px] px-2 py-1.5">
                          <div className="flex flex-col gap-1">
                            <span><StatusBadge s={it.status} /></span>
                            <span className="text-[11px] text-slate-400">{it.reason}</span>
                            {it.result && <ResultBadge r={it.result} />}
                          </div>
                        </td>
                        <td className="px-2 py-1.5 text-right">
                          {open && (
                            <button type="button" className="text-slate-500 hover:text-slate-200" title={t.ignore}
                              onClick={() => ignore(it)}><Ban size={14} /></button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
          {items.length === 0 && <p className="text-sm text-slate-400">{t.nothing}</p>}

          {open && items.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-3">
              {!confirm ? (
                <button type="button" className="fwpt-btn" disabled={busy || !writeEnabled || selected.length === 0}
                  onClick={() => setConfirm(true)}>
                  <CheckCircle2 size={14} /> {t.apply(selected.length)}
                </button>
              ) : (
                <>
                  <span className="text-sm text-amber-300">{t.confirm(selected.length)}</span>
                  <button type="button" className="fwpt-btn" disabled={busy}
                    onClick={() => { setConfirm(false); act(() => dnsSyncApply(run.id),
                      (r) => setMessage(t.applied(r as { ok: number; skipped: number; error: number })), run.id); }}>
                    {t.confirmYes}
                  </button>
                  <button type="button" className="fwpt-btn-ghost" onClick={() => setConfirm(false)}>{de.common.cancel}</button>
                </>
              )}
              <button type="button" className="fwpt-btn-ghost ml-auto" disabled={busy}
                onClick={() => act(() => dnsSyncDiscard(run.id), undefined, run.id)}>
                <Trash2 size={14} /> {t.discard}
              </button>
            </div>
          )}

          {(run.stats.no_ptr_sample ?? []).length > 0 && (
            <details className="text-xs text-slate-400">
              <summary className="cursor-pointer">{t.noPtr(run.stats.no_ptr)}</summary>
              <p className="mt-1 font-mono">{run.stats.no_ptr_sample!.map((r) => r.ci ? `${r.ip} (${r.ci})` : r.ip).join(', ')}</p>
            </details>
          )}
        </div>
      )}

      <div className="fwpt-card space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-slate-200">{t.ignoredTitle}</h3>
          <button type="button" className="text-xs text-cyan-400 hover:underline"
            onClick={() => dnsSyncIgnored().then(setIgnored).catch((e) => setError(err(e)))}>{t.ignoredShow}</button>
        </div>
        {ignored && (ignored.length === 0 ? <p className="text-xs text-slate-500">{t.ignoredNone}</p> : (
          <ul className="space-y-1 text-xs">
            {ignored.map((g) => (
              <li key={g.ip_id} className="flex items-center gap-3 text-slate-300">
                <span className="font-mono">{g.ip}</span>
                <span className="text-slate-500">{g.reason || '—'} · {g.created_by} · {fmt(g.created_at)}</span>
                <button type="button" className="text-cyan-400 hover:underline"
                  onClick={() => dnsSyncUnignore(g.ip_id).then(() => dnsSyncIgnored().then(setIgnored))}>{t.unignore}</button>
              </li>
            ))}
          </ul>
        ))}
      </div>
    </div>
  );
}
