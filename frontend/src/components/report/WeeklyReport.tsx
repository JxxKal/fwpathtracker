import { AlertTriangle, ChevronDown, ChevronRight, FileText, Loader2, Play, Printer, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  ApiError, reportDelete, reportGet, reportList, reportRun,
  type ReportChapter, type ReportChart, type ReportData, type ReportKpi, type ReportList,
  type ReportListItem, type ReportStatus, type ReportTable,
} from '../../api';
import { de } from '../../i18n/de';

// „Stephan fragt, A38 antwortet": links die Berichte, rechts einer davon.
// Die Ansicht ist zugleich die Druckvorlage — Drucken/PDF nimmt dieselbe Seite.

const STATUS: Record<ReportStatus, { label: string; cls: string }> = {
  ok: { label: 'vollständig', cls: 'bg-emerald-500/15 text-emerald-300 border-emerald-700' },
  partial: { label: 'teilweise', cls: 'bg-amber-500/15 text-amber-300 border-amber-700' },
  error: { label: 'Fehler', cls: 'bg-red-500/15 text-red-300 border-red-800' },
  failed: { label: 'fehlgeschlagen', cls: 'bg-red-500/15 text-red-300 border-red-800' },
  off: { label: 'nicht eingerichtet', cls: 'bg-slate-700/30 text-slate-400 border-slate-700' },
};

const fmt = (n: number) => n.toLocaleString('de-DE');
const dt = (iso: string) => new Date(iso).toLocaleString('de-DE', {
  weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

function Badge({ status }: { status: ReportStatus }) {
  const s = STATUS[status] ?? STATUS.error;
  return <span className={`rounded border px-1.5 py-0.5 text-[10px] ${s.cls}`}>{s.label}</span>;
}

export default function WeeklyReport() {
  const [list, setList] = useState<ReportList | null>(null);
  const [current, setCurrent] = useState<(ReportListItem & { data: ReportData }) | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');

  async function load(select?: number) {
    try {
      const l = await reportList();
      setList(l);
      const id = select ?? l.reports[0]?.id;
      if (id !== undefined) setCurrent(await reportGet(id));
      if (!from) {
        setFrom(l.default.start.slice(0, 16));
        setTo(new Date().toISOString().slice(0, 16));
      }
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 403 ? de.report.adminOnly
        : e instanceof Error ? e.message : String(e));
    }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { void load(); }, []);

  async function run() {
    setBusy(true); setErr(null);
    try {
      const r = await reportRun(from ? new Date(from + 'Z').toISOString() : undefined,
        to ? new Date(to + 'Z').toISOString() : undefined);
      await load(r.id);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  async function remove(id: number) {
    await reportDelete(id);
    setCurrent(null);
    await load();
  }

  return (
    <div className="space-y-4">
      <div className="fwpt-card space-y-3 print:hidden">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 font-medium text-slate-100">
              <FileText size={16} className="text-cyan-400" /> {de.report.title}
            </h2>
            <p className="mt-0.5 text-xs text-slate-500">{de.report.hint}</p>
            {list && (
              <p className="mt-1 text-xs text-slate-400">
                {list.schedule.enabled ? de.report.next(dt(list.schedule.next)) : de.report.scheduleOff}
              </p>
            )}
          </div>
          {current && (
            <button type="button" className="fwpt-btn-ghost" onClick={() => window.print()}>
              <Printer size={14} /> {de.report.print}
            </button>
          )}
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.report.from} (UTC)</span>
            <input type="datetime-local" className="fwpt-input w-52" value={from}
              onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.report.to} (UTC)</span>
            <input type="datetime-local" className="fwpt-input w-52" value={to}
              onChange={(e) => setTo(e.target.value)} />
          </label>
          <button type="button" className="fwpt-btn" onClick={run} disabled={busy}>
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            {busy ? de.report.running : de.report.run}
          </button>
          {list && list.reports.length > 0 && (
            <select className="fwpt-input ml-auto w-72" value={current?.id ?? ''}
              onChange={(e) => reportGet(Number(e.target.value)).then(setCurrent)}>
              {list.reports.map((r) => (
                <option key={r.id} value={r.id}>
                  {new Date(r.period_end).toLocaleDateString('de-DE')} · {r.trigger === 'schedule'
                    ? de.report.scheduled : de.report.manual} · {STATUS[r.status]?.label}
                </option>
              ))}
            </select>
          )}
        </div>
        {err && <p className="text-sm text-red-400">{err}</p>}
        {list && list.reports.length === 0 && !err && (
          <p className="text-sm text-slate-400">{de.report.empty}</p>
        )}
      </div>
      {current && <ReportView data={current.data} item={current} onDelete={() => remove(current.id)} />}
    </div>
  );
}

function ReportView({ data, item, onDelete }: { data: ReportData; item: ReportListItem; onDelete: () => void }) {
  const chapters = data.chapters.filter((c) => c.status !== 'off');
  const off = data.chapters.filter((c) => c.status === 'off');
  return (
    <article className="report space-y-4">
      {/* Titel */}
      <section className="fwpt-card report-page">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <p className="text-xs uppercase tracking-widest text-cyan-400">{data.period.kw}</p>
            <h1 className="text-2xl font-semibold text-slate-100">{data.title}</h1>
            <p className="text-sm text-slate-400">{data.period.from} – {data.period.to}</p>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            <Badge status={data.summary.status} />
            <span>{item.trigger === 'schedule' ? de.report.scheduled : `${de.report.manual}${item.created_by ? ` (${item.created_by})` : ''}`}</span>
            <span>· {de.report.created} {dt(item.created_at)}</span>
            <button type="button" className="fwpt-btn-ghost px-1.5 print:hidden" title={de.report.delete}
              onClick={onDelete}><Trash2 size={13} /></button>
          </div>
        </div>
        <Tiles kpis={data.summary.kpis} />
        <Heatmap data={data} />
        <div className="mt-3 flex flex-wrap gap-1.5 text-[11px]">
          {data.sources.map((s) => (
            <span key={s.id} title={s.note ?? ''} className={`rounded border px-1.5 py-0.5 ${STATUS[s.status]?.cls}`}>
              {s.source}: {STATUS[s.status]?.label}
            </span>
          ))}
        </div>
      </section>

      {/* Kapitel 1 */}
      <section className="fwpt-card report-page">
        <h2 className="flex items-center gap-2 text-lg font-medium text-slate-100">
          <AlertTriangle size={17} className="text-amber-400" /> {de.report.attentionQ}
        </h2>
        {data.attention.length === 0
          ? <p className="mt-2 text-sm text-slate-400">{de.report.attentionNone}</p>
          : (
            <ul className="mt-3 space-y-2">
              {data.attention.map((a, i) => (
                <li key={i} className={`rounded-md border-l-4 bg-slate-950/40 px-3 py-2 ${a.level === 'high'
                  ? 'border-red-500' : 'border-amber-500'}`}>
                  <p className="text-sm text-slate-100">{a.title}</p>
                  <p className="text-xs text-slate-400">{a.why}</p>
                  <p className="text-[10px] uppercase tracking-wide text-slate-500">{a.source}</p>
                </li>
              ))}
            </ul>
          )}
      </section>

      {chapters.map((c) => <Chapter key={c.id} c={c} days={data.days} />)}

      {off.length > 0 && (
        <p className="px-1 text-xs text-slate-500">
          {de.report.notIncluded}: {off.map((c) => `${c.source} (${c.note})`).join(' · ')}
        </p>
      )}
    </article>
  );
}

function Tiles({ kpis }: { kpis: ReportKpi[] }) {
  return (
    <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      {kpis.map((k) => {
        const d = k.prev === null || k.prev === undefined ? null : k.value - k.prev;
        return (
          <div key={k.key} className="rounded-md border border-slate-800 bg-slate-950/40 px-3 py-2">
            <p className="text-2xl font-semibold tabular-nums text-slate-100">{fmt(k.value)}</p>
            <p className="text-[11px] leading-tight text-slate-400">{k.label}</p>
            {d !== null && (
              <p className={`text-[11px] tabular-nums ${d > 0 ? 'text-amber-400' : d < 0 ? 'text-emerald-400' : 'text-slate-500'}`}>
                {d > 0 ? '▲' : d < 0 ? '▼' : '='} {d !== 0 ? fmt(Math.abs(d)) : ''} {de.report.vsPrev}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}

function Heatmap({ data }: { data: ReportData }) {
  if (!data.heatmap.length) return null;
  return (
    <div className="mt-4 overflow-x-auto">
      <p className="mb-1 text-xs text-slate-500">{de.report.heatmap}</p>
      <table className="text-[11px]">
        <thead>
          <tr>
            <th />
            {data.days.map((d) => <th key={d.date} className="px-1 font-normal text-slate-500">{d.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {data.heatmap.map((row) => {
            const max = Math.max(1, ...row.values);
            return (
              <tr key={row.id}>
                <td className="pr-2 text-right text-slate-400">{row.label}</td>
                {row.values.map((v, i) => (
                  <td key={i} className="p-0.5">
                    <div className="flex h-6 w-14 items-center justify-center rounded tabular-nums"
                      style={{ background: v ? `rgba(34, 211, 238, ${0.12 + 0.6 * (v / max)})` : 'rgba(51,65,85,0.25)',
                        color: v / max > 0.6 ? '#0f172a' : '#cbd5e1' }}>
                      {v ? fmt(v) : ''}
                    </div>
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Chapter({ c, days }: { c: ReportChapter; days: { label: string }[] }) {
  return (
    <section className="fwpt-card report-page space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-lg font-medium text-slate-100">{c.question}</h2>
          <p className="text-[11px] uppercase tracking-wide text-slate-500">{c.source}</p>
        </div>
        <Badge status={c.status} />
      </div>
      <p className="text-base text-slate-200">{c.answer}</p>
      {c.note && <p className="text-xs text-amber-400">{c.note}</p>}
      {c.hints?.map((h, i) => <p key={i} className="text-xs text-slate-500">{h}</p>)}
      {c.charts.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2">
          {c.charts.map((ch, i) => <Chart key={i} chart={ch} days={days} />)}
        </div>
      )}
      {c.tables.map((t, i) => <Table key={i} t={t} />)}
    </section>
  );
}

function Chart({ chart, days }: { chart: ReportChart; days: { label: string }[] }) {
  if (chart.type === 'top') {
    const items = chart.items ?? [];
    const max = Math.max(1, ...items.map((i) => i.value));
    return (
      <figure>
        <figcaption className="mb-1 text-xs text-slate-400">{chart.title}</figcaption>
        <div className="space-y-1">
          {items.map((i) => (
            <div key={i.label} className="flex items-center gap-2 text-[11px]">
              <span className="w-40 truncate text-right text-slate-300" title={i.label}>{i.label}</span>
              <div className="h-3.5 flex-1 rounded bg-slate-800/60">
                <div className="h-3.5 rounded bg-cyan-500/70" style={{ width: `${(i.value / max) * 100}%` }} />
              </div>
              <span className="w-12 tabular-nums text-slate-400">{fmt(i.value)}</span>
            </div>
          ))}
        </div>
      </figure>
    );
  }
  // Balken je Tag, gestapelt oder nebeneinander — als SVG, damit Druck und Bildschirm gleich aussehen.
  const series = chart.series ?? [];
  const n = days.length;
  const sums = days.map((_, i) => series.reduce((a, s) => a + (s.values[i] ?? 0), 0));
  const max = Math.max(1, ...(chart.stacked || series.length === 1 ? sums
    : series.flatMap((s) => s.values)));
  const W = 420, H = 140, pad = 22, bw = (W - pad) / n;
  return (
    <figure>
      <figcaption className="mb-1 text-xs text-slate-400">{chart.title}</figcaption>
      <svg viewBox={`0 0 ${W} ${H + 18}`} className="w-full">
        {[0.5, 1].map((f) => (
          <g key={f}>
            <line x1={pad} x2={W} y1={H - f * (H - 10)} y2={H - f * (H - 10)} stroke="#334155" strokeDasharray="2 3" />
            <text x={pad - 3} y={H - f * (H - 10) + 3} fontSize="8" fill="#64748b" textAnchor="end">{fmt(Math.round(max * f))}</text>
          </g>
        ))}
        {days.map((d, i) => {
          let y = H;
          const x = pad + i * bw;
          return (
            <g key={i}>
              {series.map((s, k) => {
                const v = s.values[i] ?? 0;
                const h = (v / max) * (H - 10);
                if (chart.stacked || series.length === 1) {
                  y -= h;
                  return <rect key={k} x={x + 3} y={y} width={bw - 6} height={h} fill={s.color} rx="1.5"><title>{`${s.label}: ${v}`}</title></rect>;
                }
                const w = (bw - 6) / series.length;
                return <rect key={k} x={x + 3 + k * w} y={H - h} width={w - 1} height={h} fill={s.color} rx="1.5"><title>{`${s.label}: ${v}`}</title></rect>;
              })}
              <text x={x + bw / 2} y={H + 12} fontSize="8" fill="#94a3b8" textAnchor="middle">{d.label}</text>
            </g>
          );
        })}
      </svg>
      {series.length > 1 && (
        <div className="flex flex-wrap gap-3 text-[10px] text-slate-400">
          {series.map((s) => (
            <span key={s.label} className="flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-sm" style={{ background: s.color }} />{s.label}
            </span>
          ))}
        </div>
      )}
    </figure>
  );
}

const ROWS = 15;

function Table({ t }: { t: ReportTable }) {
  const [open, setOpen] = useState(false);
  const rows = open ? t.rows : t.rows.slice(0, ROWS);
  const more = t.total !== null && t.total > t.rows.length ? t.total - t.rows.length : 0;
  return (
    <div>
      <button type="button" className="mb-1 flex items-center gap-1 text-xs text-slate-300 print:hidden"
        onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {t.title} <span className="text-slate-500">({fmt(t.total ?? t.rows.length)})</span>
      </button>
      <p className="mb-1 hidden text-xs text-slate-700 print:block">{t.title}</p>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-[11px]">
          <thead className="bg-slate-900/60 text-left text-slate-400">
            <tr>{t.columns.map((c) => <th key={c} className="px-2 py-1 font-normal">{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-t border-slate-800/70 text-slate-300">
                {r.map((v, k) => <td key={k} className="max-w-md px-2 py-1 align-top">{typeof v === 'number' ? fmt(v) : v}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {(t.rows.length > ROWS && !open) && (
        <button type="button" className="mt-1 text-[11px] text-cyan-400 print:hidden" onClick={() => setOpen(true)}>
          {de.report.showAll(t.rows.length)}
        </button>
      )}
      {more > 0 && <p className="mt-1 text-[11px] text-slate-500">{de.report.moreInSource(more)}</p>}
    </div>
  );
}
