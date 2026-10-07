import { AlertTriangle, CheckCircle2, Circle, ExternalLink, Info, XCircle } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { webdriveStatus } from '../../api';
import { de } from '../../i18n/de';
import type { WebdriveFacUser, WebdriveStatus, WebdriveUser } from '../../types';

// Webdrive auf einen Blick: wer hat ein Problem und warum, wer ist aktiv,
// wann lief der Sync. Bewusst keine Logzeilen — dafür der Link ins Graylog.

type Range = 'today' | '24h' | '7d';
const REFRESH_MS = 60_000;

function sinceFor(range: Range): string {
  const now = new Date();
  if (range === 'today') {
    now.setHours(0, 0, 0, 0);
    return now.toISOString();
  }
  const hours = range === '24h' ? 24 : 24 * 7;
  return new Date(now.getTime() - hours * 3_600_000).toISOString();
}

function fmt(iso: string | null | undefined, withDate: boolean): string {
  if (!iso) return '–';
  const d = new Date(iso);
  return withDate
    ? d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
}

function GraylogLink({ st, username }: { st: WebdriveStatus; username: string }) {
  if (!st.graylog_url || !st.since || !st.now) return null;
  const href = `${st.graylog_url}/search?q=${encodeURIComponent(`"${username}"`)}`
    + `&rangetype=absolute&from=${encodeURIComponent(st.since)}&to=${encodeURIComponent(st.now)}`;
  return (
    <a href={href} target="_blank" rel="noreferrer"
      className="inline-flex shrink-0 items-center gap-1 text-xs text-slate-500 hover:text-cyan-400">
      {de.webdrive.inGraylog} <ExternalLink size={12} />
    </a>
  );
}

function Section({ title, count, tone, children }: {
  title: string; count: number; tone: 'red' | 'amber' | 'plain'; children: React.ReactNode;
}) {
  const color = tone === 'red' ? 'text-red-400' : tone === 'amber' ? 'text-amber-400' : 'text-slate-400';
  return (
    <div className="fwpt-card space-y-2">
      <div className={`text-[11px] font-medium uppercase tracking-wide ${color}`}>
        {title} ({count})
      </div>
      {count === 0 ? <p className="text-sm text-slate-500">{de.webdrive.none}</p> : children}
    </div>
  );
}

export default function WebdriveDashboard() {
  const [range, setRange] = useState<Range>('today');
  const [st, setSt] = useState<WebdriveStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSt(await webdriveStatus(sinceFor(range)));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [range]);

  useEffect(() => {
    void load();
    const id = window.setInterval(() => { void load(); }, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [load]);

  if (!st) {
    return <div className={`fwpt-card text-sm ${error ? 'text-red-400' : 'text-slate-400'}`}>
      {error ?? de.common.loading}
    </div>;
  }
  if (!st.configured) {
    return <div className="fwpt-card text-sm text-slate-400">{de.webdrive.notConfigured}</div>;
  }

  const withDate = range !== 'today';
  const t = (iso: string | null | undefined) => fmt(iso, withDate);
  const problems = st.problems ?? [];
  const hints = st.hints ?? [];
  const active = st.active ?? [];
  const inactive = st.inactive ?? [];
  const unattributed = st.unattributed ?? [];
  const sync = st.sync;

  const userRow = (u: WebdriveUser, isActive: boolean) => (
    <li key={u.username} className="flex items-baseline justify-between gap-3 text-sm">
      <span className="flex items-center gap-2">
        <Circle size={8} className={isActive ? 'fill-emerald-400 text-emerald-400' : 'text-slate-600'} />
        <span className="text-slate-200">{u.username}</span>
      </span>
      <span className="text-xs text-slate-500">
        {isActive ? de.webdrive.since(t(u.first)) : `${t(u.first)} – ${t(u.last)}`}
        {u.uploads > 0 && ` · ${de.webdrive.uploads(u.uploads)}`}
      </span>
    </li>
  );

  return (
    <div className="mx-auto max-w-5xl space-y-3">
      {/* Kopf: Stand der Daten, Zeitraum, Sync */}
      <div className="fwpt-card space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-sm text-slate-400">
            {st.poll?.last_ok ? de.webdrive.asOf(fmt(st.poll.last_ok, false)) : de.webdrive.neverPolled}
            {st.poll?.stale && st.poll.last_ok && (
              <span className="ml-2 inline-flex items-center gap-1 text-amber-400">
                <AlertTriangle size={14} /> {de.webdrive.stale}
              </span>
            )}
            {error && <span className="ml-2 text-red-400">{error}</span>}
          </div>
          <div className="w-32">
            <select className="fwpt-input py-1 text-sm" value={range}
              onChange={(e) => setRange(e.target.value as Range)}>
              <option value="today">{de.webdrive.rangeToday}</option>
              <option value="24h">{de.webdrive.range24h}</option>
              <option value="7d">{de.webdrive.range7d}</option>
            </select>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-2 text-sm text-slate-300">
          <span className="text-slate-400">{de.webdrive.sync(st.sync_rule ?? 'Webdrive-User')}:</span>
          {sync ? (
            <>
              <span>{fmt(sync.last_run, false)}</span>
              {sync.ok
                ? <CheckCircle2 size={14} className="text-emerald-400" />
                : <span className="inline-flex items-center gap-1 text-red-400">
                    <XCircle size={14} /> {sync.error ?? de.webdrive.syncFailed}
                  </span>}
              {sync.users !== null && <span className="text-slate-500">· {de.webdrive.syncUsers(sync.users)}</span>}
              {sync.last_change && (
                <span className="text-slate-500">
                  · {de.webdrive.lastChange} {fmt(sync.last_change.ts, withDate)}
                  {sync.last_change.manual && ` (${de.webdrive.manual})`}: {sync.last_change.username} – {sync.last_change.text}
                </span>
              )}
            </>
          ) : <span className="text-slate-500">{de.webdrive.noSync}</span>}
        </div>
        {st.poll?.last_error && <p className="text-xs text-red-400">{st.poll.last_error}</p>}
      </div>

      <Section title={de.webdrive.problems} count={problems.length} tone="red">
        <ul className="space-y-2">
          {problems.map((p) => (
            <li key={`${p.username}-${p.category}-${p.last}`} className="flex items-start justify-between gap-3">
              <div className="flex items-start gap-2">
                <AlertTriangle size={16} className="mt-0.5 shrink-0 text-red-400" />
                <div>
                  <div className="text-sm"><span className="font-medium text-slate-100">{p.username}</span>
                    <span className="text-slate-300"> · {p.reason}</span></div>
                  {p.category === 'login' && (
                    <div className="text-xs text-slate-500">
                      {de.webdrive.attempts(p.count)} · {t(p.first)}{p.count > 1 && `–${t(p.last)}`} · {de.webdrive.noSuccess}
                    </div>
                  )}
                  {p.category === 'file' && <div className="text-xs text-slate-500">{t(p.last)}</div>}
                </div>
              </div>
              <GraylogLink st={st} username={p.username} />
            </li>
          ))}
        </ul>
      </Section>

      <Section title={de.webdrive.hints} count={hints.length} tone="amber">
        <ul className="space-y-1.5">
          {hints.map((h) => (
            <li key={`${h.username}-${h.kind}-${h.ts}`} className="flex items-start justify-between gap-3 text-sm">
              <div className="flex items-start gap-2">
                <Info size={15} className="mt-0.5 shrink-0 text-amber-400" />
                <span><span className="text-slate-100">{h.username}</span>
                  <span className="text-slate-400"> · {h.text} {t(h.ts)}</span></span>
              </div>
              <GraylogLink st={st} username={h.username} />
            </li>
          ))}
        </ul>
      </Section>

      <div className="grid gap-3 md:grid-cols-2">
        <Section title={de.webdrive.active} count={active.length} tone="plain">
          <ul className="space-y-1">{active.map((u) => userRow(u, true))}</ul>
        </Section>
        <Section title={de.webdrive.inactive} count={inactive.length} tone="plain">
          <ul className="space-y-1">{inactive.map((u) => userRow(u, false))}</ul>
        </Section>
      </div>
      {(st.unknown_sessions ?? 0) > 0 && (
        <p className="px-1 text-xs text-slate-500">{de.webdrive.unknownSessions(st.unknown_sessions ?? 0)}</p>
      )}

      {st.users_error && <div className="fwpt-card text-sm text-red-400">{de.webdrive.usersError(st.users_error)}</div>}
      {st.users && <FacUsers users={st.users} withDate={withDate} />}

      {unattributed.length > 0 && (
        <Section title={de.webdrive.unattributed} count={unattributed.length} tone="amber">
          <ul className="space-y-1">
            {unattributed.map((u) => (
              <li key={`${u.reason}-${u.detail}-${u.ts}`} className="text-sm text-slate-300">
                {t(u.ts)} · {u.reason} <span className="text-xs text-slate-500">{u.detail}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

const STATUS_COLOR: Record<WebdriveFacUser['status'], string> = {
  problem: 'text-red-400', active: 'text-emerald-400', inactive: 'text-slate-300',
  known: 'text-slate-500', never: 'text-slate-500',
};

/** Alle User, die der FAC kennt — mit fehlenden AD-Attributen, bevor sie bei
 *  der Erstanmeldung daran scheitern. */
function FacUsers({ users, withDate }: { users: WebdriveFacUser[]; withDate: boolean }) {
  const missing = users.filter((u) => u.missing.length > 0).length;
  return (
    <div className="fwpt-card space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-2 text-[11px] font-medium uppercase tracking-wide text-slate-400">
        <span>{de.webdrive.users} ({users.length})</span>
        {missing > 0 && <span className="text-amber-400">· {de.webdrive.usersMissing(missing)}</span>}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <tbody>
            {users.map((u) => (
              <tr key={u.username} className="border-t border-slate-800/60">
                <td className="py-1 pr-3 text-slate-200">{u.username}</td>
                <td className="py-1 pr-3 text-slate-400">{u.name || '–'}</td>
                <td className="py-1 pr-3 text-xs text-slate-500">{u.email || '–'}</td>
                <td className="py-1 pr-3 text-xs">
                  {u.missing.length > 0 && (
                    <span className="inline-flex items-center gap-1 text-amber-400">
                      <AlertTriangle size={12} /> {de.webdrive.missing(u.missing.join(', '))}
                    </span>
                  )}
                  {!u.enabled && <span className="ml-2 text-red-400">{de.webdrive.disabled}</span>}
                </td>
                <td className={`py-1 text-right text-xs ${STATUS_COLOR[u.status]}`}>
                  {de.webdrive.userStatus[u.status]}{u.last && ` · ${fmt(u.last, withDate)}`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
