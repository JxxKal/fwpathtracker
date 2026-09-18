import { RefreshCw, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { dnsCachePurge, dnsCacheStats, getConfig, patchConfig, type DnsCacheStats }
  from '../../api';
import { de } from '../../i18n/de';

function toList(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean);
}

/** Leeres Feld heißt „Vorgabe", nicht „0" — sonst schaltet ein versehentlich
 *  geleertes Feld den Cache ab. */
function toNum(s: string, fallback: number): number {
  const n = Number(s.trim());
  return s.trim() === '' || !Number.isFinite(n) || n < 0 ? fallback : Math.round(n);
}

export default function DnsPanel() {
  const [resolvers, setResolvers] = useState('');
  const [domains, setDomains] = useState('');
  const [hitDays, setHitDays] = useState('7');
  const [missHours, setMissHours] = useState('24');
  const [retention, setRetention] = useState('180');
  const [stats, setStats] = useState<DnsCacheStats | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getConfig('dns').then((cfg) => {
      setResolvers(((cfg.resolvers as string[]) ?? []).join(', '));
      setDomains(((cfg.search_domains as string[]) ?? []).join(', '));
      setHitDays(String(cfg.cache_hit_days ?? 7));
      setMissHours(String(cfg.cache_miss_hours ?? 24));
      setRetention(String(cfg.cache_retention_days ?? 180));
    }).catch(() => { /* Panel bleibt auf den Vorgaben */ });
    void loadStats();
  }, []);

  async function loadStats() {
    try {
      setStats(await dnsCacheStats());
    } catch {
      setStats(null);   // Ein unlesbarer Cache ist kein Grund, die Felder zu sperren.
    }
  }

  async function save() {
    setBusy(true);
    try {
      await patchConfig('dns', {
        resolvers: toList(resolvers), search_domains: toList(domains),
        cache_hit_days: toNum(hitDays, 7),
        cache_miss_hours: toNum(missHours, 24),
        cache_retention_days: toNum(retention, 180),
      });
      setStatus(de.settings.saved);
      await loadStats();
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function purge(days?: number) {
    setBusy(true);
    setStatus(null);
    try {
      const r = await dnsCachePurge(days);
      setStatus(de.settings.dnsCacheRemoved(r.removed));
      await loadStats();
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  const when = stats?.oldest ? new Date(stats.oldest).toLocaleDateString('de-DE') : null;

  return (
    <div className="space-y-4">
      <div className="fwpt-card space-y-3">
        <h2 className="font-medium text-slate-100">{de.settings.dns}</h2>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.dnsResolvers}</label>
          <input className="fwpt-input" value={resolvers} placeholder="10.0.0.53, 10.0.1.53"
            onChange={(e) => setResolvers(e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.dnsDomains}</label>
          <input className="fwpt-input" value={domains} placeholder="corp.example, dmz.example"
            onChange={(e) => setDomains(e.target.value)} />
        </div>
      </div>

      <div className="fwpt-card space-y-3">
        <div>
          <h2 className="font-medium text-slate-100">{de.settings.dnsCache}</h2>
          <p className="mt-0.5 text-xs text-slate-500">{de.settings.dnsCacheHint}</p>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <label className="mb-1 block text-xs text-slate-400">{de.settings.dnsHitDays}</label>
            <input className="fwpt-input" type="number" min={0} value={hitDays}
              onChange={(e) => setHitDays(e.target.value)} />
            <p className="mt-1 text-[11px] text-slate-600">{de.settings.dnsHitDaysHint}</p>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">{de.settings.dnsMissHours}</label>
            <input className="fwpt-input" type="number" min={0} value={missHours}
              onChange={(e) => setMissHours(e.target.value)} />
            <p className="mt-1 text-[11px] text-slate-600">{de.settings.dnsMissHoursHint}</p>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">
              {de.settings.dnsRetentionDays}
            </label>
            <input className="fwpt-input" type="number" min={0} value={retention}
              onChange={(e) => setRetention(e.target.value)} />
            <p className="mt-1 text-[11px] text-slate-600">{de.settings.dnsRetentionDaysHint}</p>
          </div>
        </div>

        <div className="rounded border border-slate-800 bg-slate-950/60 p-2 text-xs text-slate-400">
          {stats && stats.total > 0 ? (
            <span>
              {de.settings.dnsCacheStats(stats.total, stats.named, stats.misses)}
              {' · '}{de.settings.dnsCacheSaved(stats.hits)}
              {when ? ` · ${de.settings.dnsCacheOldest(when)}` : ''}
            </span>
          ) : <span className="text-slate-600">{de.settings.dnsCacheEmpty}</span>}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>
            {de.settings.save}
          </button>
          <button type="button" className="fwpt-btn-ghost" onClick={() => void loadStats()}
            disabled={busy}>
            <RefreshCw size={14} /> {de.common.refresh}
          </button>
          <button type="button" className="fwpt-btn-ghost" onClick={() => void purge()}
            disabled={busy}>
            {de.settings.dnsCachePurge}
          </button>
          <button type="button" className="fwpt-btn-ghost text-red-300 hover:text-red-200"
            title={de.settings.dnsCacheClearHint}
            onClick={() => void purge(0)} disabled={busy}>
            <Trash2 size={14} /> {de.settings.dnsCacheClear}
          </button>
          {status && <span className="text-sm text-slate-400">{status}</span>}
        </div>
      </div>
    </div>
  );
}
