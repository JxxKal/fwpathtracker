import { Database, Globe, Server } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { searchEndpoints } from '../api';
import type { Provenance, SearchHit } from '../types';

export function ProvenanceIcon({ provenance }: { provenance: Provenance }) {
  // FMG = Server, iTop = Database, DNS/IP = Globe
  if (provenance === 'fmg') return <Server size={13} className="text-cyan-400" />;
  if (provenance === 'itop') return <Database size={13} className="text-emerald-400" />;
  return <Globe size={13} className="text-slate-400" />;
}

// Reihenfolge = Identifizierungs-Reihenfolge: FortiManager zuerst, dann iTop, dann DNS.
const GROUPS: { key: Provenance; label: string }[] = [
  { key: 'fmg', label: 'FortiManager' },
  { key: 'itop', label: 'iTop (CMDB)' },
  { key: 'dns', label: 'DNS' },
];

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}

export default function EndpointAutocomplete({ value, onChange, placeholder }: Props) {
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const timer = useRef<number>();
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    window.clearTimeout(timer.current);
    // Nur überspringen, wenn die Eingabe wie eine (Teil-)IP aussieht (Ziffern
    // MIT Punkt). Reine Ziffern wie "3101"/"0042" sind gültige Objektnamen-Teile
    // (z.B. WD-OT-L3-SVO3101) und sollen durchsucht werden.
    const looksLikeIp = /^[0-9]+(\.[0-9]*)+$/.test(value.trim());
    if (value.trim().length < 2 || looksLikeIp) {
      setHits([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    timer.current = window.setTimeout(async () => {
      try {
        const res = await searchEndpoints(value.trim());
        setHits(res);
        setOpen(true);
      } catch {
        setHits([]);
      } finally {
        setLoading(false);
      }
    }, 300);
    return () => window.clearTimeout(timer.current);
  }, [value]);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  function pick(h: SearchHit) {
    onChange(h.name);
    setOpen(false);
  }

  const grouped = GROUPS.map((g) => ({ ...g, items: hits.filter((h) => h.provenance === g.key) }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="relative" ref={box}>
      <input
        className="fwpt-input" placeholder={placeholder} value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => (hits.length > 0 || loading) && setOpen(true)}
        autoComplete="off"
      />
      {open && (loading || hits.length > 0 || value.trim().length >= 2) && (
        <div className="absolute z-20 mt-1 max-h-80 w-full overflow-auto rounded-md border border-slate-700 bg-slate-900 shadow-xl">
          {loading && (
            <p className="px-3 py-2 text-xs text-slate-500">Suche in FortiManager …</p>
          )}
          {!loading && hits.length === 0 && (
            <p className="px-3 py-2 text-xs text-slate-500">
              Kein Objekt in FortiManager, iTop oder DNS gefunden.
            </p>
          )}
          {!loading && grouped.map((g) => (
            <div key={g.key}>
              <p className="border-b border-slate-800 bg-slate-950/60 px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                {g.label}
              </p>
              <ul>
                {g.items.map((h) => (
                  <li key={`${h.provenance}-${h.name}`}>
                    <button
                      type="button"
                      title={h.name}
                      className="flex w-full items-start gap-2 px-3 py-2 text-left text-sm hover:bg-slate-800"
                      onClick={() => pick(h)}
                    >
                      <ProvenanceIcon provenance={h.provenance} />
                      <span className="min-w-0 flex-1">
                        <span className="block break-all font-medium text-slate-200">{h.name}</span>
                        <span className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
                          {h.type && (
                            <span className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-400">
                              {h.type}
                            </span>
                          )}
                          {(h.ip ?? h.fqdn) && (
                            <span className="font-mono">{h.ip ?? h.fqdn}</span>
                          )}
                        </span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
