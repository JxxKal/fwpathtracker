import { Network } from 'lucide-react';
import { useState } from 'react';
import { inventoryOwns, type OwnsMatch, type OwnsResult } from '../api';
import { de } from '../i18n/de';

// Diagnose: welche VDOM/Firewall hält ein Netz? Macht falsche/mehrdeutige
// Ingress-Zuordnungen sichtbar (z.B. Quelle scheinbar an falscher FW).
export default function NetOwnership() {
  const [ip, setIp] = useState('');
  const [res, setRes] = useState<OwnsResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function lookup() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await inventoryOwns(ip.trim()));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const isIngress = (m: OwnsMatch) =>
    res?.ingress != null && m.device === res.ingress.device && m.vdom === res.ingress.vdom;

  // Mehrdeutig: mehrere distinkte Geräte/VDOMs mit gleichem (längstem) Präfix.
  const topLen = res?.matches[0]?.prefixlen;
  const topOwners = new Set(
    (res?.matches ?? [])
      .filter((m) => m.prefixlen === topLen)
      .map((m) => `${m.device}/${m.vdom}`),
  );
  const ambiguous = topOwners.size > 1;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Network size={16} className="text-cyan-400" /> {de.owns.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.owns.hint}</p>
      </div>
      <div className="flex gap-2">
        <input
          className="fwpt-input" placeholder="10.180.42.208" value={ip}
          onChange={(e) => setIp(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && ip.trim() && lookup()}
        />
        <button type="button" className="fwpt-btn" onClick={lookup} disabled={busy || !ip.trim()}>
          {de.owns.check}
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res && res.matches.length === 0 && (
        <p className="text-sm text-amber-400">{de.owns.none}</p>
      )}

      {res && res.matches.length > 0 && (
        <>
          {ambiguous && <p className="text-sm text-amber-400">⚠ {de.owns.ambiguous}</p>}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-slate-500">
                <tr>
                  <th className="px-3 py-1.5 font-medium">Gerät / VDOM</th>
                  <th className="px-3 py-1.5 font-medium">Interface</th>
                  <th className="px-3 py-1.5 font-medium">Netz</th>
                  <th className="px-3 py-1.5 font-medium">Quelle</th>
                </tr>
              </thead>
              <tbody>
                {res.matches.map((m, i) => (
                  <tr key={`${m.device}-${m.vdom}-${m.cidr}-${i}`}
                    className={isIngress(m)
                      ? 'bg-cyan-950/60 text-cyan-200 ring-1 ring-inset ring-cyan-700'
                      : 'text-slate-400'}>
                    <td className="whitespace-nowrap px-3 py-1.5">
                      <span className="text-slate-200">{m.device}</span>
                      <span className="text-slate-500"> / {m.vdom}</span>
                      {isIngress(m) && (
                        <span className="ml-2 rounded bg-cyan-900/70 px-1.5 py-0.5 text-[10px] text-cyan-200">
                          {de.owns.ingressTag}
                        </span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono">{m.interface ?? '—'}</td>
                    <td className="whitespace-nowrap px-3 py-1.5 font-mono">{m.cidr}</td>
                    <td className="whitespace-nowrap px-3 py-1.5">{m.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
