import { Boxes } from 'lucide-react';
import { useState } from 'react';
import { freeSubnets, type FreeSubnetResult } from '../api';
import { de } from '../i18n/de';

const SIZES = [30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16];

export default function FreeSubnet() {
  const [supernet, setSupernet] = useState('');
  const [prefix, setPrefix] = useState(24);
  const [res, setRes] = useState<FreeSubnetResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function find() {
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await freeSubnets(supernet.trim(), prefix));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Boxes size={16} className="text-cyan-400" /> {de.freesubnet.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.freesubnet.hint}</p>
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex flex-1 flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.freesubnet.supernet}</span>
          <input className="fwpt-input font-mono" value={supernet}
            onChange={(e) => setSupernet(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && supernet.trim() && find()}
            placeholder="10.180.0.0/16" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-[11px] text-slate-500">{de.freesubnet.size}</span>
          <select className="fwpt-input w-24" value={prefix}
            onChange={(e) => setPrefix(Number(e.target.value))}>
            {SIZES.map((p) => <option key={p} value={p}>/{p}</option>)}
          </select>
        </label>
        <button type="button" className="fwpt-btn" onClick={find} disabled={busy || !supernet.trim()}>
          {de.freesubnet.find}
        </button>
      </div>

      {err && <p className="text-sm text-red-400">{err}</p>}

      {res && (
        <>
          <p className="text-xs text-slate-500">
            {res.allocated} / {res.subnets_total} {de.freesubnet.summary}: {res.free.length}
            {res.capped && <span className="ml-1 text-amber-500">{de.freesubnet.capped}</span>}
          </p>
          {res.free.length === 0 ? (
            <p className="text-sm text-amber-400">{de.freesubnet.none}</p>
          ) : (
            <div className="flex max-h-64 flex-wrap gap-1.5 overflow-y-auto">
              {res.free.map((cidr) => (
                <span key={cidr} className="rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-xs text-emerald-300">
                  {cidr}
                </span>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
