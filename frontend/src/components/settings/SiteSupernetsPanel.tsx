import { Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { patchConfig, siteSupernets, type SiteSupernet } from '../../api';
import { de } from '../../i18n/de';

export default function SiteSupernetsPanel() {
  const [sites, setSites] = useState<SiteSupernet[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { siteSupernets().then((r) => setSites(r.sites)).catch(() => undefined); }, []);

  const update = (i: number, k: keyof SiteSupernet, v: string) =>
    setSites((list) => list.map((s, idx) => (idx === i ? { ...s, [k]: v } : s)));

  async function save() {
    setBusy(true);
    try {
      const clean = sites.filter((s) => s.name.trim() && s.cidr.trim());
      await patchConfig('site_supernets', { sites: clean });
      setSites(clean);
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <h2 className="font-medium text-slate-100">{de.settings.siteSupernets}</h2>
      <p className="text-xs text-slate-500">
        Vorauswahl-Bereiche im „Freies Subnetz finden"-Tool (Standort → Supernet).
        Reihenfolge = Anzeige.
      </p>
      <div className="space-y-2">
        {sites.map((s, i) => (
          <div key={i} className="flex items-center gap-2">
            <input className="fwpt-input flex-1" value={s.name} placeholder="Standort"
              onChange={(e) => update(i, 'name', e.target.value)} />
            <input className="fwpt-input w-48 font-mono" value={s.cidr} placeholder="10.180.0.0/20"
              onChange={(e) => update(i, 'cidr', e.target.value)} />
            <button type="button" className="text-slate-500 hover:text-red-400"
              onClick={() => setSites((l) => l.filter((_, idx) => idx !== i))}>
              <Trash2 size={15} />
            </button>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn-ghost"
          onClick={() => setSites((l) => [...l, { name: '', cidr: '' }])}>
          <Plus size={14} /> Standort
        </button>
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
