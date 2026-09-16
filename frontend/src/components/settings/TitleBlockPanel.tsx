import { Trash2, Upload } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

// Schriftfeld der Netzpläne: Stammdaten, die kein System erraten kann.
// Titel, Datum, Autor, Zahlen und Zeichnungsnummer füllt A38 selbst.
//
// Das Logo wird als Data-URI in der Config abgelegt und landet im Style jeder
// erzeugten Zeichnung — deshalb die Größenbremse. Ein PNG mit 400px Breite
// oder ein SVG reicht für ein Schriftfeld völlig.
const WARN_BYTES = 120_000;
const MAX_BYTES = 512_000;

export default function TitleBlockPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const file = useRef<HTMLInputElement>(null);

  useEffect(() => { getConfig('titleblock').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('titleblock', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  function pick(f: File | undefined) {
    setStatus(null);
    if (!f) return;
    if (!/^image\/(png|jpeg|gif|svg\+xml|webp)$/.test(f.type)) {
      setStatus(de.settings.tbLogoType);
      return;
    }
    if (f.size > MAX_BYTES) {
      setStatus(de.settings.tbLogoTooBig);
      return;
    }
    const r = new FileReader();
    r.onload = () => {
      set('logo', String(r.result));
      if (f.size > WARN_BYTES) setStatus(de.settings.tbLogoLarge);
    };
    r.readAsDataURL(f);
  }

  const logo = (cfg.logo as string) ?? '';
  const enabled = (cfg.enabled as boolean) ?? true;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.titleBlock}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.titleBlockHint}</p>
      </div>

      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={enabled} onChange={(e) => set('enabled', e.target.checked)} />
        {de.settings.tbEnabled}
      </label>

      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.tbCompany}</label>
          <input className="fwpt-input" value={(cfg.company as string) ?? ''}
            placeholder="Beispiel Energy" onChange={(e) => set('company', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.tbConfidential}</label>
          <input className="fwpt-input" value={(cfg.confidential as string) ?? 'Company confidential'}
            onChange={(e) => set('confidential', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.tbGroup}</label>
          <input className="fwpt-input" value={(cfg.group as string) ?? ''}
            placeholder="WD2/DR PLT/IT OT" onChange={(e) => set('group', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">{de.settings.tbPrefix}</label>
          <input className="fwpt-input font-mono" value={(cfg.drawing_no_prefix as string) ?? 'A38'}
            onChange={(e) => set('drawing_no_prefix', e.target.value)} />
        </div>
      </div>

      <div>
        <label className="mb-1 block text-xs text-slate-400">{de.settings.tbLogo}</label>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex h-16 w-44 items-center justify-center rounded border border-slate-700 bg-white">
            {logo
              ? <img src={logo} alt="" className="max-h-14 max-w-40 object-contain" />
              : <span className="text-xs text-slate-500">{de.settings.tbLogoNone}</span>}
          </div>
          <input ref={file} type="file" accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif"
            className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
          <button type="button" className="fwpt-btn-ghost" onClick={() => file.current?.click()}>
            <Upload size={14} /> {de.settings.tbLogoPick}
          </button>
          {logo && (
            <button type="button" className="fwpt-btn-ghost" onClick={() => set('logo', '')}>
              <Trash2 size={14} /> {de.settings.tbLogoClear}
            </button>
          )}
        </div>
        <p className="mt-1 text-[11px] text-slate-600">{de.settings.tbLogoHint}</p>
      </div>

      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>
          {de.settings.save}
        </button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
