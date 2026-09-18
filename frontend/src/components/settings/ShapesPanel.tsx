import { Crosshair, Plus, Trash2, Upload } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';
import PortCalibrator, { type Block } from './PortCalibrator';

// Shape-Bibliothek: je Muster ein Modellbild für die physischen Netzpläne.
// Bewusst als Upload statt als Konverter — Visio-Stencils der Hersteller sind
// teils altes Binärformat oder enthalten nur EMF, SVG/PNG bettet draw.io
// dagegen direkt und verlustfrei ein.
const MAX_BYTES = 512_000;

interface Rule {
  match: string; label?: string; image?: string;
  width?: number; height?: number; blocks?: Block[];
}

export default function ShapesPanel() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pickFor = useRef<number | null>(null);
  const [calibrate, setCalibrate] = useState<number | null>(null);
  const file = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getConfig('shapes').then((c) => setRules((c.rules as Rule[]) ?? []));
  }, []);

  const update = (i: number, k: keyof Rule, v: string) =>
    setRules((list) => list.map((r, idx) => (idx === i ? { ...r, [k]: v } : r)));

  async function save() {
    setBusy(true);
    try {
      const clean = rules.filter((r) => r.match.trim() && r.image);
      await patchConfig('shapes', { rules: clean });
      setRules(clean);
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  function pick(f: File | undefined) {
    const idx = pickFor.current;
    setStatus(null);
    if (!f || idx === null) return;
    if (!/^image\/(png|jpeg|gif|svg\+xml|webp)$/.test(f.type)) {
      setStatus(de.settings.tbLogoType);
      return;
    }
    if (f.size > MAX_BYTES) {
      setStatus(de.settings.tbLogoTooBig);
      return;
    }
    const r = new FileReader();
    r.onload = () => update(idx, 'image', String(r.result));
    r.readAsDataURL(f);
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.shapes}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.shapesHint}</p>
      </div>

      <input ref={file} type="file" className="hidden"
        accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif"
        onChange={(e) => { pick(e.target.files?.[0]); e.target.value = ''; }} />

      <div className="space-y-2">
        {rules.length === 0 && <p className="text-xs text-slate-600">{de.settings.shapesEmpty}</p>}
        {rules.map((r, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="flex h-12 w-28 shrink-0 items-center justify-center rounded border border-slate-700 bg-white">
              {r.image
                ? <img src={r.image} alt="" className="max-h-10 max-w-24 object-contain" />
                : <span className="text-[10px] text-slate-500">{de.settings.tbLogoNone}</span>}
            </div>
            <input className="fwpt-input w-56 font-mono" value={r.match}
              placeholder="IKS-6728A" title={de.settings.shapesMatchHint}
              onChange={(e) => update(i, 'match', e.target.value)} />
            <input className="fwpt-input flex-1" value={r.label ?? ''}
              placeholder={de.settings.shapesLabel}
              onChange={(e) => update(i, 'label', e.target.value)} />
            <button type="button" className="fwpt-btn-ghost shrink-0"
              onClick={() => { pickFor.current = i; file.current?.click(); }}>
              <Upload size={14} /> {de.settings.tbLogoPick}
            </button>
            <button type="button" className="fwpt-btn-ghost shrink-0" disabled={!r.image}
              title={de.settings.calHint} onClick={() => setCalibrate(i)}>
              <Crosshair size={14} /> {de.settings.shapesCalibrate}
            </button>
            <span className="w-28 shrink-0 text-[11px] text-slate-500">
              {r.blocks?.length
                ? de.settings.shapesCalibrated(
                  r.blocks.reduce((n, b) => n + b.cols * b.rows, 0))
                : de.settings.shapesNotCalibrated}
            </span>
            <button type="button" className="shrink-0 text-slate-500 hover:text-red-400"
              onClick={() => setRules((l) => l.filter((_x, idx) => idx !== i))}>
              <Trash2 size={15} />
            </button>
          </div>
        ))}
      </div>

      {calibrate !== null && rules[calibrate]?.image && (
        <PortCalibrator
          image={rules[calibrate].image as string}
          initial={rules[calibrate].blocks ?? []}
          onClose={() => setCalibrate(null)}
          onSave={(blocks, size) => {
            setRules((l) => l.map((r, idx) => (idx === calibrate
              ? { ...r, blocks, width: size.width, height: size.height } : r)));
            setCalibrate(null);
          }} />
      )}

      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn-ghost"
          onClick={() => setRules((l) => [...l, { match: '', label: '', image: '' }])}>
          <Plus size={14} /> {de.settings.shapesAdd}
        </button>
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>
          {de.settings.save}
        </button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
