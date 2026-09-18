import { Crosshair, RefreshCw, Trash2, Upload } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { diagramHardware, getConfig, patchConfig, type HardwareModel } from '../../api';
import { de } from '../../i18n/de';
import PortCalibrator, { type Spot } from './PortCalibrator';

// Shape-Bibliothek: je erkanntem Gerätemodell ein Bild und die Lage seiner
// Buchsen. Die Liste der Modelle kommt aus LibreNMS — Freitext taugt als
// Schlüssel nicht, weil sich jedes Modell auf fünf Arten schreiben lässt und
// ein Tippfehler erst auffällt, wenn die Zeichnung fertig ist und nichts passt.
const MAX_BYTES = 512_000;

interface Rule {
  hardware?: string; match?: string; label?: string; image?: string;
  width?: number; height?: number;
  ports?: Record<string, Spot>; port_w?: number; port_h?: number;
}

export default function ShapesPanel() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [models, setModels] = useState<HardwareModel[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [calibrate, setCalibrate] = useState<string | null>(null);
  const pickFor = useRef<string | null>(null);
  const file = useRef<HTMLInputElement>(null);

  useEffect(() => { getConfig('shapes').then((c) => setRules((c.rules as Rule[]) ?? [])); }, []);
  useEffect(() => { void load(); }, []);

  async function load() {
    setStatus(null);
    try {
      setModels((await diagramHardware()).models);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  const ruleFor = (hw: string) => rules.find((r) => r.hardware === hw);

  function patch(hw: string, change: Partial<Rule>) {
    setRules((l) => {
      const idx = l.findIndex((r) => r.hardware === hw);
      if (idx < 0) return [...l, { hardware: hw, ...change }];
      return l.map((r, i) => (i === idx ? { ...r, ...change } : r));
    });
  }

  async function save() {
    setBusy(true);
    try {
      // Regeln ohne Bild tragen nichts — und Alt-Regeln mit Teilstring-Muster
      // bleiben unangetastet, damit nichts kaputtgeht, was schon läuft.
      const clean = rules.filter((r) => r.image && (r.hardware || r.match));
      setRules(await patchConfig('shapes', { rules: clean }).then((c) => (c.rules as Rule[]) ?? []));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  function pick(f: File | undefined) {
    const hw = pickFor.current;
    setStatus(null);
    if (!f || !hw) return;
    if (!/^image\/(png|jpeg|gif|svg\+xml|webp)$/.test(f.type)) {
      setStatus(de.settings.tbLogoType); return;
    }
    if (f.size > MAX_BYTES) { setStatus(de.settings.tbLogoTooBig); return; }
    const r = new FileReader();
    r.onload = () => patch(hw, { image: String(r.result) });
    r.readAsDataURL(f);
  }

  const open = calibrate ? ruleFor(calibrate) : undefined;
  const openModel = models.find((m) => m.hardware === calibrate);

  return (
    <div className="fwpt-card space-y-3">
      <div className="flex items-start gap-2">
        <div>
          <h2 className="font-medium text-slate-100">{de.settings.shapes}</h2>
          <p className="mt-0.5 text-xs text-slate-500">{de.settings.shapesHint}</p>
        </div>
        <button type="button" className="fwpt-btn-ghost ml-auto shrink-0" onClick={load}>
          <RefreshCw size={14} /> {de.settings.shapesReload}
        </button>
      </div>

      <input ref={file} type="file" className="hidden"
        accept="image/png,image/jpeg,image/svg+xml,image/webp,image/gif"
        onChange={(e) => { pick(e.target.files?.[0]); e.target.value = ''; }} />

      {models.length === 0 && <p className="text-xs text-slate-600">{de.settings.shapesNoModels}</p>}

      <div className="space-y-1.5">
        {models.map((m) => {
          const r = ruleFor(m.hardware);
          const placed = Object.keys(r?.ports ?? {}).length;
          return (
            <div key={m.hardware} className="flex items-center gap-2">
              <div className="flex h-11 w-32 shrink-0 items-center justify-center rounded border border-slate-700 bg-white">
                {r?.image
                  ? <img src={r.image} alt="" className="max-h-9 max-w-28 object-contain" />
                  : <span className="text-[10px] text-slate-500">{de.settings.shapesDefault}</span>}
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm text-slate-200" title={m.hardware}>{m.hardware}</p>
                <p className="truncate text-[11px] text-slate-600">
                  {de.settings.shapesCount(m.count)}
                  {m.example ? ` · z. B. ${m.example}` : ''}
                  {placed > 0 ? ` · ${de.settings.shapesCalibrated(placed)}` : ''}
                </p>
              </div>
              <button type="button" className="fwpt-btn-ghost shrink-0"
                onClick={() => { pickFor.current = m.hardware; file.current?.click(); }}>
                <Upload size={14} /> {de.settings.shapesImage}
              </button>
              <button type="button" className="fwpt-btn-ghost shrink-0" disabled={!r?.image}
                title={de.settings.calHint} onClick={() => setCalibrate(m.hardware)}>
                <Crosshair size={14} /> {de.settings.shapesCalibrate}
              </button>
              {r && (
                <button type="button" className="shrink-0 text-slate-500 hover:text-red-400"
                  title={de.settings.shapesClear}
                  onClick={() => setRules((l) => l.filter((x) => x.hardware !== m.hardware))}>
                  <Trash2 size={15} />
                </button>
              )}
            </div>
          );
        })}
      </div>

      {calibrate && open?.image && openModel && (
        <PortCalibrator
          image={open.image} deviceId={openModel.device_id}
          initial={open.ports ?? {}}
          portW={open.port_w ?? 16} portH={open.port_h ?? 16}
          onClose={() => setCalibrate(null)}
          onSave={(ports, size, sizes) => {
            patch(calibrate, {
              ports, width: size.width, height: size.height,
              port_w: sizes.w, port_h: sizes.h,
            });
            setCalibrate(null);
          }} />
      )}

      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>
          {de.settings.save}
        </button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
