import { Plus, Trash2, X } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import { de } from '../../i18n/de';

// Buchsenraster auf einem Modellbild einmessen.
//
// Ein Bild allein trägt keine Information — die Leitung muss an der richtigen
// Buchse landen. Von Hand Koordinaten einzutippen wäre mühsam, deshalb hier
// zwei Klicks: erste und letzte Buchse eines Blocks. Aus Spalten und Reihen
// folgt der Abstand, der Rest ist Rechnen.
//
// Zählrichtung ist entscheidend: viele Switches führen oben die ungeraden und
// unten die geraden Ports (zigzag), andere oben 1..24 und unten 25..48
// (rowwise). Ohne diese Angabe landet die Hälfte der Leitungen falsch.

export interface Block {
  cols: number; rows: number; order: 'rowwise' | 'zigzag'; start: number;
  x: number; y: number; dx: number; dy: number; w: number; h: number;
  x2?: number; y2?: number;
}

const EMPTY: Block = {
  cols: 12, rows: 2, order: 'zigzag', start: 1,
  x: 0, y: 0, dx: 0, dy: 0, w: 20, h: 20,
};

function withPitch(b: Block): Block {
  const dx = b.cols > 1 && b.x2 !== undefined ? (b.x2 - b.x) / (b.cols - 1) : b.dx;
  const dy = b.rows > 1 && b.y2 !== undefined ? (b.y2 - b.y) / (b.rows - 1) : b.dy;
  return { ...b, dx, dy };
}

/** Mittelpunkt der i-ten Buchse eines Blocks — dieselbe Regel wie im Backend. */
export function center(b: Block, i: number): { x: number; y: number } {
  const [col, row] = b.order === 'zigzag'
    ? [Math.floor(i / b.rows), i % b.rows]
    : [i % b.cols, Math.floor(i / b.cols)];
  return { x: b.x + col * b.dx, y: b.y + row * b.dy };
}

export default function PortCalibrator({ image, initial, onSave, onClose }: {
  image: string;
  initial: Block[];
  onSave: (blocks: Block[], size: { width: number; height: number }) => void;
  onClose: () => void;
}) {
  const [blocks, setBlocks] = useState<Block[]>(initial.length ? initial : [{ ...EMPTY }]);
  const [active, setActive] = useState(0);
  const [next, setNext] = useState<'first' | 'last'>('first');
  const [size, setSize] = useState({ width: 0, height: 0 });
  const img = useRef<HTMLImageElement>(null);

  const shown = Math.min(size.width || 900, 900);
  const scale = size.width ? shown / size.width : 1;

  const set = (patch: Partial<Block>) =>
    setBlocks((l) => l.map((b, i) => (i === active ? withPitch({ ...b, ...patch }) : b)));

  function click(e: React.MouseEvent<HTMLImageElement>) {
    const r = e.currentTarget.getBoundingClientRect();
    const x = Math.round((e.clientX - r.left) / scale);
    const y = Math.round((e.clientY - r.top) / scale);
    if (next === 'first') {
      set({ x, y });
      setNext('last');
    } else {
      set({ x2: x, y2: y });
      setNext('first');
    }
  }

  const preview = useMemo(() => blocks.flatMap((b, bi) => {
    const n = Math.max(0, b.cols * b.rows);
    return Array.from({ length: n }, (_v, i) => ({ bi, i, ...center(b, i), w: b.w, h: b.h }));
  }), [blocks]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/70 p-6">
      <div className="fwpt-card w-full max-w-5xl space-y-3">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <h3 className="text-sm font-medium text-slate-100">{de.settings.calTitle}</h3>
          <button type="button" onClick={onClose}
            className="ml-auto text-slate-500 hover:text-slate-300" aria-label="Schließen">
            <X size={16} />
          </button>
        </div>
        <p className="text-xs text-slate-500">{de.settings.calHint}</p>

        <div className="relative inline-block bg-white" style={{ width: shown }}>
          <img ref={img} src={image} alt="" onClick={click}
            className="block cursor-crosshair" style={{ width: shown }}
            onLoad={(e) => setSize({
              width: e.currentTarget.naturalWidth, height: e.currentTarget.naturalHeight,
            })} />
          {preview.map((p) => (
            <div key={`${p.bi}-${p.i}`}
              className={`pointer-events-none absolute border-2 ${
                p.bi === active ? 'border-emerald-500' : 'border-slate-400'}`}
              style={{
                left: (p.x - p.w / 2) * scale, top: (p.y - p.h / 2) * scale,
                width: p.w * scale, height: p.h * scale,
              }} />
          ))}
        </div>

        <p className="text-xs text-cyan-400">
          {next === 'first' ? de.settings.calClickFirst : de.settings.calClickLast}
          {size.width > 0 && <span className="ml-2 text-slate-600">
            {size.width} × {size.height} px</span>}
        </p>

        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.settings.calBlock}</span>
            <select className="fwpt-input w-28" value={active}
              onChange={(e) => { setActive(Number(e.target.value)); setNext('first'); }}>
              {blocks.map((_b, i) => <option key={i} value={i}>{i + 1}</option>)}
            </select>
          </label>
          {([['cols', de.settings.calCols], ['rows', de.settings.calRows],
             ['start', de.settings.calStart], ['w', de.settings.calW],
             ['h', de.settings.calH]] as const).map(([key, label]) => (
            <label key={key} className="flex flex-col gap-1">
              <span className="text-[11px] text-slate-500">{label}</span>
              <input className="fwpt-input w-20" type="number" min={1}
                value={blocks[active][key]}
                onChange={(e) => set({ [key]: Number(e.target.value) } as Partial<Block>)} />
            </label>
          ))}
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.settings.calOrder}</span>
            <select className="fwpt-input w-52" value={blocks[active].order}
              onChange={(e) => set({ order: e.target.value as Block['order'] })}>
              <option value="zigzag">{de.settings.calZigzag}</option>
              <option value="rowwise">{de.settings.calRowwise}</option>
            </select>
          </label>
          <button type="button" className="fwpt-btn-ghost"
            onClick={() => { setBlocks((l) => [...l, { ...EMPTY }]); setActive(blocks.length); setNext('first'); }}>
            <Plus size={14} /> {de.settings.calAddBlock}
          </button>
          {blocks.length > 1 && (
            <button type="button" className="fwpt-btn-ghost"
              onClick={() => { setBlocks((l) => l.filter((_b, i) => i !== active)); setActive(0); }}>
              <Trash2 size={14} />
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button type="button" className="fwpt-btn"
            disabled={!size.width}
            onClick={() => onSave(blocks.map(withPitch), size)}>
            {de.settings.save}
          </button>
          <button type="button" className="fwpt-btn-ghost" onClick={onClose}>
            {de.common.cancel}
          </button>
          <span className="text-xs text-slate-600">
            {de.settings.calPorts(preview.length)}
          </span>
        </div>
      </div>
    </div>
  );
}
