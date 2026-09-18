import { Undo2, X, ZoomIn, ZoomOut } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { diagramDevicePorts } from '../../api';
import { de } from '../../i18n/de';

// Buchsen eines Modellbilds zuordnen — durch Klicken, nicht durch Rechnen.
//
// Ein Raster war der falsche Ansatz: echte Frontblenden haben Lücken zwischen
// Portgruppen, Hutschienengeräte stehen hochkant, und 40/100-G-Buchsen sitzen
// abgesetzt und in anderer Größe. Deshalb bekommt jeder Port seinen eigenen
// Platz: die Portliste des Geräts wird der Reihe nach abgearbeitet, und der
// nächste Port landet dort, wo geklickt wird — daneben oder darunter, wie das
// Gerät es eben hergibt.
//
// Zugeordnet wird über den NAMEN. `HundredGigE1/0/1` und `GigabitEthernet1/0/1`
// tragen dieselbe Nummer und sind verschiedene Buchsen; der Name ist bei allen
// Geräten desselben Modells gleich und trägt die Zuordnung deshalb weiter.

export interface Spot { x: number; y: number; w?: number; h?: number }

export default function PortCalibrator({ image, deviceId, initial, portW, portH,
  onSave, onClose }: {
  image: string;
  deviceId: string;
  initial: Record<string, Spot>;
  portW: number;
  portH: number;
  onSave: (ports: Record<string, Spot>, size: { width: number; height: number },
    sizes: { w: number; h: number }) => void;
  onClose: () => void;
}) {
  const [names, setNames] = useState<{ name: string; alias: string | null }[]>([]);
  const [spots, setSpots] = useState<Record<string, Spot>>(initial);
  const [order, setOrder] = useState<string[]>(Object.keys(initial));
  const [w, setW] = useState(portW);
  const [h, setH] = useState(portH);
  const [zoom, setZoom] = useState(1);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    diagramDevicePorts(deviceId).then((r) => setNames(r.ports))
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [deviceId]);

  // Der nächste Port ohne Platz — das ist der, der beim nächsten Klick sitzt.
  const next = useMemo(
    () => names.find((p) => !(p.name in spots))?.name ?? null,
    [names, spots],
  );
  const done = names.filter((p) => p.name in spots).length;
  const scale = size.width ? (Math.min(size.width, 1000) / size.width) * zoom : zoom;

  function click(e: React.MouseEvent<HTMLImageElement>) {
    if (!next) return;
    const r = e.currentTarget.getBoundingClientRect();
    const x = Math.round((e.clientX - r.left) / scale);
    const y = Math.round((e.clientY - r.top) / scale);
    setSpots((s) => ({ ...s, [next]: { x, y } }));
    setOrder((o) => [...o, next]);
  }

  function undo() {
    const last = order[order.length - 1];
    if (!last) return;
    setOrder((o) => o.slice(0, -1));
    setSpots((s) => { const { [last]: _drop, ...rest } = s; return rest; });
  }

  /** Einzelne Buchse anders groß machen — 40/100 G sind breiter als RJ45. */
  function resize(name: string, key: 'w' | 'h', value: number) {
    setSpots((s) => ({ ...s, [name]: { ...s[name], [key]: value || undefined } }));
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-black/70 p-6">
      <div className="fwpt-card w-full max-w-6xl space-y-3">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
          <h3 className="text-sm font-medium text-slate-100">{de.settings.calTitle}</h3>
          <span className="text-xs text-slate-500">{de.settings.calProgress(done, names.length)}</span>
          <button type="button" onClick={onClose}
            className="ml-auto text-slate-500 hover:text-slate-300" aria-label="Schließen">
            <X size={16} />
          </button>
        </div>
        <p className="text-xs text-slate-500">{de.settings.calHint}</p>
        {err && <p className="text-sm text-red-400">{err}</p>}

        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.settings.calW}</span>
            <input className="fwpt-input w-20" type="number" min={4} value={w}
              onChange={(e) => setW(Number(e.target.value))} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-[11px] text-slate-500">{de.settings.calH}</span>
            <input className="fwpt-input w-20" type="number" min={4} value={h}
              onChange={(e) => setH(Number(e.target.value))} />
          </label>
          <button type="button" className="fwpt-btn-ghost" onClick={() => setZoom((z) => Math.min(4, z * 1.5))}>
            <ZoomIn size={14} />
          </button>
          <button type="button" className="fwpt-btn-ghost" onClick={() => setZoom((z) => Math.max(0.5, z / 1.5))}>
            <ZoomOut size={14} />
          </button>
          <button type="button" className="fwpt-btn-ghost" onClick={undo} disabled={!order.length}>
            <Undo2 size={14} /> {de.settings.calUndo}
          </button>
          <span className="pb-2 text-xs text-cyan-400">
            {next ? de.settings.calNext(next) : de.settings.calAllPlaced}
          </span>
        </div>

        <div className="max-h-[52vh] overflow-auto rounded border border-slate-800 bg-white">
          <div className="relative inline-block">
            <img src={image} alt="" onClick={click} className="block cursor-crosshair"
              style={{ width: size.width ? size.width * scale : undefined }}
              onLoad={(e) => setSize({
                width: e.currentTarget.naturalWidth, height: e.currentTarget.naturalHeight,
              })} />
            {Object.entries(spots).map(([name, s]) => (
              <div key={name} title={name}
                className="pointer-events-none absolute border-2 border-emerald-500 bg-emerald-400/20"
                style={{
                  left: (s.x - (s.w ?? w) / 2) * scale, top: (s.y - (s.h ?? h) / 2) * scale,
                  width: (s.w ?? w) * scale, height: (s.h ?? h) * scale,
                }} />
            ))}
          </div>
        </div>

        {/* Portliste: zeigt die Reihenfolge und erlaubt Sondergrößen. */}
        <div className="max-h-40 overflow-auto rounded border border-slate-800">
          <table className="w-full text-left text-xs">
            <tbody>
              {names.map((p) => {
                const s = spots[p.name];
                return (
                  <tr key={p.name} className={`border-t border-slate-800/60 ${
                    p.name === next ? 'bg-cyan-950/60 text-cyan-300' : 'text-slate-400'}`}>
                    <td className="py-1 pr-2 font-mono">{p.name}</td>
                    <td className="py-1 pr-2 text-slate-600">{p.alias}</td>
                    <td className="py-1 pr-2">{s ? `${s.x} / ${s.y}` : '—'}</td>
                    <td className="py-1 pr-2">
                      {s && (
                        <span className="flex items-center gap-1">
                          <input className="fwpt-input !w-16 !py-0.5" type="number"
                            placeholder={String(w)} value={s.w ?? ''}
                            onChange={(e) => resize(p.name, 'w', Number(e.target.value))} />
                          <input className="fwpt-input !w-16 !py-0.5" type="number"
                            placeholder={String(h)} value={s.h ?? ''}
                            onChange={(e) => resize(p.name, 'h', Number(e.target.value))} />
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="flex items-center gap-2">
          <button type="button" className="fwpt-btn" disabled={!size.width}
            onClick={() => onSave(spots, size, { w, h })}>
            {de.settings.save}
          </button>
          <button type="button" className="fwpt-btn-ghost" onClick={onClose}>
            {de.common.cancel}
          </button>
          <button type="button" className="fwpt-btn-ghost"
            onClick={() => { setSpots({}); setOrder([]); }}>
            {de.settings.calReset}
          </button>
        </div>
      </div>
    </div>
  );
}
