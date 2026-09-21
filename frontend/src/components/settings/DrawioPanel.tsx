import { CheckCircle2, ExternalLink, TriangleAlert, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { drawioTest, getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';

// Selbst gehostetes draw.io: nur die Basis-URL. Kein Token, kein Secret —
// draw.io ist eine statische Web-App, der Inhalt bleibt im Browser.
export default function DrawioPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; soft?: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getConfig('drawio').then(setCfg); }, []);

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('drawio', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true); setTest(null);
    try {
      const r = await drawioTest();
      if (r.hint) setTest({ ok: false, soft: true, text: r.hint });
      else setTest({ ok: r.ok, text: r.looks_like_drawio ? `OK — HTTP ${r.status}, draw.io erkannt` : `HTTP ${r.status}, sieht aber nicht nach draw.io aus` });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="font-medium text-slate-100">{de.settings.drawio}</h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.settings.drawioHint}</p>
      </div>
      <div>
        <label className="mb-1 block text-xs text-slate-400">Base-URL</label>
        <input className="fwpt-input" value={(cfg.base_url as string) ?? ''}
          placeholder="http://svo3041-ot:8780"
          onChange={(e) => setCfg((c) => ({ ...c, base_url: e.target.value }))} />
      </div>
      <div>
        <label className="mb-1 block text-xs text-slate-400">{de.settings.uplinkLabel}</label>
        <input className="fwpt-input" value={(cfg.uplink_label as string) ?? ''}
          placeholder="Uplink"
          onChange={(e) => setCfg((c) => ({ ...c, uplink_label: e.target.value }))} />
        <p className="mt-1 text-[11px] text-slate-600">{de.settings.uplinkLabelHint}</p>
      </div>
      {test && (
        <div className={`flex items-start gap-2 text-sm ${test.ok ? 'text-emerald-400' : test.soft ? 'text-amber-400' : 'text-red-400'}`}>
          {test.ok ? <CheckCircle2 size={16} className="mt-0.5 shrink-0" />
            : test.soft ? <TriangleAlert size={16} className="mt-0.5 shrink-0" />
              : <XCircle size={16} className="mt-0.5 shrink-0" />}
          <span>{test.text}</span>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={runTest} disabled={busy}>{de.settings.test}</button>
        {typeof cfg.base_url === 'string' && cfg.base_url.trim() && (
          <a className="fwpt-btn-ghost" href={cfg.base_url.trim()} target="_blank" rel="noopener noreferrer">
            <ExternalLink size={14} /> Im Browser öffnen
          </a>
        )}
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
