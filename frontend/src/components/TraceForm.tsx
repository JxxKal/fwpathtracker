import { ArrowLeftRight, Play, Route, Search } from 'lucide-react';
import { FormEvent, useState } from 'react';
import { de } from '../i18n/de';
import type { TraceRequest } from '../types';
import EndpointAutocomplete from './EndpointAutocomplete';

export type TraceMode = 'service' | 'ports';

interface Props {
  onSubmit: (req: TraceRequest) => void;
  onPortSubmit: (src: string, dst: string) => void;
  busy: boolean;
  mode: TraceMode;
  onModeChange: (m: TraceMode) => void;
  initial?: TraceRequest | null;
}

export default function TraceForm({ onSubmit, onPortSubmit, busy, mode, onModeChange, initial }: Props) {
  const [src, setSrc] = useState(initial?.src ?? '');
  const [dst, setDst] = useState(initial?.dst ?? '');
  const [protocol, setProtocol] = useState(initial?.protocol ?? 'tcp');
  const [dstPort, setDstPort] = useState(initial?.dst_port ? String(initial.dst_port) : '443');
  const [srcPort, setSrcPort] = useState('');
  const [icmpType, setIcmpType] = useState('8');
  const [icmpCode, setIcmpCode] = useState('0');

  const ports = mode === 'ports';

  function build(swap = false): TraceRequest {
    const isIcmp = protocol === 'icmp';
    return {
      src: swap ? dst : src,
      dst: swap ? src : dst,
      protocol,
      dst_port: isIcmp ? null : Number(dstPort) || null,
      src_port: isIcmp || !srcPort ? null : Number(srcPort),
      icmp_type: isIcmp ? Number(icmpType) : null,
      icmp_code: isIcmp ? Number(icmpCode) : null,
    };
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!src.trim() || !dst.trim()) return;
    if (ports) onPortSubmit(src.trim(), dst.trim());
    else onSubmit(build());
  }

  const isIcmp = protocol === 'icmp';
  const disabled = busy || !src.trim() || !dst.trim();

  return (
    <form onSubmit={submit} className="fwpt-card space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <Route size={18} className="mt-0.5 text-cyan-400" />
          <div>
            <h2 className="font-medium text-slate-100">{ports ? de.trace.portsTitle : de.trace.title}</h2>
            <p className="max-w-2xl text-xs text-slate-500">{ports ? de.trace.portsHint : de.trace.hint}</p>
          </div>
        </div>
        <div className="inline-flex rounded-md border border-slate-700 p-0.5 text-xs">
          {(['service', 'ports'] as TraceMode[]).map((m) => (
            <button
              key={m} type="button"
              className={`rounded px-2.5 py-1 transition-colors ${
                mode === m ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
              onClick={() => onModeChange(m)}
            >
              {m === 'service' ? de.trace.modeService : de.trace.modePorts}
            </button>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <label className="mb-1 block text-xs text-slate-400">{de.trace.src}</label>
          <EndpointAutocomplete value={src} onChange={setSrc} placeholder="10.1.1.10 / ws0042" />
        </div>
        <div className="min-w-56 flex-1">
          <label className="mb-1 block text-xs text-slate-400">{de.trace.dst}</label>
          <EndpointAutocomplete value={dst} onChange={setDst} placeholder="10.2.1.30 / srv-db" />
        </div>
        {!ports && (
          <div>
            <label className="mb-1 block text-xs text-slate-400">{de.trace.protocol}</label>
            <select className="fwpt-input" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
        )}
        {!ports && !isIcmp && (
          <>
            <div className="w-28">
              <label className="mb-1 block text-xs text-slate-400">{de.trace.dstPort}</label>
              <input className="fwpt-input" value={dstPort} inputMode="numeric"
                onChange={(e) => setDstPort(e.target.value)} />
            </div>
            <div className="w-32">
              <label className="mb-1 block text-xs text-slate-400">{de.trace.srcPort}</label>
              <input className="fwpt-input" value={srcPort} inputMode="numeric"
                onChange={(e) => setSrcPort(e.target.value)} placeholder="—" />
            </div>
          </>
        )}
        {!ports && isIcmp && (
          <>
            <div className="w-24">
              <label className="mb-1 block text-xs text-slate-400">{de.trace.icmpType}</label>
              <input className="fwpt-input" value={icmpType} inputMode="numeric"
                onChange={(e) => setIcmpType(e.target.value)} />
            </div>
            <div className="w-24">
              <label className="mb-1 block text-xs text-slate-400">{de.trace.icmpCode}</label>
              <input className="fwpt-input" value={icmpCode} inputMode="numeric"
                onChange={(e) => setIcmpCode(e.target.value)} />
            </div>
          </>
        )}
        <button className="fwpt-btn" disabled={disabled}>
          {ports ? <Search size={15} /> : <Play size={15} />}
          {ports
            ? (busy ? de.trace.portsRunning : de.trace.portsRun)
            : (busy ? de.trace.running : de.trace.run)}
        </button>
        {!ports && (
          <button
            type="button" className="fwpt-btn-ghost" title={de.trace.reverseHint}
            disabled={disabled} onClick={() => onSubmit(build(true))}
          >
            <ArrowLeftRight size={14} />
            {de.trace.reverse}
          </button>
        )}
      </div>
    </form>
  );
}
