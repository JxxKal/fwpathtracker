import { Calculator } from 'lucide-react';
import { useMemo, useState } from 'react';
import { de } from '../i18n/de';

function ipToInt(s: string): number | null {
  const p = s.trim().split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) {
    if (!/^\d+$/.test(o)) return null;
    const v = Number(o);
    if (v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}
function intToIp(n: number): string {
  return [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.');
}
function maskToPrefix(m: number): number | null {
  let prefix = 0;
  let seenZero = false;
  for (let i = 31; i >= 0; i--) {
    if ((m >>> i) & 1) { if (seenZero) return null; prefix++; } else seenZero = true;
  }
  return prefix;
}
const prefixToMask = (p: number) => (p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);

interface Calc {
  address: string; prefix: number; netmask: string; wildcard: string;
  network: string; broadcast: string; hostMin: string; hostMax: string; hosts: string;
}

function calc(raw: string): Calc | null {
  const s = raw.trim();
  if (!s) return null;
  let ipPart = s; let maskPart = '';
  if (s.includes('/')) { [ipPart, maskPart] = s.split('/'); }
  else if (/\s/.test(s)) { const parts = s.split(/\s+/); ipPart = parts[0]; maskPart = parts[1] ?? ''; }

  const ip = ipToInt(ipPart);
  if (ip === null) return null;

  let prefix: number;
  if (!maskPart.trim()) prefix = 32;
  else if (/^\d+$/.test(maskPart.trim())) {
    prefix = Number(maskPart.trim());
    if (prefix < 0 || prefix > 32) return null;
  } else {
    const m = ipToInt(maskPart);
    if (m === null) return null;
    const p = maskToPrefix(m);
    if (p === null) return null;
    prefix = p;
  }

  const mask = prefixToMask(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  let hostMin: number; let hostMax: number; let hosts: string;
  if (prefix >= 32) { hostMin = network; hostMax = network; hosts = '1'; }
  else if (prefix === 31) { hostMin = network; hostMax = broadcast; hosts = '2'; }
  else { hostMin = (network + 1) >>> 0; hostMax = (broadcast - 1) >>> 0; hosts = String(2 ** (32 - prefix) - 2); }

  return {
    address: intToIp(ip), prefix, netmask: intToIp(mask), wildcard: intToIp(~mask >>> 0),
    network: intToIp(network), broadcast: intToIp(broadcast),
    hostMin: intToIp(hostMin), hostMax: intToIp(hostMax), hosts,
  };
}

function Row({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="w-28 shrink-0 text-xs text-slate-500">{label}</span>
      <span className="font-mono text-sm text-slate-200">{value}</span>
      {sub && <span className="text-xs text-slate-500">{sub}</span>}
    </div>
  );
}

export default function IpCalc() {
  const [input, setInput] = useState('');
  const res = useMemo(() => calc(input), [input]);
  const show = input.trim().length > 0;

  return (
    <div className="fwpt-card space-y-3">
      <div>
        <h2 className="flex items-center gap-2 font-medium text-slate-100">
          <Calculator size={16} className="text-cyan-400" /> {de.ipcalc.title}
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">{de.ipcalc.hint}</p>
      </div>
      <input className="fwpt-input font-mono" value={input}
        onChange={(e) => setInput(e.target.value)} placeholder={de.ipcalc.placeholder} />

      {show && !res && <p className="text-sm text-amber-400">{de.ipcalc.invalid}</p>}

      {res && (
        <div className="grid gap-1.5 sm:grid-cols-2">
          <Row label="Adresse" value={res.address} sub={`/${res.prefix}`} />
          <Row label="Netzmaske" value={res.netmask} sub={`= /${res.prefix}`} />
          <Row label="Netz" value={`${res.network}/${res.prefix}`} />
          <Row label="Wildcard" value={res.wildcard} />
          <Row label="Host-Min" value={res.hostMin} sub="übl. Gateway" />
          <Row label="Host-Max" value={res.hostMax} />
          <Row label="Broadcast" value={res.broadcast} />
          <Row label="Hosts" value={res.hosts} />
        </div>
      )}
    </div>
  );
}
