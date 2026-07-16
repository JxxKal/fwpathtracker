import { ArrowLeftRight, Boxes, Globe, Monitor, Wrench, type LucideIcon } from 'lucide-react';
import type { Candidate } from '../types';

const ICONS: Record<string, LucideIcon> = {
  interface: ArrowLeftRight, address: Monitor, addrgrp: Boxes,
  service: Wrench, servicegrp: Boxes, vip: Globe, unknown: Monitor,
};
const COLORS: Record<string, string> = {
  interface: 'text-cyan-400', address: 'text-slate-400', addrgrp: 'text-amber-400',
  service: 'text-emerald-400', servicegrp: 'text-amber-400', vip: 'text-purple-400',
  unknown: 'text-slate-500',
};

function ObjRow({ name, type }: { name: string; type: string }) {
  const Icon = ICONS[type] ?? Monitor;
  return (
    <div className="flex items-center gap-1.5">
      <Icon size={13} className={`shrink-0 ${COLORS[type] ?? 'text-slate-400'}`} />
      <span className="truncate font-mono text-slate-200" title={name}>{name}</span>
    </div>
  );
}

function Col({ label, names, types, def }: {
  label: string; names: string[]; types?: Record<string, string>; def: string;
}) {
  return (
    <div className="min-w-0">
      <p className="mb-1 text-[10px] font-medium uppercase tracking-wide text-slate-500">{label}</p>
      {names.length === 0 ? <span className="text-xs text-slate-600">—</span> : (
        <div className="space-y-1">
          {names.map((n) => <ObjRow key={n} name={n} type={types?.[n] || def} />)}
        </div>
      )}
    </div>
  );
}

// Treffer-Regel im FortiManager-Stil: jedes Objekt einzeln mit Typ-Icon, in Spalten.
export default function PolicyCard({ policy }: { policy: Candidate }) {
  const t = policy.obj_types;
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/40 p-3">
      <div className="mb-3 flex items-center gap-2 border-b border-slate-800/70 pb-2">
        <span className="font-mono text-sm text-cyan-300">
          #{policy.policyid} {policy.name}
        </span>
        <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${
          policy.action === 'accept' ? 'bg-emerald-900/60 text-emerald-300' : 'bg-red-900/60 text-red-300'
        }`}>{policy.action}</span>
      </div>
      <div className="grid gap-4 text-xs sm:grid-cols-2 lg:grid-cols-5">
        <Col label="Quell-Interface" names={policy.srcintf} def="interface" />
        <Col label="Quelle" names={policy.srcaddr} types={t} def="address" />
        <Col label="Ziel-Interface" names={policy.dstintf} def="interface" />
        <Col label="Ziel" names={policy.dstaddr} types={t} def="address" />
        <Col label="Dienst" names={policy.service} types={t} def="service" />
      </div>
    </div>
  );
}
