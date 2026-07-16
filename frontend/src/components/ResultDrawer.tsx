import { Check, Copy, X } from 'lucide-react';
import { useState } from 'react';
import { de } from '../i18n/de';
import type { Hop, TraceResult } from '../types';

interface Props {
  result: TraceResult;
  onClose: () => void;
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-slate-800 hover:text-slate-200"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch { /* Clipboard nicht verfügbar */ }
      }}
    >
      {done ? <Check size={11} /> : <Copy size={11} />}
      {done ? de.drawer.copied : de.drawer.copy}
    </button>
  );
}

/** Ein Lookup-Block (Router oder Policy): Proxy-Request + Response, jeweils kopierbar. */
function LookupBlock({ title, source, proxy, response }: {
  title: string; source?: string | null; proxy: unknown; response?: unknown;
}) {
  const proxyStr = JSON.stringify(proxy, null, 2);
  const resource = (proxy as { resource?: string } | null)?.resource;
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/60 p-2">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wide text-slate-400">
          {title}{source ? ` · ${source}` : ''}
        </span>
        <CopyBtn text={proxyStr} />
      </div>
      {resource && (
        <pre className="mb-1 overflow-x-auto rounded bg-slate-950 p-2 text-[11px] text-cyan-300">{resource}</pre>
      )}
      <details>
        <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
          {de.drawer.requestJson}
        </summary>
        <pre className="mt-1 max-h-40 overflow-auto rounded bg-slate-950 p-2 text-[11px] text-slate-400">{proxyStr}</pre>
      </details>
      {response != null && (
        <details>
          <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
            {de.drawer.responseJson}
          </summary>
          <pre className="mt-1 max-h-56 overflow-auto rounded bg-slate-950 p-2 text-[11px] text-slate-400">{JSON.stringify(response, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

function HopBlock({ hop }: { hop: Hop }) {
  const curated = JSON.stringify({
    srcintf: hop.srcintf, src_zone: hop.src_zone,
    egress: hop.egress, egress_zone: hop.egress_zone,
    egress_class: hop.egress_class, route: hop.route,
    verdict: hop.verdict, policy_id: hop.matched_policy?.policyid ?? null,
  }, null, 2);
  const rl = hop.debug?.router_lookup;
  const pl = hop.debug?.policy_lookup;
  return (
    <section className="mb-4 space-y-2">
      <h3 className="text-xs font-medium uppercase text-slate-500">
        Hop {hop.index + 1}: {hop.device}/{hop.vdom}
      </h3>
      <pre className="overflow-x-auto rounded-md bg-slate-950 p-2 text-xs text-slate-300">{curated}</pre>
      {rl && (
        <LookupBlock title={de.drawer.routerLookup} source={rl.source}
          proxy={rl.proxy} response={rl.response} />
      )}
      {pl && (
        <LookupBlock title={de.drawer.policyLookup}
          proxy={pl.proxy} response={pl.response} />
      )}
    </section>
  );
}

export default function ResultDrawer({ result, onClose }: Props) {
  return (
    <div className="fixed inset-y-0 right-0 z-30 w-[32rem] max-w-full overflow-y-auto border-l border-slate-800 bg-slate-900 p-4 shadow-2xl">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="font-medium text-slate-100">{de.drawer.title}</h2>
        <button type="button" className="text-slate-500 hover:text-slate-300" onClick={onClose}>
          <X size={18} />
        </button>
      </div>

      <section className="mb-4">
        <h3 className="mb-1 text-xs font-medium uppercase text-slate-500">{de.drawer.lookupParams}</h3>
        <pre className="overflow-x-auto rounded-md bg-slate-950 p-2 text-xs text-slate-300">
{JSON.stringify({
  src: result.src.ip, dst: result.dst.ip, protocol: result.protocol,
  dst_port: result.dst_port, src_port: result.src_port,
  icmp_type: result.icmp_type, icmp_code: result.icmp_code,
}, null, 2)}
        </pre>
      </section>

      {result.hops.map((hop) => <HopBlock key={hop.index} hop={hop} />)}

      {result.warnings.length > 0 && (
        <section className="mb-4">
          <h3 className="mb-1 text-xs font-medium uppercase text-slate-500">{de.drawer.warnings}</h3>
          <ul className="space-y-1 text-xs text-amber-400">
            {result.warnings.map((w) => <li key={w}>{w}</li>)}
          </ul>
        </section>
      )}

      <p className="text-xs text-slate-500">
        {de.drawer.duration}: {result.duration_ms} ms
        {result.inventory_synced_at && (
          <> · {de.drawer.syncedAt} {new Date(result.inventory_synced_at).toLocaleTimeString('de-DE')}</>
        )}
      </p>
    </div>
  );
}
