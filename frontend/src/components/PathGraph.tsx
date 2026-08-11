import { Background, Controls, Edge, Node, ReactFlow, ReactFlowProvider, useReactFlow } from '@xyflow/react';
import { useEffect, useMemo } from 'react';
import { de } from '../i18n/de';
import { useSwitchports } from '../switchports';
import type { Hop, TraceResult } from '../types';
import FirewallNode from './nodes/FirewallNode';
import HostNode from './nodes/HostNode';

const nodeTypes = { host: HostNode, firewall: FirewallNode } as never;

const edgeColor: Record<string, string> = {
  ALLOW: '#34d399',
  DENY: '#f87171',
  UNKNOWN: '#fbbf24',
};

interface Props {
  result: TraceResult;
  onSelect: (hop: Hop) => void;
  selectedIndex: number | null;
}

// Linearer Pfad → manueller Horizontal-Layouter (kein dagre/elk nötig)
const HOST_W = 208;
const FW_W = 320;
const GAP = 90;

function PathGraphInner({ result, onSelect, selectedIndex }: Props) {
  // Endet der Pfad im Internet, gibt es kein Zielgerät, dessen Switchport man
  // suchen könnte — dann nur die Quelle nachschlagen.
  const lastEgress = result.hops[result.hops.length - 1]?.egress_class;
  const dstIsInternet = lastEgress === 'DEFAULT';
  const switchports = useSwitchports([
    result.src.ip,
    dstIsInternet ? null : result.dst.ip,
  ]);

  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    let x = 0;

    nodes.push({
      id: 'src', type: 'host', position: { x, y: 40 },
      data: {
        ip: result.src.ip, names: result.src.names, role: 'src',
        switchport: switchports[result.src.ip],
      },
    });
    x += HOST_W + GAP;

    result.hops.forEach((hop, i) => {
      nodes.push({
        id: `hop-${i}`, type: 'firewall', position: { x, y: 0 },
        data: { hop, onSelect, selected: selectedIndex === i },
      });
      x += FW_W + GAP;
    });

    nodes.push({
      id: 'dst', type: 'host', position: { x, y: 40 },
      data: dstIsInternet
        ? { ip: result.dst.ip, names: [{ name: de.common.internet, provenance: 'ip' }], role: 'internet' }
        : {
            ip: result.dst.ip, names: result.dst.names, role: 'dst',
            switchport: switchports[result.dst.ip],
          },
    });

    const chain = ['src', ...result.hops.map((_, i) => `hop-${i}`), 'dst'];
    for (let i = 0; i < chain.length - 1; i++) {
      const hop = result.hops[Math.min(i, result.hops.length - 1)];
      const verdict = i === 0 ? result.hops[0]?.verdict ?? 'UNKNOWN' : hop.verdict;
      const label = i < result.hops.length
        ? undefined
        : de.egress[result.hops[result.hops.length - 1].egress_class];
      // Label der Kante NACH einem Hop = dessen Egress-Klasse
      const outHopIdx = i - 1;
      const egressLabel = outHopIdx >= 0 && outHopIdx < result.hops.length
        ? de.egress[result.hops[outHopIdx].egress_class]
        : label;
      const dimmed = hop?.after_deny ?? false;
      edges.push({
        id: `e-${i}`,
        source: chain[i],
        target: chain[i + 1],
        animated: verdict === 'ALLOW' && !dimmed,
        label: i === 0 ? undefined : egressLabel,
        labelStyle: { fill: '#94a3b8', fontSize: 10 },
        labelBgStyle: { fill: '#0f172a', fillOpacity: 0.9 },
        style: {
          stroke: dimmed ? '#475569' : edgeColor[verdict] ?? '#64748b',
          strokeWidth: 2,
          opacity: dimmed ? 0.4 : 1,
        },
      });
    }
    return { nodes, edges };
  }, [result, onSelect, selectedIndex, switchports, dstIsInternet]);

  // fitView als Prop greift nur beim ersten Mount. Bei jedem neuen Trace (und
  // nach dem Auf-/Zuklappen der Kandidaten-Regeln) die Ansicht neu einpassen,
  // sonst bleibt der Graph aus dem Sichtfeld gescrollt.
  const { fitView } = useReactFlow();
  useEffect(() => {
    const raf = requestAnimationFrame(() =>
      fitView({ padding: 0.12, duration: 200, maxZoom: 1.5 }));
    return () => cancelAnimationFrame(raf);
  }, [result, fitView, switchports]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.12, maxZoom: 1.5 }}
      minZoom={0.2}
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      colorMode="dark"
    >
      <Background color="#1e293b" gap={24} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

export default function PathGraph(props: Props) {
  return (
    <div className="h-[520px] rounded-lg border border-slate-800 bg-slate-950">
      <ReactFlowProvider>
        <PathGraphInner {...props} />
      </ReactFlowProvider>
    </div>
  );
}
