import { de } from '../i18n/de';

// Zone zuerst, physisches Interface nur als Beiwerk: Policies im FortiManager
// referenzieren Zonen bzw. normalisierte Interfaces, nicht port3 oder vlan815.
// Wer nach der Regel sucht, braucht den Zonennamen — das Interface steht
// gedämpft dahinter, falls es davon abweicht.
export function IntfLabel({ intf, zone }: { intf: string | null; zone?: string | null }) {
  if (!intf) return <span>?</span>;
  if (!zone || zone === intf) return <span title={de.hop.intfTitle}>{intf}</span>;
  return (
    <span title={`${de.hop.zoneTitle}: ${zone} · ${de.hop.intfTitle}: ${intf}`}>
      {zone}<span className="ml-1 text-slate-600">({intf})</span>
    </span>
  );
}

export function IntfPair({ srcintf, srcZone, egress, egressZone }: {
  srcintf: string; srcZone?: string | null; egress: string | null; egressZone?: string | null;
}) {
  return (
    <>
      <IntfLabel intf={srcintf} zone={srcZone} /> → <IntfLabel intf={egress} zone={egressZone} />
    </>
  );
}
