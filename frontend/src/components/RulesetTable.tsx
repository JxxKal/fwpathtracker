import { de } from '../i18n/de';
import type { Candidate } from '../types';

export default function RulesetTable({ candidates, wide = false }: {
  candidates: Candidate[];
  wide?: boolean;
}) {
  if (candidates.length === 0) {
    return <p className="p-2 text-xs text-slate-500">—</p>;
  }
  const cell = wide ? 'px-3 py-1.5 whitespace-nowrap' : 'px-2 py-1';
  return (
    <div className={wide ? 'max-h-[55vh] overflow-auto' : 'max-h-80 overflow-auto'}>
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-slate-900 text-slate-500">
          <tr>
            <th className={`${cell} font-medium`}>ID</th>
            <th className={`${cell} font-medium`}>Name</th>
            <th className={`${cell} font-medium`}>Aktion</th>
            <th className={`${cell} font-medium`}>Quelle</th>
            <th className={`${cell} font-medium`}>Ziel</th>
            <th className={`${cell} font-medium`}>Service</th>
          </tr>
        </thead>
        <tbody>
          {candidates.map((c) => (
            <tr
              key={c.policyid ?? c.name}
              className={
                c.hit
                  ? 'bg-cyan-950/60 text-cyan-200 ring-1 ring-inset ring-cyan-700'
                  : 'text-slate-400'
              }
              title={c.hit ? de.hop.matched : undefined}
            >
              <td className={`${cell} font-mono`}>{c.policyid}</td>
              <td className={wide ? cell : `max-w-32 truncate ${cell}`}>{c.name}</td>
              <td className={`${cell} font-medium ${c.action === 'accept' ? 'text-emerald-400' : 'text-red-400'}`}>
                {c.action}
              </td>
              <td className={wide ? cell : `max-w-28 truncate ${cell}`}>{c.srcaddr.join(', ')}</td>
              <td className={wide ? cell : `max-w-28 truncate ${cell}`}>{c.dstaddr.join(', ')}</td>
              <td className={wide ? cell : `max-w-24 truncate ${cell}`}>{c.service.join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
