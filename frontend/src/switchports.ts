import { useEffect, useState } from 'react';
import { locateHost, type LocateResult } from './api';

export interface SwitchportState {
  loading: boolean;
  result: LocateResult | null;
}

const EMPTY: SwitchportState = { loading: false, result: null };

/**
 * Switchports der Trace-Endpunkte nachladen.
 *
 * Bewusst NACH dem Trace und nicht als Teil davon: die Pfadanalyse soll nicht
 * auf LibreNMS warten und auch dann laufen, wenn dort nichts konfiguriert ist.
 * Fehler werden geschluckt — ein fehlender Switchport ist eine fehlende
 * Zusatzinformation, kein Trace-Problem. Die Ergebnisse trudeln nach und der
 * Graph ergänzt sich, statt den Trace aufzuhalten.
 *
 * Serverseitig sind die Antworten kurz gecacht, ein Re-Trace derselben Endpunkte
 * kostet also nichts.
 */
export function useSwitchports(ips: (string | null | undefined)[]): Record<string, SwitchportState> {
  const [state, setState] = useState<Record<string, SwitchportState>>({});
  // Abhängigkeit als String, damit ein neu gebautes Array kein Refetch auslöst.
  const key = ips.filter(Boolean).join('|');

  useEffect(() => {
    const wanted = key ? key.split('|') : [];
    if (!wanted.length) {
      setState({});
      return;
    }
    let cancelled = false;
    setState(Object.fromEntries(wanted.map((ip) => [ip, { loading: true, result: null }])));

    Promise.all(
      wanted.map(async (ip) => {
        try {
          return [ip, { loading: false, result: await locateHost(ip) }] as const;
        } catch {
          return [ip, EMPTY] as const;    // LibreNMS nicht konfiguriert o.ä.
        }
      }),
    ).then((entries) => {
      if (!cancelled) setState(Object.fromEntries(entries));
    });

    return () => { cancelled = true; };
  }, [key]);

  return state;
}
