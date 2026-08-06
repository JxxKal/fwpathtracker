// Teilbare Links auf eine Check-Gruppe bzw. einen einzelnen Check —
// gedacht zum Verschicken per Teams/Mail an Kollegen. App.tsx liest die
// Parameter beim Start und springt in die Checks-Ansicht.

export interface CheckDeepLink { groupId: string; checkId: string | null; }

export function buildCheckLink(groupId: string, checkId?: string | null): string {
  const url = new URL(window.location.href);
  url.search = '';
  url.hash = '';
  url.searchParams.set('tab', 'checks');
  url.searchParams.set('group', groupId);
  if (checkId) url.searchParams.set('check', checkId);
  return url.toString();
}

export function readCheckLink(search: string = window.location.search): CheckDeepLink | null {
  const p = new URLSearchParams(search);
  const groupId = p.get('group');
  if (!groupId) return null;
  return { groupId, checkId: p.get('check') };
}

/** Clipboard-Copy mit Fallback — navigator.clipboard gibt es nur im Secure Context
 *  (HTTPS/localhost); ohne Zertifikat läuft der Tracker auch mal auf http. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fällt unten auf execCommand zurück */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
