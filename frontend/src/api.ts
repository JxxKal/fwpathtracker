// API-Client (ids-Muster: fetch-Wrapper + Demo-Mode-Gate pro Funktion).
import * as demo from './demo/api';
import { isDemoMode } from './demo/mode';
import type {
  InventorySummary, SamlConfig, SearchHit, Session, SslStatus, SyncStatus,
  TraceHistoryEntry, TraceRequest, TraceResult, UserEntry,
} from './types';

let token: string | null = localStorage.getItem('fwpt-token');

export function setToken(t: string | null): void {
  token = t;
  if (t) localStorage.setItem('fwpt-token', t);
  else localStorage.removeItem('fwpt-token');
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (res.status === 401) {
    setToken(null);
    window.dispatchEvent(new Event('fwpt-logout'));
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch { /* Klartext-Fehler */ }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function login(username: string, password: string): Promise<Session> {
  if (isDemoMode() || (username === 'demo' && password === 'demo')) {
    localStorage.setItem('fwpt-demo', '1');
    return demo.login();
  }
  const r = await request<{ token: string; username: string; role: 'admin' | 'viewer' }>(
    '/api/auth/login',
    { method: 'POST', body: JSON.stringify({ username, password }) },
  );
  setToken(r.token);
  return { token: r.token, username: r.username, role: r.role };
}

// ── Trace ─────────────────────────────────────────────────────────────────────

export async function runTrace(req: TraceRequest): Promise<TraceResult> {
  if (isDemoMode()) return demo.trace(req);
  return request('/api/trace', { method: 'POST', body: JSON.stringify(req) });
}

export async function fetchTraces(): Promise<TraceHistoryEntry[]> {
  if (isDemoMode()) return demo.traces();
  return request('/api/traces');
}

export async function searchEndpoints(q: string): Promise<SearchHit[]> {
  if (isDemoMode()) return demo.search(q);
  return request(`/api/search?q=${encodeURIComponent(q)}`);
}

// ── Settings ──────────────────────────────────────────────────────────────────

export async function getConfig(key: string): Promise<Record<string, unknown>> {
  if (isDemoMode()) return {};
  const r = await request<{ value: Record<string, unknown> }>(`/api/config/${key}`);
  return r.value;
}

export async function patchConfig(
  key: string, value: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (isDemoMode()) return value;
  const r = await request<{ value: Record<string, unknown> }>(`/api/config/${key}`, {
    method: 'PATCH', body: JSON.stringify({ value }),
  });
  return r.value;
}

export async function fmgTest(): Promise<{ ok: boolean; version?: string; adoms: string[] }> {
  if (isDemoMode()) return { ok: true, version: '7.4.5-demo', adoms: ['corp'] };
  return request('/api/fmg/test', { method: 'POST' });
}

export async function fmgSync(): Promise<void> {
  if (isDemoMode()) return;
  await request('/api/fmg/sync', { method: 'POST' });
}

export async function fmgSyncStatus(): Promise<SyncStatus> {
  if (isDemoMode()) return demo.syncStatus();
  return request('/api/fmg/sync/status');
}

export async function inventorySummary(): Promise<InventorySummary> {
  if (isDemoMode()) return demo.inventorySummary();
  return request('/api/fmg/inventory/summary');
}

export async function itopTest(): Promise<{ ok: boolean; organisations: string[] }> {
  if (isDemoMode()) return { ok: true, organisations: ['Demo Org'] };
  return request('/api/itop/test', { method: 'POST' });
}

export async function itopRefresh(): Promise<{ ok: boolean; count: number }> {
  if (isDemoMode()) return { ok: true, count: 42 };
  return request('/api/itop/refresh', { method: 'POST' });
}

// ── Users ─────────────────────────────────────────────────────────────────────

export async function fetchUsers(): Promise<UserEntry[]> {
  if (isDemoMode()) return [{ id: 1, username: 'demo', role: 'admin' }];
  return request('/api/users');
}

export async function createUser(
  username: string, password: string, role: string,
): Promise<void> {
  if (isDemoMode()) return;
  await request('/api/users', {
    method: 'POST', body: JSON.stringify({ username, password, role }),
  });
}

export async function deleteUser(id: number): Promise<void> {
  if (isDemoMode()) return;
  await request(`/api/users/${id}`, { method: 'DELETE' });
}

// ── SAML / SSO ──────────────────────────────────────────────────────────────────

const SAML_DEFAULTS: SamlConfig = {
  enabled: false,
  idp_entity_id: '', idp_sso_url: '', idp_slo_url: '', idp_x509_cert: '',
  sp_entity_id: '', acs_url: '', slo_url: '',
  attribute_username: 'uid', attribute_email: 'email',
  attribute_display_name: 'displayName', default_role: 'viewer',
};

export async function fetchSamlConfig(): Promise<SamlConfig> {
  if (isDemoMode()) return SAML_DEFAULTS;
  const v = await getConfig('saml');
  return { ...SAML_DEFAULTS, ...(v as Partial<SamlConfig>) };
}

export async function saveSamlConfig(cfg: SamlConfig): Promise<SamlConfig> {
  await patchConfig('saml', cfg as unknown as Record<string, unknown>);
  return cfg;
}

// Öffentlich (kein JWT) — steuert den SSO-Button auf der Login-Seite.
export async function samlEnabled(): Promise<{ enabled: boolean; login_url: string }> {
  try {
    const res = await fetch('/api/auth/saml/enabled');
    if (!res.ok) return { enabled: false, login_url: '/api/auth/saml/login' };
    return await res.json();
  } catch {
    return { enabled: false, login_url: '/api/auth/saml/login' };
  }
}

// ── SSL / TLS ───────────────────────────────────────────────────────────────────

export async function fetchSslStatus(): Promise<SslStatus> {
  if (isDemoMode()) return { mode: 'none', active: false };
  return request('/api/ssl/status');
}

export async function sslSelfSigned(
  body: { common_name: string; days: number; country?: string; org?: string },
): Promise<SslStatus> {
  return request('/api/ssl/self-signed', { method: 'POST', body: JSON.stringify(body) });
}

export async function getSslHostname(): Promise<{ hostname: string }> {
  if (isDemoMode()) return { hostname: '' };
  return request('/api/ssl/hostname');
}

export async function setSslHostname(hostname: string): Promise<{ hostname: string }> {
  return request('/api/ssl/hostname', { method: 'POST', body: JSON.stringify({ hostname }) });
}

// Uploads gehen an FormData vorbei am JSON-request-Helper (multipart + Bearer manuell).
async function uploadForm(path: string, fd: FormData): Promise<SslStatus> {
  const res = await fetch(path, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: fd,
  });
  if (res.status === 401) { setToken(null); window.dispatchEvent(new Event('fwpt-logout')); }
  if (!res.ok) {
    let detail = res.statusText;
    try { const b = await res.json(); detail = typeof b.detail === 'string' ? b.detail : JSON.stringify(b.detail); } catch { /* */ }
    throw new ApiError(res.status, detail);
  }
  return res.json();
}

export async function uploadSslCert(cert: File, key: File, ca?: File | null): Promise<SslStatus> {
  const fd = new FormData();
  fd.append('cert', cert);
  fd.append('key', key);
  if (ca) fd.append('ca', ca);
  return uploadForm('/api/ssl/upload', fd);
}

export async function uploadSslPfx(pfx: File, password: string): Promise<SslStatus> {
  const fd = new FormData();
  fd.append('pfx', pfx);
  fd.append('password', password);
  return uploadForm('/api/ssl/upload-pfx', fd);
}
