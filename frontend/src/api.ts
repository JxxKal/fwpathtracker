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

export interface OwnsMatch {
  device: string; vdom: string; interface: string | null;
  vlan: string | number | null; cidr: string; prefixlen: number;
  netmask: string; gateway: string | null; source: string; site_name: string | null;
}
export interface OwnsResult {
  ip: string;
  ingress: { device: string; vdom: string; interface: string } | null;
  matches: OwnsMatch[];
}

// ── Check-Gruppen (Batch-Regressions-Checks) ────────────────────────────────────

export interface CheckItem {
  id?: string; label?: string; src: string; dst: string; protocol: string;
  dst_port?: number | null; src_port?: number | null;
  icmp_type?: number | null; icmp_code?: number | null; expect: 'ALLOW' | 'DENY';
}
export interface CheckGroup { id: string; name: string; checks: CheckItem[]; }
export interface ChecksDoc { groups: CheckGroup[]; }
export interface CheckResult {
  id?: string | null; label?: string | null; src: string; dst: string;
  protocol: string; dst_port: number | null; expect: string;
  actual: string | null; ok: boolean; error: string | null;
  result: TraceResult | null;
}

export async function getChecks(): Promise<ChecksDoc> {
  if (isDemoMode()) {
    return { groups: [{ id: 'demo', name: 'OT-Freigaben', checks: [
      { id: '1', label: 'Admin→DB', src: '10.1.1.10', dst: '10.2.1.30', protocol: 'tcp', dst_port: 443, expect: 'ALLOW' },
      { id: '2', label: 'Legacy→DB (soll blocken)', src: '10.1.1.10', dst: '10.2.9.9', protocol: 'tcp', dst_port: 23, expect: 'DENY' },
    ] }] };
  }
  return request('/api/checks');
}
export async function saveChecks(doc: ChecksDoc): Promise<ChecksDoc> {
  if (isDemoMode()) return doc;
  return request('/api/checks', { method: 'PUT', body: JSON.stringify(doc) });
}
export async function runChecks(checks: CheckItem[]): Promise<{
  results: CheckResult[]; passed: number; total: number; synced_at: string;
}> {
  if (isDemoMode()) {
    const results = checks.map((c) => {
      const r = demo.trace({
        src: c.src, dst: c.dst, protocol: c.protocol,
        dst_port: c.dst_port ?? null, src_port: null, icmp_type: null, icmp_code: null,
      });
      return {
        id: c.id ?? null, label: c.label ?? null, src: c.src, dst: c.dst,
        protocol: c.protocol, dst_port: c.dst_port ?? null, expect: c.expect,
        actual: r.verdict, ok: r.verdict === c.expect, error: null, result: r,
      };
    });
    return { results, passed: results.filter((x) => x.ok).length, total: results.length, synced_at: new Date().toISOString() };
  }
  return request('/api/checks/run', { method: 'POST', body: JSON.stringify({ checks }) });
}

export interface SiteSupernet { name: string; cidr: string; }
export async function siteSupernets(): Promise<{ sites: SiteSupernet[] }> {
  if (isDemoMode()) {
    return { sites: [
      { name: 'Holstein', cidr: '10.180.0.0/20' }, { name: 'Gas Nord', cidr: '10.180.16.0/20' },
      { name: 'Hamburg', cidr: '10.180.32.0/20' }, { name: 'Oel West', cidr: '10.180.48.0/21' },
      { name: 'Oel Nord', cidr: '10.180.56.0/21' },
    ] };
  }
  return request('/api/itop/site-supernets');
}

export interface FreeSubnetResult {
  supernet: string; prefix: number; allocated: number; subnets_total: number;
  free: string[]; capped: boolean;
}
export async function freeSubnets(supernet: string, prefix: number): Promise<FreeSubnetResult> {
  if (isDemoMode()) {
    return {
      supernet, prefix, allocated: 6, subnets_total: 128,
      free: [`10.180.5.0/${prefix}`, `10.180.6.0/${prefix}`, `10.180.11.0/${prefix}`],
      capped: false,
    };
  }
  return request('/api/itop/free-subnets', { method: 'POST', body: JSON.stringify({ supernet, prefix }) });
}

export async function inventoryOwns(ip: string): Promise<OwnsResult> {
  if (isDemoMode()) {
    return {
      ip, ingress: { device: 'fw-a', vdom: 'root', interface: 'lan1' },
      matches: [
        { device: 'fw-a', vdom: 'root', interface: 'lan1', vlan: 42, cidr: '10.1.1.0/24', prefixlen: 24, netmask: '255.255.255.0', gateway: '10.1.1.1', source: 'connected', site_name: null },
      ],
    };
  }
  return request(`/api/fmg/inventory/owns/${encodeURIComponent(ip)}`);
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
