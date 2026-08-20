// API-Client (ids-Muster: fetch-Wrapper + Demo-Mode-Gate pro Funktion).
import * as demo from './demo/api';
import { isDemoMode } from './demo/mode';
import type {
  InventorySummary, PortTraceResult, SamlConfig, SearchHit, Session, SslStatus,
  SyncStatus, TraceHistoryEntry, TraceRequest, TraceResult, UserEntry,
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

export async function portTrace(src: string, dst: string): Promise<PortTraceResult> {
  if (isDemoMode()) return demo.portTrace(src, dst);
  return request('/api/trace/ports', {
    method: 'POST', body: JSON.stringify({ src, dst }),
  });
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
  /** Namen, unter denen die IP bekannt ist — bei Eingabe eines Objektnamens
   *  belegt das, worauf er aufgelöst wurde. */
  names?: string[];
  ingress: { device: string; vdom: string; interface: string } | null;
  matches: OwnsMatch[];
}

// ── Check-Gruppen (Batch-Regressions-Checks) ────────────────────────────────────

export interface CheckLastRun {
  at: string; actual: string | null; ok: boolean; error: string | null;
}
export interface CheckItem {
  id?: string; label?: string; src: string; dst: string; protocol: string;
  dst_port?: number | null; src_port?: number | null;
  icmp_type?: number | null; icmp_code?: number | null; expect: 'ALLOW' | 'DENY';
  done?: boolean; done_at?: string | null; done_by?: string | null;
  last_run?: CheckLastRun | null;
}
export interface CheckGroup { id: string; name: string; checks: CheckItem[]; }
export interface ChecksDoc { groups: CheckGroup[]; }
export interface CheckResult {
  id?: string | null; label?: string | null; src: string; dst: string;
  protocol: string; dst_port: number | null; expect: string;
  actual: string | null; ok: boolean; error: string | null;
  result: TraceResult | null;
}

// Demo-Modus hält die Gruppen im Speicher, damit Erledigt-Status & Läufe
// innerhalb der Sitzung genauso stehen bleiben wie gegen die echte API.
let demoChecks: ChecksDoc | null = null;
function demoDoc(): ChecksDoc {
  if (!demoChecks) {
    demoChecks = { groups: [{ id: 'demo', name: 'OT-Freigaben', checks: [
      { id: '1', label: 'Admin→DB', src: '10.1.1.10', dst: '10.2.1.30', protocol: 'tcp', dst_port: 443, expect: 'ALLOW' },
      { id: '2', label: 'Legacy→DB (soll blocken)', src: '10.1.1.10', dst: '10.2.9.9', protocol: 'tcp', dst_port: 23, expect: 'DENY' },
    ] }] };
  }
  return demoChecks;
}

export async function getChecks(): Promise<ChecksDoc> {
  if (isDemoMode()) return demoDoc();
  return request('/api/checks');
}
export async function saveChecks(doc: ChecksDoc): Promise<ChecksDoc> {
  if (isDemoMode()) { demoChecks = doc; return doc; }
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

export interface CheckStatusUpdate {
  check_id: string; done?: boolean | null; record_run?: boolean;
  actual?: string | null; ok?: boolean | null; error?: string | null;
}
// Erledigt-Status / Lauf-Ergebnis fortschreiben; liefert das komplette Dokument zurück.
export async function updateCheckStatus(
  groupId: string, updates: CheckStatusUpdate[],
): Promise<ChecksDoc> {
  if (isDemoMode()) {
    const doc = demoDoc();
    const now = new Date().toISOString();
    const g = doc.groups.find((x) => x.id === groupId);
    for (const u of updates) {
      const c = g?.checks.find((x) => x.id === u.check_id);
      if (!c) continue;
      if (u.record_run) {
        c.last_run = { at: now, actual: u.actual ?? null, ok: !!u.ok, error: u.error ?? null };
        if (u.ok && !c.done) { c.done = true; c.done_at = now; c.done_by = 'demo'; }
      }
      if (u.done === true) {
        c.done = true;
        if (!c.done_at) { c.done_at = now; c.done_by = 'demo'; }
      } else if (u.done === false) { c.done = false; c.done_at = null; c.done_by = null; }
    }
    return doc;
  }
  return request('/api/checks/status', {
    method: 'POST', body: JSON.stringify({ group_id: groupId, updates }),
  });
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

export async function inventoryOwns(q: string): Promise<OwnsResult> {
  if (isDemoMode()) {
    return {
      ip: q, names: ['WD-OT-L3-SVO3230'],
      ingress: { device: 'fw-a', vdom: 'root', interface: 'lan1' },
      matches: [
        { device: 'fw-a', vdom: 'root', interface: 'lan1', vlan: 42, cidr: '10.1.1.0/24', prefixlen: 24, netmask: '255.255.255.0', gateway: '10.1.1.1', source: 'connected', site_name: null },
      ],
    };
  }
  // Query-Parameter statt Pfadsegment: FMG-Objektnamen dürfen Schrägstriche und
  // Leerzeichen enthalten ('NET-10.1.0.0/16').
  return request(`/api/fmg/inventory/owns?q=${encodeURIComponent(q)}`);
}

export async function itopTest(): Promise<{ ok: boolean; organisations: string[] }> {
  if (isDemoMode()) return { ok: true, organisations: ['Demo Org'] };
  return request('/api/itop/test', { method: 'POST' });
}

export async function itopRefresh(): Promise<{ ok: boolean; count: number }> {
  if (isDemoMode()) return { ok: true, count: 42 };
  return request('/api/itop/refresh', { method: 'POST' });
}

// ── LibreNMS / Switchport-Suche ────────────────────────────────────────────────

export type PortKind = 'access' | 'edge' | 'trunk' | 'uplink' | 'unknown';
export type MatchReason = 'lldp_peer' | 'description' | null;

export interface LocateCandidate {
  device_id: number | string;
  hostname: string | null;
  sys_name: string | null;
  port_id: number;
  if_name: string | null;
  if_alias: string | null;
  if_descr: string | null;
  oper_status: string | null;
  vlan_id: number | null;
  mac_count: number;
  port_kind: PortKind;
  match_reason: MatchReason;
  match_detail: string | null;
  has_neighbor: boolean;
  neighbor: string | null;
  neighbor_monitored: boolean;
  updated_at: string | null;
  age_s: number | null;
  age_bucket: number;
  stale: boolean;
}

export interface LocateUplink {
  local_port_id: number | null;
  local_port: string | null;
  local_alias: string | null;
  remote_hostname: string | null;
  remote_port: string | null;
  remote_platform: string | null;
  protocol: string | null;
}

export interface LocateSelfDevice {
  device_id: number;
  hostname: string | null;
  sys_name: string | null;
  os: string | null;
  hardware: string | null;
  uplinks: LocateUplink[];
}

export interface LocateArp {
  provenance: 'fortigate' | 'librenms';
  device: string | null;
  vdom: string | null;
  interface: string | null;
}

export interface LocateResult {
  ip: string;
  mac: string | null;
  mac_readable: string | null;
  arp: LocateArp | null;
  best: LocateCandidate | null;
  candidates: LocateCandidate[];
  confidence: 'high' | 'medium' | 'low' | 'none';
  self_device: LocateSelfDevice | null;
  aliases: string[];
  warnings: string[];
}

const demoCandidates: LocateCandidate[] = [
  {
    device_id: 169, hostname: 'moxa-iks-01', sys_name: 'bpvo049', port_id: 3701,
    if_name: 'Port 5', if_alias: 'Anlage 3', if_descr: 'Port 5', oper_status: 'up',
    vlan_id: 0, mac_count: 3, port_kind: 'access',
    match_reason: null, match_detail: null, has_neighbor: false,
    neighbor: null, neighbor_monitored: false,
    updated_at: '2026-08-10 14:43:05', age_s: 240, age_bucket: 0, stale: false,
  },
  {
    device_id: 169, hostname: 'moxa-iks-01', sys_name: 'bpvo049', port_id: 3789,
    if_name: 'Port 23', if_alias: 'Ring A', if_descr: 'Port 23', oper_status: 'up',
    vlan_id: 0, mac_count: 182, port_kind: 'trunk',
    match_reason: null, match_detail: null, has_neighbor: false,
    neighbor: null, neighbor_monitored: false,
    updated_at: '2026-08-10 14:43:05', age_s: 240, age_bucket: 0, stale: false,
  },
  {
    device_id: 42, hostname: 'hpe-core-01', sys_name: 'core-01', port_id: 9001,
    if_name: 'Gi1/0/1', if_alias: 'Uplink MOXA', if_descr: 'GigabitEthernet1/0/1',
    oper_status: 'up', vlan_id: 7, mac_count: 412, port_kind: 'uplink',
    match_reason: null, match_detail: null, has_neighbor: true, neighbor: 'moxa-iks-01 / Port 23', neighbor_monitored: true,
    updated_at: '2026-08-10 14:41:12', age_s: 353, age_bucket: 0, stale: false,
  },
];

export async function locateHost(q: string): Promise<LocateResult> {
  if (isDemoMode()) {
    return {
      ip: q, mac: '000c2911891a', mac_readable: '00:0c:29:11:89:1a',
      arp: { provenance: 'fortigate', device: 'fw-a', vdom: 'root', interface: 'lan1' },
      best: demoCandidates[0], candidates: demoCandidates,
      confidence: 'high', self_device: null, aliases: [], warnings: [],
    };
  }
  return request(`/api/locate?q=${encodeURIComponent(q)}`);
}

// ── Netzwerkport-Check (VLAN-Sicht eines Hosts) ──────────────────────────────

export interface VlanRef { number: number; name: string | null; device_id?: number }

export interface PortVlans { untagged: number[]; tagged: number[] }

export interface HostPortFinding extends LocateCandidate {
  vlan: VlanRef | null;
  port_vlans: PortVlans | null;
  best: boolean;
}

export interface L3Interface {
  device: string; vdom: string; interface: string;
  vlan: number | null; alias: string | null; description: string | null;
  zone: string; ip: string | null; network: string | null;
  secondary_networks: string[]; enabled: boolean; adom: string | null;
  prefix_source: string; matched_network: string;
}

export interface HostDevicePort {
  port_id: number; if_name: string | null; if_alias: string | null;
  oper_status: string | null; admin_status: string | null;
  vlans_observed: number[]; mac_count: number;
}

export interface HostPortsResult {
  ip: string;
  names: string[];
  mac: string | null;
  mac_readable: string | null;
  arp: LocateResult['arp'];
  confidence: LocateResult['confidence'];
  findings: HostPortFinding[];
  device: (LocateSelfDevice & {
    ports: HostDevicePort[]; vlans: { number: number; name: string | null }[];
  }) | null;
  l3: L3Interface[];
  vlan_summary: { vlan: number; name: string | null; where: string[] }[];
  warnings: string[];
}

export async function hostPorts(q: string): Promise<HostPortsResult> {
  if (isDemoMode()) {
    return {
      ip: q, names: ['BOCKS2'], mac: '000c2911891a', mac_readable: '00:0c:29:11:89:1a',
      arp: { provenance: 'fortigate', device: 'fw-a', vdom: 'root', interface: 'lan1' },
      confidence: 'high',
      findings: [
        { ...demoCandidates[0], vlan: { number: 44, name: 'OT-PLT-Bockstedt' },
          port_vlans: { untagged: [44], tagged: [] }, best: true },
        { ...demoCandidates[2], vlan: { number: 44, name: 'OT-PLT-Bockstedt' },
          port_vlans: { untagged: [1], tagged: [44, 90] }, best: false },
      ],
      device: null,
      l3: [{
        device: 'fw-a', vdom: 'root', interface: 'PLT', vlan: 44,
        alias: 'OT PLT Bockstedt', description: null, zone: 'inside-a',
        ip: '10.124.44.1/24', network: '10.124.44.0/24', secondary_networks: [],
        enabled: true, adom: 'corp', prefix_source: 'connected',
        matched_network: '10.124.44.0/24',
      }],
      vlan_summary: [{ vlan: 44, name: 'OT-PLT-Bockstedt',
        where: ['moxa-iks-01 / Port 5', 'hpe-core-01 / Gi1/0/1', 'fw-a/root · PLT'] }],
      warnings: [],
    };
  }
  return request(`/api/host-ports?q=${encodeURIComponent(q)}`);
}

// ── Globale VLAN-Übersicht ───────────────────────────────────────────────────

export interface VlanRow {
  vlan: number;
  names: string[];
  networks: string[];
  switches: { device_id: number; hostname: string | null; name: string | null;
              domain?: string | null }[];
  switch_count: number;
  firewall_interfaces: L3Interface[];
  sources: ('librenms' | 'fmg')[];
}

export interface VlanStats {
  librenms_rows: number;
  librenms_skipped: number;
  /** Geräte, die tatsächlich VLANs geliefert haben … */
  librenms_devices: number;
  /** … gegenüber allen, die LibreNMS überwacht. Fehlt ein VLAN, ist das die
   *  erste Frage: hat sein Switch überhaupt VLAN-Daten geliefert? */
  librenms_devices_known: number;
  contributing_devices: string[];
  fmg_interfaces: number;
}

export interface VlanOverview {
  vlans: VlanRow[];
  free: [number, number][];
  used_count: number;
  free_count: number;
  range: [number, number];
  sources: { librenms: boolean; fmg: boolean };
  stats: VlanStats;
  synced_at: string | null;
  warnings: string[];
}

export async function vlanOverview(): Promise<VlanOverview> {
  if (isDemoMode()) {
    const fw = (n: number, name: string, net: string): L3Interface => ({
      device: 'fw-a', vdom: 'root', interface: name, vlan: n, alias: name,
      description: null, zone: 'inside-a', ip: null, network: net,
      secondary_networks: [], enabled: true, adom: 'corp',
      prefix_source: 'connected', matched_network: net,
    });
    return {
      vlans: [
        { vlan: 44, names: ['OT-PLT-Bockstedt'], networks: ['10.124.44.0/24'],
          switches: [{ device_id: 169, hostname: 'moxa-iks-01', name: 'OT-PLT' },
                     { device_id: 42, hostname: 'hpe-core-01', name: 'OT-PLT' }],
          switch_count: 2, firewall_interfaces: [fw(44, 'PLT', '10.124.44.0/24')],
          sources: ['fmg', 'librenms'] },
        { vlan: 90, names: ['OT-Mgmt'], networks: [],
          switches: [{ device_id: 42, hostname: 'hpe-core-01', name: 'OT-Mgmt' }],
          switch_count: 1, firewall_interfaces: [], sources: ['librenms'] },
      ],
      free: [[1, 43], [45, 89], [91, 4094]],
      used_count: 2, free_count: 4092, range: [1, 4094],
      sources: { librenms: true, fmg: true },
      stats: { librenms_rows: 3, librenms_skipped: 0, librenms_devices: 2,
        librenms_devices_known: 3, contributing_devices: ['moxa-iks-01', 'hpe-core-01'],
        fmg_interfaces: 1 },
      synced_at: '2026-08-17T06:00:00+00:00', warnings: [],
    };
  }
  return request('/api/vlans');
}

export async function librenmsTest(): Promise<{
  ok: boolean; version: string; db_schema?: number; devices: number;
}> {
  if (isDemoMode()) return { ok: true, version: '26.6.1', devices: 137 };
  return request('/api/librenms/test', { method: 'POST' });
}

export async function librenmsRefresh(): Promise<{ ok: boolean }> {
  if (isDemoMode()) return { ok: true };
  return request('/api/librenms/refresh', { method: 'POST' });
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
