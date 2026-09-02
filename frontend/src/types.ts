// Spiegelt die Pydantic-Modelle des Backends (engine/verdict.py)

export type HopVerdict = 'ALLOW' | 'DENY' | 'UNKNOWN';
export type TraceVerdict = 'ALLOW' | 'DENY' | 'DEGRADED';
export type EgressClass = 'LOCAL' | 'VDOM_LINK' | 'OVERLAY' | 'ROUTED' | 'DEFAULT' | 'UNKNOWN';
export type Provenance = 'fmg' | 'itop' | 'dns' | 'ip';

export interface NameEntry {
  name: string;
  provenance: Provenance;
}

export interface Endpoint {
  ip: string;
  names: NameEntry[];
  provenance: Provenance;
}

export interface Candidate {
  policyid: number | null;
  name: string;
  action: string;
  srcintf: string[];
  dstintf: string[];
  srcaddr: string[];
  dstaddr: string[];
  service: string[];
  comments: string;
  hit: boolean;
  obj_types?: Record<string, string>;
  /** Gesetzt bei globalen Header-/Footer-Regeln des FortiManagers — die stehen
   *  nicht im Geräte-Package und sind auch nur dort zu ändern. */
  scope?: 'header' | 'footer' | null;
  package?: string | null;
}

export interface Suggestion {
  device: string;
  vdom: string;
  adom: string;
  package: string | null;
  src_zone: string;
  dst_zone: string;
  src_obj: { name: string; existing: boolean; subnet?: string };
  dst_obj: { name: string; existing: boolean; subnet?: string };
  service: { name: string; existing: boolean; protocol?: string; port?: number };
  policy_name: string;
  cli: string;
  jsonrpc: string[];
  note: string;
  fmg_url?: string | null;
}

/** Ist-Nachweis eines Hops: passende Einträge der FortiOS-Session-Tabelle.
 *  `truncated`/`server_filtered` gehören dazu, weil "0 Sessions" nur bei
 *  vollständiger Liste etwas bedeutet. */
export interface SessionProbe {
  match_count: number;
  returned: number;
  truncated: boolean;
  server_filtered: boolean | null;
  samples: SessionSample[];
  policy_ids: number[];
  params: Record<string, unknown>;
}

export interface SessionSample {
  src: string | null;
  srcport: number | null;
  dst: string | null;
  dstport: number | null;
  proto: number | null;
  protocol: string | null;
  srcintf: string | null;
  dstintf: string | null;
  policyid: number | null;
  nat_src: string | null;
  nat_dst: string | null;
  duration: number | null;
  expire: number | null;
}

export interface Hop {
  index: number;
  device: string;
  vdom: string;
  adom: string | null;
  srcintf: string;
  src_zone: string | null;
  egress: string | null;
  egress_zone: string | null;
  egress_class: EgressClass;
  route: { interface: string; gateway: string | null; source: string } | null;
  verdict: HopVerdict;
  matched_policy: Candidate | null;
  candidates: Candidate[];
  suggestion: Suggestion | null;
  /** Nur gesetzt, wenn der Trace mit Session-Probe lief. */
  sessions?: SessionProbe | null;
  warnings: string[];
  degraded: boolean;
  after_deny: boolean;
  debug?: HopDebug;
}

/** Entscheidungs-Protokoll eines Hops: warum ging es hier weiter — und wohin.
 *  Bewusst locker typisiert (das Backend erweitert die Felder je Fall). */
export interface HopDebug {
  router_lookup?: { proxy: unknown; source?: string | null; response?: unknown };
  policy_lookup?: { proxy: unknown; response?: unknown };
  session_probe?: { proxy: unknown; summary?: Record<string, unknown> };
  ingress?: unknown;          // Präfix-Treffer der Quelle (nur Hop 1)
  route?: unknown;            // Interface/Gateway/Herkunft + Cache-Kandidaten
  classification?: {          // geprüfte Regeln + Präfix-Besitzer des Ziels
    checks?: { rule: string; hit: boolean }[];
    dst_owner?: { device: string; network?: string; source?: string } | null;
    owner_conflict?: { chosen: string; owner: string; owner_prefix?: string };
    [k: string]: unknown;
  };
  next_hop?: unknown;         // Übergang inkl. Eintritts-VDOM-Auflösung
  loop_detected?: unknown;
}

export interface TraceResult {
  verdict: TraceVerdict;
  src: Endpoint;
  dst: Endpoint;
  protocol: string;
  dst_port: number | null;
  src_port: number | null;
  icmp_type: number | null;
  icmp_code: number | null;
  hops: Hop[];
  warnings: string[];
  vip: { name: string; extip: string; mappedip: string | null } | null;
  duration_ms: number;
  inventory_synced_at: string | null;
}

// ── Deep-Tracker (alle Ports) ────────────────────────────────────────────────
export type PortRange = [number, number];   // [lo, hi] inklusiv

export interface PortHop {
  index: number;
  device: string;
  vdom: string;
  label: string;
  srcintf: string;
  egress: string | null;
  egress_class: EgressClass | string;
  tcp: PortRange[];
  udp: PortRange[];
  warnings: string[];
  reachable: boolean;
  debug?: HopDebug;
}

export interface PortLimit {
  range: PortRange;
  hop: string | null;
}

export interface PortTraceResult {
  src: Endpoint;
  dst: Endpoint;
  reachable: boolean;
  hops: PortHop[];
  tcp: PortRange[];
  udp: PortRange[];
  limits: { tcp?: PortLimit[]; udp?: PortLimit[] };
  warnings: string[];
  duration_ms: number;
  inventory_synced_at: string | null;
}

export interface TraceRequest {
  src: string;
  dst: string;
  protocol: string;
  dst_port?: number | null;
  src_port?: number | null;
  icmp_type?: number | null;
  icmp_code?: number | null;
  /** Opt-in: zusätzlich die Session-Tabelle jeder Firewall im Pfad lesen. */
  sessions?: boolean;
}

export interface TraceHistoryEntry {
  id: number;
  created_at: string;
  username: string;
  request: TraceRequest;
  verdict: TraceVerdict;
  duration_ms: number;
}

export interface SearchHit {
  name: string;
  ip?: string | null;
  fqdn?: string | null;
  type?: string | null;
  provenance: Provenance;
  adom?: string;
}

export interface SyncStatus {
  phase: 'idle' | 'running' | 'done' | 'error';
  log: string[];
  stats: Record<string, number>;
  started_at: string | null;
  finished_at: string | null;
}

export interface InventorySummary {
  synced_at: string | null;
  adoms: string[];
  devices: Record<string, { adom: string; vdoms: string[] }>;
  counts: Record<string, number>;
}

export interface UserEntry {
  id: number;
  username: string;
  role: 'admin' | 'viewer';
}

export interface Session {
  token: string;
  username: string;
  role: 'admin' | 'viewer';
}

export interface SamlConfig {
  enabled: boolean;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_slo_url: string;
  idp_x509_cert: string;
  sp_entity_id: string;
  acs_url: string;
  slo_url: string;
  attribute_username: string;
  attribute_email: string;
  attribute_display_name: string;
  default_role: 'admin' | 'viewer';
}

export interface SslStatus {
  mode: 'none' | 'upload' | 'self-signed' | 'acme';
  active: boolean;
  subject?: string | null;
  issuer?: string | null;
  not_after?: string | null;
  domains?: string[] | null;
  hostname?: string | null;
}
