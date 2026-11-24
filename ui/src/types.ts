export type NodeKind = "vps" | "gpu" | "mac" | "other";
export type NodeStatus = "online" | "degraded" | "offline";

export interface JoinRequest {
  key: string;
  nodeId: string;
  name: string;
  os: string;
  ip: string | null;
  code: string;
  at: number;
}

export type Accelerator =
  | { kind: "none" }
  | {
      kind: "nvidia";
      gpus: { idx: number; name: string; vramTotalMb: number }[];
      driver?: string;
      driverLoaded: boolean;
    }
  | { kind: "apple"; chip: string; unifiedTotalMb: number; ane: boolean };

export interface Node {
  id: string;
  name: string;
  kind: NodeKind;
  os: string;
  kernel?: string;
  status: NodeStatus;
  lastSeen: number;
  uptimeSecs: number;
  hw: { cpuCores: number; ramTotalMb: number; diskTotalGb: number; accel: Accelerator };
  docker: "running" | "stopped" | "absent";
  version: string;
  lanIp?: string;
  tailscaleIp?: string;
  connectSlug?: string;
  connectEnabled: boolean;
}

export interface ManagedApp {
  id: string;
  nodeId: string;
  name: string;
  type: "docker" | "compose" | "ai" | "system";
  runner?: string;
  image?: string;
  model?: string;
  state: "running" | "stopped" | "starting" | "stopping" | "error";
  ports: number[];
  domains: { host: string; tls: string }[];
  usage: { cpu: number; memMb: number; vramMb?: number; tps?: number };
}

export interface TelemetrySample {
  t: number;
  cpu: number;
  memMb: number;
  diskGb: number;
  netRxBps: number;
  netTxBps: number;
  gpu?: number[];
  vramMb?: number[];
  tempC?: number;
}

export interface DiscoveredPeer {
  id: string;
  hostname: string;
  ip: string;
  source: string;
  os: string;
  online: boolean;
  rackdeckVersion?: string;
  inFleet: boolean;
}

export interface ConnectRoute {
  id: string;
  host: string;
  nodeId: string;
  targetApp: string;
  targetPort: number;
  tls: string;
  requireAuth: boolean;
  bytes24h: number;
}

export interface AccessTokenRecord {
  id: string;
  name: string;
  client: string;
  scope: "read" | "deploy";
  nodeIds: string[];
  createdAt: number;
  lastUsedAt?: number;
  expiresAt?: number;
  revoked: boolean;
}

export interface AuditEvent {
  id: string;
  ts: number;
  actor: string;
  action: string;
  target: string;
  ok: boolean;
  reason?: string;
}

export interface PairingInvitation {
  id: string;
  nodeId: string;
  code6: string;
  fingerprint: string;
  qrUri: string;
  expiresAt: number;
}
