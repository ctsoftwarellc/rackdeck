import type {
  AccessTokenRecord,
  AuditEvent,
  ConnectRoute,
  DiscoveredPeer,
  JoinRequest,
  ManagedApp,
  Node,
  PairingInvitation,
  TelemetrySample,
} from "./types";

interface SecretRow {
  name: string;
  nodeIds: string[];
  updatedAt: number;
}

const LATEST_VERSION = "0.2.3";
const CONTROLLER_ID = "macbook-pro";

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function clamp(v: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, v));
}

function jitter(val: number, delta: number, min: number, max: number): number {
  const next = val + (Math.random() - 0.5) * 2 * delta;
  return Number(clamp(next, min, max).toFixed(1));
}

function randHex(len: number): string {
  const chars = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function buildInitialState() {
  const now = nowSec();

  const nodes: Node[] = [
    {
      id: CONTROLLER_ID,
      name: "macbook-pro",
      kind: "mac",
      os: "macOS 15.4 (arm64)",
      kernel: "Darwin 24.4.0",
      status: "online",
      lastSeen: now,
      uptimeSecs: 4 * 86400 + 11 * 3600 + 22 * 60,
      hw: {
        cpuCores: 14,
        ramTotalMb: 36864,
        diskTotalGb: 1000,
        accel: {
          kind: "apple",
          chip: "Apple M3 Max",
          unifiedTotalMb: 36864,
          ane: true,
        },
      },
      docker: "running",
      version: LATEST_VERSION,
      lanIp: "192.168.1.89",
      tailscaleIp: "100.84.12.14",
      connectSlug: "macbook-pro",
      connectEnabled: false,
    },
    {
      id: "gpu-rig",
      name: "gpu-rig",
      kind: "gpu",
      os: "Ubuntu 24.04 LTS (x86_64)",
      kernel: "6.8.0-51-generic",
      status: "online",
      lastSeen: now,
      uptimeSecs: 19 * 86400 + 6 * 3600 + 40 * 60,
      hw: {
        cpuCores: 16,
        ramTotalMb: 65536,
        diskTotalGb: 2000,
        accel: {
          kind: "nvidia",
          gpus: [{ idx: 0, name: "NVIDIA RTX 4090", vramTotalMb: 24576 }],
          driver: "565.57",
          driverLoaded: true,
        },
      },
      docker: "running",
      version: "0.2.2",
      lanIp: "192.168.1.88",
      tailscaleIp: "100.84.12.21",
      connectEnabled: false,
    },
    {
      id: "nas-closet",
      name: "nas-closet",
      kind: "other",
      os: "Ubuntu 24.04 LTS (x86_64)",
      kernel: "6.8.0-51-generic",
      status: "online",
      lastSeen: now,
      uptimeSecs: 47 * 86400 + 3 * 3600 + 15 * 60,
      hw: {
        cpuCores: 8,
        ramTotalMb: 16384,
        diskTotalGb: 4000,
        accel: { kind: "none" },
      },
      docker: "running",
      version: "0.2.2",
      lanIp: "192.168.1.15",
      tailscaleIp: "100.84.12.33",
      connectEnabled: false,
    },
    {
      id: "vps-fra1",
      name: "vps-fra1",
      kind: "vps",
      os: "Debian 12 (x86_64)",
      kernel: "6.1.0-28-amd64",
      status: "offline",
      lastSeen: now - 2 * 3600 - 18 * 60,
      uptimeSecs: 0,
      hw: {
        cpuCores: 2,
        ramTotalMb: 4096,
        diskTotalGb: 80,
        accel: { kind: "none" },
      },
      docker: "running",
      version: LATEST_VERSION,
      tailscaleIp: "100.84.12.40",
      connectEnabled: false,
    },
  ];

  const apps: ManagedApp[] = [
    {
      id: "mac-mlx-lm",
      nodeId: CONTROLLER_ID,
      name: "mlx-lm",
      type: "ai",
      runner: "mlx_lm",
      model: "Qwen2.5-Coder-32B-4bit",
      state: "running",
      ports: [8090],
      domains: [],
      usage: { cpu: 11.4, memMb: 18940, tps: 34.2 },
    },
    {
      id: "mac-postgres",
      nodeId: CONTROLLER_ID,
      name: "postgres-dev",
      type: "docker",
      image: "postgres:17-alpine",
      canUpdate: true,
      updateAvailable: true,
      state: "running",
      ports: [5432],
      domains: [],
      usage: { cpu: 1.8, memMb: 312 },
    },
    {
      id: "mac-rackdeck",
      nodeId: CONTROLLER_ID,
      name: "rackdeck",
      type: "system",
      image: "launchd · com.rackdeck.controller",
      state: "running",
      ports: [7420],
      domains: [],
      usage: { cpu: 0.3, memMb: 13 },
    },
    {
      id: "gpu-ollama",
      nodeId: "gpu-rig",
      name: "ollama",
      type: "ai",
      runner: "ollama",
      model: "qwen2.5-coder:32b",
      state: "running",
      ports: [11434],
      domains: [],
      usage: { cpu: 19.2, memMb: 4280, vramMb: 19450, tps: 78.6 },
    },
    {
      id: "gpu-open-webui",
      nodeId: "gpu-rig",
      name: "chat-ui",
      type: "docker",
      image: "ghcr.io/open-webui/open-webui:main",
      canUpdate: true,
      state: "running",
      ports: [3000],
      domains: [],
      usage: { cpu: 4.1, memMb: 1380 },
    },
    {
      id: "gpu-comfyui",
      nodeId: "gpu-rig",
      name: "comfyui",
      type: "docker",
      image: "yanwk/comfyui-boot:cu124",
      canUpdate: true,
      state: "stopped",
      ports: [8188],
      domains: [],
      usage: { cpu: 0, memMb: 0 },
    },
    {
      id: "gpu-dockerd",
      nodeId: "gpu-rig",
      name: "docker.service",
      type: "system",
      image: "systemd · active (running)",
      state: "running",
      ports: [],
      domains: [],
      usage: { cpu: 0.8, memMb: 148 },
    },
    {
      id: "nas-pihole",
      nodeId: "nas-closet",
      name: "pihole",
      type: "docker",
      image: "pihole/pihole:latest",
      canUpdate: false,
      state: "running",
      ports: [53, 8080],
      domains: [],
      usage: { cpu: 2.4, memMb: 196 },
    },
    {
      id: "nas-uptime-kuma",
      nodeId: "nas-closet",
      name: "uptime-kuma",
      type: "docker",
      image: "louislam/uptime-kuma:1",
      canUpdate: true,
      state: "running",
      ports: [3001],
      domains: [],
      usage: { cpu: 1.5, memMb: 242 },
    },
    {
      id: "nas-tailscaled",
      nodeId: "nas-closet",
      name: "tailscaled.service",
      type: "system",
      image: "systemd · active (running)",
      state: "running",
      ports: [],
      domains: [],
      usage: { cpu: 0.4, memMb: 44 },
    },
    {
      id: "vps-caddy",
      nodeId: "vps-fra1",
      name: "caddy",
      type: "docker",
      image: "caddy:2-alpine",
      canUpdate: true,
      state: "stopped",
      ports: [80, 443],
      domains: [],
      usage: { cpu: 0, memMb: 0 },
    },
    {
      id: "vps-plausible",
      nodeId: "vps-fra1",
      name: "plausible",
      type: "docker",
      image: "ghcr.io/plausible/community-edition:v2",
      canUpdate: true,
      state: "stopped",
      ports: [8000],
      domains: [],
      usage: { cpu: 0, memMb: 0 },
    },
    {
      id: "vps-agent",
      nodeId: "vps-fra1",
      name: "rackdeck-agent.service",
      type: "system",
      image: "systemd · inactive (dead)",
      state: "stopped",
      ports: [],
      domains: [],
      usage: { cpu: 0, memMb: 0 },
    },
  ];

  const tokens: AccessTokenRecord[] = [
    {
      id: "tok_claude_read",
      name: "Claude Code · Nov 10",
      client: "Claude Code",
      scope: "read",
      nodeIds: [],
      createdAt: now - 14 * 86400,
      lastUsedAt: now - 4 * 60,
      expiresAt: now + 76 * 86400,
      revoked: false,
    },
    {
      id: "tok_codex_deploy",
      name: "Codex · Nov 19",
      client: "Codex",
      scope: "deploy",
      nodeIds: [],
      createdAt: now - 5 * 86400,
      lastUsedAt: now - 42 * 60,
      expiresAt: now + 85 * 86400,
      revoked: false,
    },
  ];

  const secrets: SecretRow[] = [
    {
      name: "CLAUDE_CODE_OAUTH_TOKEN",
      nodeIds: [CONTROLLER_ID, "gpu-rig"],
      updatedAt: now - 3 * 86400,
    },
    {
      name: "HF_TOKEN",
      nodeIds: [CONTROLLER_ID, "gpu-rig"],
      updatedAt: now - 9 * 86400,
    },
    {
      name: "BACKUP_ENCRYPTION_KEY",
      nodeIds: ["nas-closet", "vps-fra1"],
      updatedAt: now - 21 * 86400,
    },
  ];

  const audit: AuditEvent[] = [
    {
      id: "aud_106",
      ts: now - 4 * 60,
      actor: "mcp:claude-code-macbook",
      action: "node_health",
      target: "fleet (4 machines)",
      ok: true,
    },
    {
      id: "aud_105",
      ts: now - 42 * 60,
      actor: "mcp:codex-workstation",
      action: "app.restart",
      target: "gpu-rig/chat-ui",
      ok: true,
    },
    {
      id: "aud_104",
      ts: now - 95 * 60,
      actor: "mcp:claude-code-macbook",
      action: "app.stop",
      target: "gpu-rig/ollama",
      ok: false,
      reason: "read token cannot mutate apps",
    },
    {
      id: "aud_103",
      ts: now - 3 * 3600,
      actor: "owner",
      action: "secret.put",
      target: "CLAUDE_CODE_OAUTH_TOKEN",
      ok: true,
    },
    {
      id: "aud_102",
      ts: now - 6 * 3600,
      actor: "mcp:claude-code-macbook",
      action: "container_logs_tail",
      target: "macbook-pro/mlx-lm",
      ok: true,
    },
    {
      id: "aud_101",
      ts: now - 24 * 3600,
      actor: "owner",
      action: "node.join",
      target: "nas-closet",
      ok: true,
    },
  ];

  const peers: DiscoveredPeer[] = [
    {
      id: "peer_nas",
      hostname: "studio-nas",
      ip: "100.84.12.51",
      source: "tailscale",
      os: "Linux (TrueNAS SCALE)",
      online: true,
      inFleet: false,
    },
    {
      id: "peer_nuc",
      hostname: "homelab-nuc",
      ip: "100.84.12.64",
      source: "tailscale",
      os: "Ubuntu 24.04 LTS",
      online: true,
      rackdeckVersion: LATEST_VERSION,
      inFleet: false,
    },
  ];

  const routes: ConnectRoute[] = [
    {
      id: "rt_webui",
      host: "chat.rackdev.app",
      nodeId: "gpu-rig",
      targetApp: "chat-ui",
      targetPort: 3000,
      tls: "auto",
      requireAuth: true,
      bytes24h: 482_000_000,
    },
  ];

  return { nodes, apps, tokens, secrets, audit, peers, routes };
}

function appSampleLogs(app: ManagedApp): string[] {
  switch (app.name) {
    case "mlx-lm":
      return [
        "Loaded Qwen2.5-Coder-32B-4bit into Apple Silicon unified memory (18.5 GB)",
        "HTTP server listening on 127.0.0.1:8090",
        "POST /v1/chat/completions 200 (prompt 412 tok, gen 188 tok, 34.2 tok/s)",
        "POST /v1/chat/completions 200 (prompt 196 tok, gen 94 tok, 35.1 tok/s)",
        "KV cache trimmed: 2 active slots, unified memory pressure normal",
      ];
    case "ollama":
      return [
        "time=info msg=\"NVIDIA RTX 4090 detected (24576 MiB VRAM, driver 565.57)\"",
        "time=info msg=\"loaded model qwen2.5-coder:32b (19.0 GiB VRAM)\"",
        "POST /api/generate 200 1.84s (78.6 tok/s)",
        "POST /api/chat 200 2.31s (76.9 tok/s)",
        "GPU thermal check: 66C, fan 41%, memory clocks nominal",
      ];
    case "chat-ui":
    case "open-webui":
      return [
        "INFO:     Started server process [1]",
        "INFO:     Uvicorn running on http://0.0.0.0:3000 (Press CTRL+C to quit)",
        "INFO:     Connected to Ollama backend at http://127.0.0.1:11434",
        "INFO:     GET /api/v1/models 200 OK (12ms)",
        "INFO:     POST /api/chat/completions 200 OK (streamed)",
      ];
    case "pihole":
      return [
        "dnsmasq[42]: started, version 2.90 cachesize 10000",
        "FTL: 18,412 queries over last 24h (14.2% blocked)",
        "query[A] api.github.com from 192.168.1.89 -> forwarded to 1.1.1.1",
        "query[A] telemetry.example.invalid from 192.168.1.88 -> gravity blocked",
        "FTL: database checkpoint complete (4ms)",
      ];
    case "uptime-kuma":
      return [
        "Monitor [macbook-pro :7420] UP (3ms)",
        "Monitor [gpu-rig chat-ui :3000] UP (9ms)",
        "Monitor [nas-closet pihole :8080] UP (2ms)",
        "Monitor [vps-fra1 caddy :443] DOWN (connect ETIMEDOUT)",
        "Heartbeat cycle complete (3/4 healthy)",
      ];
    case "postgres-dev":
      return [
        "PostgreSQL init complete; ready for start up.",
        "LOG:  database system is ready to accept connections",
        "LOG:  checkpoint starting: time",
        "LOG:  checkpoint complete: wrote 18 buffers (0.1%); 0 WAL file(s) added",
      ];
    default:
      return [
        `${app.name}: service initialized (${app.image ?? app.model ?? app.type})`,
        `${app.name}: health check passed`,
        `${app.name}: steady state, waiting for requests`,
      ];
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function installDemo(): void {
  const g = window as unknown as { __rackdeckDemoInstalled?: boolean };
  if (g.__rackdeckDemoInstalled) return;
  g.__rackdeckDemoInstalled = true;

  document.title = "Rackdeck Live Demo";

  const state = buildInitialState();
  let joinRequest: JoinRequest | null = {
    key: "demo-mini-pc",
    nodeId: "mini-pc",
    name: "mini-pc",
    os: "Ubuntu 24.04",
    ip: "192.168.1.42",
    code: "043 604",
    at: nowSec(),
  };

  // Baseline telemetry state per node for smooth random walks
  const telState: Record<string, TelemetrySample> = {
    [CONTROLLER_ID]: {
      t: nowSec(),
      cpu: 18,
      memMb: 21400,
      diskGb: 412,
      netRxBps: 1_850_000,
      netTxBps: 640_000,
    },
    "gpu-rig": {
      t: nowSec(),
      cpu: 31,
      memMb: 32400,
      diskGb: 984,
      netRxBps: 4_200_000,
      netTxBps: 2_900_000,
      gpu: [68],
      vramMb: [19450],
      tempC: 66,
    },
    "nas-closet": {
      t: nowSec(),
      cpu: 11,
      memMb: 4120,
      diskGb: 1420,
      netRxBps: 245_000,
      netTxBps: 138_000,
      tempC: 44,
    },
  };

  function nextSample(node: Node, ts: number): TelemetrySample {
    const prev = telState[node.id] ?? {
      t: ts,
      cpu: 12,
      memMb: Math.round(node.hw.ramTotalMb * 0.35),
      diskGb: Math.round(node.hw.diskTotalGb * 0.3),
      netRxBps: 120_000,
      netTxBps: 60_000,
    };

    const next: TelemetrySample = {
      t: ts,
      cpu: jitter(prev.cpu, node.kind === "gpu" ? 5.5 : 3.2, 4, node.kind === "gpu" ? 84 : 52),
      memMb: Math.round(
        jitter(prev.memMb, 140, node.hw.ramTotalMb * 0.18, node.hw.ramTotalMb * 0.85)
      ),
      diskGb: prev.diskGb,
      netRxBps: Math.round(jitter(prev.netRxBps, prev.netRxBps * 0.25 + 40_000, 18_000, 18_000_000)),
      netTxBps: Math.round(jitter(prev.netTxBps, prev.netTxBps * 0.25 + 25_000, 12_000, 12_000_000)),
    };

    if (node.hw.accel.kind === "nvidia") {
      const ollamaRunning = state.apps.some(
        (a) => a.nodeId === node.id && a.type === "ai" && a.state === "running"
      );
      const baseGpu = prev.gpu?.[0] ?? 65;
      const targetGpu = ollamaRunning ? jitter(baseGpu, 6, 38, 89) : jitter(baseGpu * 0.4, 2, 3, 12);
      const baseVram = ollamaRunning ? prev.vramMb?.[0] ?? 19450 : 940;
      const vram = ollamaRunning ? Math.round(jitter(baseVram, 90, 18800, 21200)) : 940;
      next.gpu = [targetGpu];
      next.vramMb = [vram];
      next.tempC = jitter(prev.tempC ?? 65, 1.2, ollamaRunning ? 58 : 37, ollamaRunning ? 74 : 46);
    } else if (prev.tempC !== undefined) {
      next.tempC = jitter(prev.tempC, 0.8, 42, 56);
    }

    telState[node.id] = next;
    return next;
  }

  // Active fake WebSocket connections
  const sockets = new Set<MockWebSocket>();

  function broadcast(payload: unknown): void {
    const raw = JSON.stringify(payload);
    sockets.forEach((ws) => ws._deliver(raw));
  }

  function recordAudit(actor: string, action: string, target: string, ok = true, reason?: string): void {
    const ev: AuditEvent = {
      id: `aud_${Date.now()}_${randHex(4)}`,
      ts: nowSec(),
      actor,
      action,
      target,
      ok,
      ...(reason ? { reason } : {}),
    };
    state.audit = [ev, ...state.audit.slice(0, 199)];
    broadcast({ t: "audit", ev });
  }

  // Periodically emit telemetry for online nodes
  window.setInterval(() => {
    const ts = nowSec();
    for (const node of state.nodes) {
      if (node.status !== "online") continue;
      node.lastSeen = ts;
      node.uptimeSecs += 2;
      const s = nextSample(node, ts);
      broadcast({ t: "tm", nodeId: node.id, s });
    }
  }, 1500);

  // Mock WebSocket implementation matching browser WebSocket API
  const NativeWebSocket = window.WebSocket;

  class MockWebSocket {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSING = 2;
    static readonly CLOSED = 3;

    readonly CONNECTING = 0;
    readonly OPEN = 1;
    readonly CLOSING = 2;
    readonly CLOSED = 3;

    url: string;
    readyState: number = MockWebSocket.CONNECTING;
    protocol = "";
    extensions = "";
    bufferedAmount = 0;
    binaryType: BinaryType = "blob";

    onopen: ((ev: Event) => unknown) | null = null;
    onmessage: ((ev: MessageEvent) => unknown) | null = null;
    onclose: ((ev: CloseEvent) => unknown) | null = null;
    onerror: ((ev: Event) => unknown) | null = null;

    private listeners: Record<string, Set<EventListenerOrEventListenerObject>> = {};
    private logTimers = new Map<string, number>();

    constructor(url: string | URL) {
      this.url = String(url);
      sockets.add(this);

      window.setTimeout(() => {
        if (this.readyState !== MockWebSocket.CONNECTING) return;
        this.readyState = MockWebSocket.OPEN;
        const openEv = new Event("open");
        this.onopen?.(openEv);
        this._dispatch("open", openEv);

        // Send initial fleet snapshot
        this._deliver(JSON.stringify({ t: "snapshot", nodes: state.nodes, apps: state.apps }));

        // Seed 24 points of recent telemetry so sparklines render immediately
        const now = nowSec();
        for (const node of state.nodes) {
          if (node.status !== "online") continue;
          for (let i = 24; i >= 1; i--) {
            const sample = nextSample(node, now - i * 2);
            this._deliver(JSON.stringify({ t: "tm", nodeId: node.id, s: sample }));
          }
        }
      }, 25);
    }

    _deliver(data: string): void {
      if (this.readyState !== MockWebSocket.OPEN) return;
      const ev = new MessageEvent("message", { data });
      this.onmessage?.(ev);
      this._dispatch("message", ev);
    }

    private _dispatch(type: string, ev: Event): void {
      const set = this.listeners[type];
      if (!set) return;
      set.forEach((fn) => {
        if (typeof fn === "function") fn(ev);
        else fn.handleEvent(ev);
      });
    }

    addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
      if (!this.listeners[type]) this.listeners[type] = new Set();
      this.listeners[type].add(listener);
    }

    removeEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
      this.listeners[type]?.delete(listener);
    }

    send(raw: string): void {
      if (this.readyState !== MockWebSocket.OPEN) return;
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }

      if (msg.t === "ping") {
        const latency = 6 + Math.floor(Math.random() * 7);
        window.setTimeout(() => {
          this._deliver(JSON.stringify({ t: "pong", id: msg.id }));
        }, latency);
      } else if (msg.t === "sub" && msg.ch === "logs") {
        const sub = String(msg.sub ?? "");
        const app = state.apps.find((a) => a.id === msg.appId);
        const seedLines = app
          ? appSampleLogs(app)
          : ["Log stream connected."];
        const ts = nowSec();
        const initial: Array<[number, string, string]> = seedLines.map((line, i) => [
          ts - (seedLines.length - i) * 3,
          "stdout",
          line,
        ]);
        this._deliver(JSON.stringify({ t: "log", sub, lines: initial }));

        let tick = 0;
        const timer = window.setInterval(() => {
          tick += 1;
          const label = app?.name ?? "service";
          const streamMsg =
            app?.type === "ai"
              ? `Request #${140 + tick} completed (${Math.round(30 + Math.random() * 48)} tok/s)`
              : `${label}: heartbeat ok (${Math.round(2 + Math.random() * 14)}ms)`;
          this._deliver(
            JSON.stringify({
              t: "log",
              sub,
              lines: [[nowSec(), "stdout", streamMsg]],
            })
          );
        }, 2600);
        this.logTimers.set(sub, timer);
      } else if (msg.t === "unsub") {
        const sub = String(msg.sub ?? "");
        const timer = this.logTimers.get(sub);
        if (timer !== undefined) {
          window.clearInterval(timer);
          this.logTimers.delete(sub);
        }
      } else if (msg.t === "term_exec") {
        this._deliver(
          JSON.stringify({
            t: "term_out",
            text: "Terminal commands are disabled in the live demo. Install Rackdeck on your own machine for interactive shell access.",
          })
        );
      }
    }

    close(): void {
      if (this.readyState === MockWebSocket.CLOSED) return;
      this.readyState = MockWebSocket.CLOSED;
      sockets.delete(this);
      this.logTimers.forEach((timer) => window.clearInterval(timer));
      this.logTimers.clear();
      const closeEv = new CloseEvent("close");
      this.onclose?.(closeEv);
      this._dispatch("close", closeEv);
    }
  }

  const PatchedWebSocket = new Proxy(NativeWebSocket, {
    construct(target, args) {
      const rawUrl = String(args[0] ?? "");
      if (rawUrl.includes("/api/ws") || rawUrl.includes("/api/v1/ws")) {
        return new MockWebSocket(rawUrl) as unknown as WebSocket;
      }
      try {
        const u = new URL(rawUrl, location.href);
        if (u.pathname === "/api/ws" || u.pathname === "/api/v1/ws") {
          return new MockWebSocket(u.href) as unknown as WebSocket;
        }
      } catch {
        // Fall through to native WebSocket
      }
      return new target(args[0], args[1]);
    },
  });

  window.WebSocket = PatchedWebSocket;

  // Intercept fetch for Rackdeck API, MCP endpoint, and GitHub latest release check
  const nativeFetch = window.fetch.bind(window);

  async function handleDemoFetch(url: URL, init?: RequestInit): Promise<Response> {
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.pathname;
    const readJson = (): Record<string, unknown> => {
      if (!init?.body || typeof init.body !== "string") return {};
      try {
        return JSON.parse(init.body) as Record<string, unknown>;
      } catch {
        return {};
      }
    };

    // GitHub latest release check (deterministic so update flow works offline)
    if (url.hostname === "api.github.com" && path.endsWith("/releases/latest")) {
      return jsonResponse({ tag_name: `v${LATEST_VERSION}` });
    }

    // Auth
    if (path === "/api/v1/auth/status") {
      return jsonResponse({ passwordRequired: true, authenticated: true });
    }
    if (path === "/api/v1/auth/login" && method === "POST") {
      return jsonResponse({ ok: true });
    }

    // Health
    if (path === "/api/v1/health") {
      const ctrl = state.nodes.find((n) => n.id === CONTROLLER_ID);
      return jsonResponse({
        ok: true,
        nodeId: CONTROLLER_ID,
        passwordSet: true,
        connectEnabled: Boolean(ctrl?.connectEnabled),
        connectActive: false,
        relayConfigured: false,
      });
    }

    // Pairing & Join Token
    if (path === "/api/v1/pair" && method === "POST") {
      const invite: PairingInvitation = {
        id: `pair_${randHex(6)}`,
        nodeId: CONTROLLER_ID,
        code6: String(100000 + Math.floor(Math.random() * 900000)),
        fingerprint: "DEMO-4F9A-SAMPLE-8C12",
        qrUri: "rackdeck://demo-preview-only",
        expiresAt: nowSec() + 60,
      };
      return jsonResponse(invite);
    }
    if (path === "/api/v1/join-token" && method === "POST") {
      return jsonResponse({
        command:
          "curl -fsSL https://get.rackdeck.dev | sh -s -- --controller http://100.84.12.14:7420 --join rd_join_demo_sample_only --key demo_sample_key",
      });
    }

    if (path === "/api/v1/join-requests" && method === "GET") {
      return jsonResponse({ requests: joinRequest ? [joinRequest] : [] });
    }
    if (path === "/api/v1/join-requests/demo-mini-pc") {
      if (method === "POST") {
        if (!joinRequest) return jsonResponse({ error: "That request expired." }, 404);
        const node: Node = {
          id: joinRequest.nodeId,
          name: joinRequest.name,
          os: joinRequest.os,
          lanIp: joinRequest.ip ?? undefined,
          kind: "other",
          status: "online",
          lastSeen: nowSec(),
          uptimeSecs: 0,
          hw: { cpuCores: 4, ramTotalMb: 8192, diskTotalGb: 256, accel: { kind: "none" } },
          docker: "absent",
          version: LATEST_VERSION,
          connectEnabled: false,
        };
        joinRequest = null;
        state.nodes.push(node);
        broadcast({ t: "node", node });
        recordAudit("you (web)", "allow machine", node.id);
        return jsonResponse({ ok: true });
      }
      if (method === "DELETE") {
        joinRequest = null;
        return jsonResponse({ ok: true });
      }
    }

    // Tailnet Discovery
    if (path === "/api/v1/discovery/scan" && method === "POST") {
      await delay(280);
      return jsonResponse({ peers: state.peers });
    }

    // Account & Connect
    if (path === "/api/v1/account") {
      return jsonResponse({ linked: false, active: false, slugs: [] });
    }
    if (path === "/api/v1/account/link" && method === "POST") {
      return jsonResponse({ error: "Account linking is disabled in the live demo." }, 400);
    }
    if (path === "/api/v1/account/link/poll" && method === "POST") {
      return jsonResponse({ status: "expired" });
    }
    if (path === "/api/v1/connect" && method === "POST") {
      const body = readJson();
      const ctrl = state.nodes.find((n) => n.id === CONTROLLER_ID);
      if (ctrl) {
        ctrl.connectEnabled = Boolean(body.enabled);
        if (typeof body.slug === "string" && body.slug.trim()) {
          ctrl.connectSlug = body.slug.trim();
        }
        broadcast({ t: "node", node: ctrl });
        recordAudit("owner", ctrl.connectEnabled ? "connect.enable" : "connect.disable", ctrl.name);
        return jsonResponse({ node: ctrl });
      }
      return jsonResponse({ ok: true });
    }

    // Connect Routes
    if (path === "/api/v1/connect/routes" && method === "GET") {
      return jsonResponse({ routes: state.routes });
    }
    if (path === "/api/v1/connect/routes" && method === "POST") {
      const body = readJson();
      const route: ConnectRoute = {
        id: `rt_${randHex(6)}`,
        host: String(body.host ?? "").trim(),
        nodeId: String(body.nodeId ?? CONTROLLER_ID),
        targetApp: String(body.targetApp ?? "app"),
        targetPort: Number(body.targetPort) || 8080,
        tls: "auto",
        requireAuth: true,
        bytes24h: 0,
      };
      state.routes = [route, ...state.routes];
      recordAudit("owner", "route.create", `${route.host} -> ${route.targetApp}:${route.targetPort}`);
      return jsonResponse({ route });
    }
    const routeDelMatch = path.match(/^\/api\/v1\/connect\/routes\/([^/]+)$/);
    if (routeDelMatch && method === "DELETE") {
      const id = decodeURIComponent(routeDelMatch[1]);
      const removed = state.routes.find((r) => r.id === id);
      state.routes = state.routes.filter((r) => r.id !== id);
      if (removed) recordAudit("owner", "route.delete", removed.host);
      return jsonResponse({ ok: true });
    }

    // Secrets
    if (path === "/api/v1/secrets" && method === "GET") {
      return jsonResponse(state.secrets);
    }
    const secretMatch = path.match(/^\/api\/v1\/secrets\/([^/]+)$/);
    if (secretMatch && method === "PUT") {
      const name = decodeURIComponent(secretMatch[1]).trim();
      const blocked = new Set([
        "PATH",
        "HOME",
        "SHELL",
        "USER",
        "IFS",
        "ENV",
        "BASH_ENV",
        "PROMPT_COMMAND",
      ]);
      const valid =
        name.length > 0 &&
        name.length <= 64 &&
        /^[A-Z_][A-Z0-9_]*$/.test(name) &&
        !blocked.has(name) &&
        !name.startsWith("LD_") &&
        !name.startsWith("DYLD_");
      if (!valid) {
        return jsonResponse(
          {
            error:
              "use capital letters, digits and _ (like CLAUDE_CODE_OAUTH_TOKEN). PATH, HOME, LD_* and DYLD_* aren't allowed",
          },
          400
        );
      }
      const body = readJson();
      const nodeIds = Array.isArray(body.nodeIds)
        ? body.nodeIds.map((x) => String(x))
        : [];
      const existing = state.secrets.find((s) => s.name === name);
      if (existing) {
        existing.nodeIds = nodeIds;
        existing.updatedAt = nowSec();
      } else {
        state.secrets = [{ name, nodeIds, updatedAt: nowSec() }, ...state.secrets];
      }
      recordAudit("owner", "secret.put", `${name} (${nodeIds.length} machines)`);
      return jsonResponse({ ok: true });
    }
    if (secretMatch && method === "DELETE") {
      const name = decodeURIComponent(secretMatch[1]);
      state.secrets = state.secrets.filter((s) => s.name !== name);
      recordAudit("owner", "secret.delete", name);
      return jsonResponse({ ok: true });
    }

    // MCP Tokens
    if (path === "/api/v1/tokens" && method === "GET") {
      return jsonResponse({ tokens: state.tokens });
    }
    if (path === "/api/v1/tokens" && method === "POST") {
      const body = readJson();
      const name = String(body.name ?? "demo-token").trim();
      const client = String(body.client ?? "Claude Code");
      const scope = body.scope === "deploy" ? "deploy" : "read";
      const days = Number(body.expiresInDays) || 90;
      const now = nowSec();
      const record: AccessTokenRecord = {
        id: `tok_${randHex(6)}`,
        name,
        client,
        scope,
        nodeIds: [],
        createdAt: now,
        expiresAt: now + days * 86400,
        revoked: false,
      };
      const token = `rd_demo_${randHex(24)}`;
      state.tokens = [record, ...state.tokens];
      recordAudit("owner", "create token", name);
      return jsonResponse({ record, token });
    }
    const tokenDelMatch = path.match(/^\/api\/v1\/tokens\/([^/]+)$/);
    if (tokenDelMatch && method === "DELETE") {
      const id = decodeURIComponent(tokenDelMatch[1]);
      const tok = state.tokens.find((t) => t.id === id);
      if (tok) {
        tok.revoked = true;
        recordAudit("owner", "token.revoke", tok.name);
      }
      return jsonResponse({ revoked: Boolean(tok) });
    }

    // Audit Log
    if (path === "/api/v1/audit" && method === "GET") {
      return jsonResponse({ events: state.audit });
    }

    const appActionMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)\/apps\/([^/]+)\/(start|stop|restart|remove|update)$/);
    if (appActionMatch && method === "POST") {
      const nodeId = decodeURIComponent(appActionMatch[1]);
      const appId = decodeURIComponent(appActionMatch[2]);
      const action = appActionMatch[3];
      const node = state.nodes.find((n) => n.id === nodeId);
      const app = state.apps.find((a) => a.id === appId && a.nodeId === nodeId);

      if (!node || !app) {
        return jsonResponse({ error: "Service not found." }, 404);
      }
      if (node.status !== "online") {
        recordAudit("owner", `app.${action}`, `${node.name}/${app.name}`, false, "machine offline");
        return jsonResponse({ error: `${node.name} is offline.` }, 409);
      }

      if (action === "remove" || action === "update") {
        if (app.type !== "docker") return jsonResponse({ error: "This action is only available for Docker apps." }, 400);
        if (action === "update" && !app.canUpdate) {
          return jsonResponse({ error: "This app has no saved Rackdeck install settings." }, 400);
        }
        await delay(action === "update" ? 1200 : 420);
        if (action === "remove") {
          state.apps = state.apps.filter((item) => item !== app);
          const deleteData = url.searchParams.get("deleteData") === "true";
          recordAudit("owner", deleteData ? "remove app and data" : "remove app", `${node.name}/${app.name}`);
          broadcast({ t: "apps", apps: [...state.apps] });
          return jsonResponse({ ok: true });
        }
        const changed = app.updateAvailable;
        if (changed) {
          app.updateAvailable = false;
          app.state = "running";
          broadcast({ t: "apps", apps: [...state.apps] });
        }
        recordAudit("owner", "update app", `${node.name}/${app.name}`);
        return jsonResponse({ ok: true, message: changed ? "App updated." : "Already up to date." });
      }

      await delay(420);
      if (action === "stop") {
        app.state = "stopped";
        app.usage = { cpu: 0, memMb: 0 };
      } else {
        app.state = "running";
        app.usage = {
          cpu: app.type === "ai" ? 14.5 : 2.8,
          memMb: app.type === "ai" ? 4200 : 380,
        };
      }
      broadcast({ t: "apps", apps: [...state.apps] });
      recordAudit("owner", `app.${action}`, `${node.name}/${app.name}`);
      return jsonResponse({ ok: true, app });
    }

    // Deploy App
    const deployMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)\/deploy$/);
    if (deployMatch && method === "POST") {
      const nodeId = decodeURIComponent(deployMatch[1]);
      const node = state.nodes.find((n) => n.id === nodeId);
      if (!node) return jsonResponse({ error: "Machine not found." }, 404);
      if (node.status !== "online") {
        return jsonResponse({ error: `${node.name} is offline.` }, 409);
      }
      if (node.docker !== "running") {
        return jsonResponse({ error: `Docker is not running on ${node.name}.` }, 400);
      }
      const body = readJson();
      const name = String(body.name ?? "").trim();
      const image = String(body.image ?? "").trim();
      if (!name || !image) {
        return jsonResponse({ error: "App name and image are required." }, 400);
      }
      await delay(700);
      if (state.apps.some((app) => app.nodeId === node.id && app.name === name && app.type === "docker")) {
        return jsonResponse({ error: "An app with that name is already on " + node.name + "." }, 409);
      }
      if (body.gpu && node.hw.accel.kind !== "nvidia") {
        return jsonResponse({ error: node.name + " has no NVIDIA GPU." }, 400);
      }
      const hostPort = Number(body.hostPort);
      const ports = new Set<number>();
      if (Number.isInteger(hostPort) && hostPort > 0) ports.add(hostPort);
      if (Array.isArray(body.ports)) {
        for (const mapping of body.ports) {
          const port = Number(String(mapping).split(":")[0]);
          if (Number.isInteger(port) && port > 0) ports.add(port);
        }
      }
      const newApp: ManagedApp = {
        id: `${node.id}-${name}-${randHex(3)}`,
        nodeId: node.id,
        name,
        type: "docker",
        image,
        canUpdate: true,
        state: "running",
        ports: [...ports],
        domains: [],
        usage: { cpu: 1.9, memMb: 184 },
      };
      state.apps = [...state.apps, newApp];
      broadcast({ t: "apps", apps: [...state.apps] });
      recordAudit("owner", "app.deploy", `${node.name}/${name}`);
      return jsonResponse({ app: newApp });
    }

    // Node Update
    const updateMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)\/update$/);
    if (updateMatch && method === "POST") {
      const nodeId = decodeURIComponent(updateMatch[1]);
      const node = state.nodes.find((n) => n.id === nodeId);
      if (!node) return jsonResponse({ error: "Machine not found." }, 404);
      if (node.status !== "online") {
        return jsonResponse({ error: `${node.name} is offline.` }, 409);
      }
      if (node.version === LATEST_VERSION) {
        return jsonResponse({ updatedTo: null });
      }
      await delay(550);
      node.version = LATEST_VERSION;
      broadcast({ t: "node", node: { ...node } });
      recordAudit("owner", "node.update", `${node.name} -> v${LATEST_VERSION}`);
      return jsonResponse({ updatedTo: LATEST_VERSION });
    }

    // Node Remove
    const nodeDelMatch = path.match(/^\/api\/v1\/nodes\/([^/]+)$/);
    if (nodeDelMatch && method === "DELETE") {
      const nodeId = decodeURIComponent(nodeDelMatch[1]);
      if (nodeId === CONTROLLER_ID) {
        return jsonResponse({ error: "Cannot remove the controller machine." }, 400);
      }
      const removed = state.nodes.find((n) => n.id === nodeId);
      state.nodes = state.nodes.filter((n) => n.id !== nodeId);
      state.apps = state.apps.filter((a) => a.nodeId !== nodeId);
      state.routes = state.routes.filter((r) => r.nodeId !== nodeId);
      state.secrets = state.secrets.map((s) => ({
        ...s,
        nodeIds: s.nodeIds.filter((id) => id !== nodeId),
      }));
      broadcast({ t: "snapshot", nodes: [...state.nodes], apps: [...state.apps] });
      if (removed) recordAudit("owner", "node.remove", removed.name);
      return jsonResponse({ ok: true });
    }

    // MCP Endpoint
    if (path === "/mcp" || path.startsWith("/mcp/")) {
      const body = readJson();
      const id = body.id ?? 1;
      const inputSchema = {
        type: "object",
        properties: { nodeId: { type: "string" }, appId: { type: "string" } },
        required: ["appId"],
        additionalProperties: false,
      };
      if (body.method === "tools/list") {
        return jsonResponse({
          jsonrpc: "2.0",
          id,
          result: {
            tools: [
              { name: "node_health", description: "List machines with live status and resource usage." },
              { name: "container_logs_tail", description: "Read recent logs for a service." },
              { name: "app_action", description: "Start, stop, or restart a container." },
              { name: "remove_app", description: "Remove a Docker app and keep its saved data.", inputSchema },
              { name: "update_app", description: "Update a Docker app.", inputSchema },
              { name: "deploy_app", description: "Deploy a Docker container." },
            ],
          },
        });
      }
      const params = body.params as { name?: string; arguments?: Record<string, unknown> } | undefined;
      if (body.method === "tools/call" && (params?.name === "remove_app" || params?.name === "update_app")) {
        const args = params.arguments ?? {};
        const node = typeof args.nodeId === "string" ? args.nodeId : CONTROLLER_ID;
        const action = params.name === "remove_app" ? "remove" : "update";
        const result = (text: string, isError = false) =>
          jsonResponse({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }], isError } });
        if (typeof args.appId !== "string" || !args.appId) return result("Choose an app from list_apps.", true);
        if (action === "remove" && args.deleteData) return result("Only the owner can delete app data in the dashboard.", true);
        const endpoint = `/api/v1/nodes/${encodeURIComponent(node)}/apps/${encodeURIComponent(args.appId)}/${action}`;
        const res = await handleDemoFetch(new URL(endpoint, url.origin), { method: "POST" });
        const data = await res.json();
        return result(res.ok ? data.message ?? "App removed." : data.error, !res.ok);
      }
      return jsonResponse({
        jsonrpc: "2.0",
        id,
        result: {
          nodes: state.nodes.map((n) => ({
            id: n.id,
            name: n.name,
            status: n.status,
            os: n.os,
            version: n.version,
          })),
        },
      });
    }

    // Unknown /api/* route
    return jsonResponse({ error: "not available in the demo" }, 404);
  }

  window.fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const rawUrl =
      typeof input === "string"
        ? input
        : input instanceof URL
        ? input.href
        : input.url;

    const isRelativeApi =
      rawUrl.startsWith("/api/") || rawUrl === "/mcp" || rawUrl.startsWith("/mcp/");

    let parsed: URL;
    try {
      parsed = isRelativeApi
        ? new URL(rawUrl, "http://demo.local")
        : new URL(rawUrl, location.href);
    } catch {
      return nativeFetch(input, init);
    }

    const isSameOriginApi =
      isRelativeApi ||
      (parsed.origin === location.origin &&
        (parsed.pathname.startsWith("/api/") ||
          parsed.pathname === "/mcp" ||
          parsed.pathname.startsWith("/mcp/")));

    const isGithubRelease =
      parsed.hostname === "api.github.com" &&
      parsed.pathname === "/repos/ctsoftwarellc/rackdeck/releases/latest";

    if (isSameOriginApi || isGithubRelease) {
      return handleDemoFetch(parsed, init);
    }

    return nativeFetch(input, init);
  };
}
