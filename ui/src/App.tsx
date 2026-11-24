import React, { useEffect, useMemo, useRef, useState } from "react";
import QRCode from "qrcode";
import { AppCatalog, dockerUnavailable } from "./AppCatalog";
import { ASSISTANTS, assistantSetup, type Assistant, type AssistantSetup } from "./assistantSetup";
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

type ParsedRoute =
  | { page: "machines" }
  | { page: "machine"; id: string }
  | { page: "apps" }
  | { page: "network" }
  | { page: "access" }
  | { page: "audit" };

const appActionProgress = {
  start: "Starting…",
  stop: "Stopping…",
  restart: "Restarting…",
  remove: "Removing…",
  update: "Updating…",
};

function appKey(app: ManagedApp) {
  return `${app.nodeId}/${app.name}`;
}

function updateDot(app: ManagedApp) {
  return app.updateAvailable && <span className="dot warn" role="img" title="Update available" aria-label="Update available" />;
}

function parseHash(raw: string): ParsedRoute {
  const clean = raw.replace(/^#/, "") || "/";
  const m = clean.match(/^\/machines\/([^/?#]+)/);
  if (m) return { page: "machine", id: decodeURIComponent(m[1]) };
  if (clean.startsWith("/apps")) return { page: "apps" };
  if (clean.startsWith("/network")) return { page: "network" };
  if (clean.startsWith("/access")) return { page: "access" };
  if (clean.startsWith("/audit")) return { page: "audit" };
  return { page: "machines" };
}

function useHash(): ParsedRoute {
  const [route, setRoute] = useState<ParsedRoute>(() => parseHash(location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseHash(location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

function fmtGb(mb: number): string {
  return `${(mb / 1024).toFixed(1)} GB`;
}
function fmtRate(bps: number): string {
  if (bps >= 1024 * 1024) return `${(bps / (1024 * 1024)).toFixed(1)} MB/s`;
  if (bps >= 1024) return `${(bps / 1024).toFixed(0)} KB/s`;
  return `${bps} B/s`;
}
function fmtUptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}
function fmtAgo(ts?: number): string {
  if (!ts) return "Never";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (diff < 60) return "Just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
function meterFillClass(pct: number): string {
  return pct >= 95 ? "m-fill crit" : pct >= 80 ? "m-fill warn" : "m-fill";
}

function legacyCopy(value: string): boolean {
  try {
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "0";
    ta.style.left = "-9999px";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, value.length);
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function copyTextToClipboard(value: string): Promise<boolean> {
  if (!window.isSecureContext || !navigator.clipboard?.writeText) {
    return Promise.resolve(legacyCopy(value));
  }
  return navigator.clipboard
    .writeText(value)
    .then(() => true)
    .catch(() => legacyCopy(value));
}

function Help({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  function close() {
    setOpen(false);
    trigger.current?.focus();
  }
  return (
    <>
      <button ref={trigger} type="button" className="help-btn" aria-label={`About ${title}`} onClick={() => setOpen(true)}>?</button>
      {open && (
        <div className="backdrop" onClick={close}>
          <div className="modal" role="dialog" aria-label={title} onClick={(e) => e.stopPropagation()} onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.stopPropagation();
              close();
            }
          }}>
            <div className="card-head">
              <h2 className="card-title">{title}</h2>
              <button type="button" className="btn btn-sm" aria-label="Close help" autoFocus onClick={close}>✕</button>
            </div>
            <div className="card-pad help-body">{children}</div>
          </div>
        </div>
      )}
    </>
  );
}

type SecretRow = { name: string; nodeIds: string[]; updatedAt: number };

function SecretsCard({ nodes }: { nodes: Node[] }) {
  const [rows, setRows] = useState<SecretRow[]>([]);
  const [editing, setEditing] = useState<{ isNew: boolean; name: string; value: string; nodeIds: string[] } | null>(null);
  const [err, setErr] = useState("");
  const load = () =>
    fetch("/api/v1/secrets")
      .then((r) => (r.ok ? r.json() : []))
      .then(setRows)
      .catch(() => {});
  useEffect(() => {
    load();
  }, []);
  const nodeName = (id: string) => nodes.find((n) => n.id === id)?.name ?? id;

  async function save(e: React.FormEvent) {
    e.preventDefault();
    if (!editing) return;
    setErr("");
    const r = await fetch(`/api/v1/secrets/${encodeURIComponent(editing.name.trim())}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value: editing.value || null, nodeIds: editing.nodeIds }),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      setErr(d.error ?? `couldn't save (${r.status})`);
      return;
    }
    setEditing(null);
    load();
  }

  async function remove(name: string) {
    if (!confirm(`Delete ${name}? It's removed from every machine on their next check-in.`)) return;
    await fetch(`/api/v1/secrets/${encodeURIComponent(name)}`, { method: "DELETE" });
    load();
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2 className="card-title">
          Secrets
          <Help title="Secrets">
            <p>Set an environment variable once and Rackdeck puts it on the machines you pick. A common one is <span className="mono">CLAUDE_CODE_OAUTH_TOKEN</span> from <span className="mono">claude setup-token</span>, so you don't log in on every machine.</p>
            <p>Values are encrypted in the dashboard and on the way to each machine. They land in <span className="mono">~/.config/rackdeck/secrets.env</span>, readable only by you, and new terminals load them.</p>
            <p>Machines that joined before this feature get secrets after their next update.</p>
          </Help>
        </h2>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => {
            setErr("");
            setEditing({ isNew: true, name: "", value: "", nodeIds: nodes.map((n) => n.id) });
          }}
        >
          + Add secret
        </button>
      </div>
      {rows.length === 0 ? (
        <p className="card-pad" style={{ margin: 0, fontSize: 13, color: "var(--text-2)" }}>No secrets yet.</p>
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Name</th>
                <th>Machines</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name}>
                  <td className="mono">{r.name}</td>
                  <td>{r.nodeIds.length ? r.nodeIds.map(nodeName).join(", ") : "None"}</td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => {
                        setErr("");
                        setEditing({ isNew: false, name: r.name, value: "", nodeIds: r.nodeIds });
                      }}
                    >
                      Edit
                    </button>{" "}
                    <button type="button" className="btn btn-sm" onClick={() => remove(r.name)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing && (
        <div className="backdrop" onClick={() => setEditing(null)}>
          <form className="modal" onSubmit={save} onClick={(e) => e.stopPropagation()}>
            <div className="card-head">
              <h2 className="card-title">{editing.isNew ? "Add secret" : `Edit ${editing.name}`}</h2>
              <button type="button" className="btn btn-sm" onClick={() => setEditing(null)}>✕</button>
            </div>
            <div className="card-pad">
              {editing.isNew && (
                <div className="field" style={{ marginBottom: 12 }}>
                  <label htmlFor="secret-name">Name</label>
                  <input
                    id="secret-name"
                    className="input mono"
                    placeholder="CLAUDE_CODE_OAUTH_TOKEN"
                    value={editing.name}
                    onChange={(e) => setEditing({ ...editing, name: e.target.value.toUpperCase() })}
                    required
                    autoFocus
                  />
                </div>
              )}
              <div className="field" style={{ marginBottom: 12 }}>
                <label htmlFor="secret-value">Value</label>
                <input
                  id="secret-value"
                  className="input mono"
                  type="password"
                  autoComplete="off"
                  placeholder={editing.isNew ? "" : "Leave blank to keep the current value"}
                  value={editing.value}
                  onChange={(e) => setEditing({ ...editing, value: e.target.value })}
                  required={editing.isNew}
                />
              </div>
              <fieldset className="field" style={{ border: 0, padding: 0, margin: "0 0 12px" }}>
                <legend style={{ fontSize: 12.5, marginBottom: 6 }}>Machines</legend>
                {nodes.map((n) => (
                  <label key={n.id} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13, marginBottom: 4 }}>
                    <input
                      type="checkbox"
                      checked={editing.nodeIds.includes(n.id)}
                      onChange={(e) =>
                        setEditing({
                          ...editing,
                          nodeIds: e.target.checked ? [...editing.nodeIds, n.id] : editing.nodeIds.filter((x) => x !== n.id),
                        })
                      }
                    />
                    {n.name}
                  </label>
                ))}
              </fieldset>
              {err && <p role="alert" style={{ color: "var(--crit)", fontSize: 13, margin: "0 0 12px" }}>{err}</p>}
              <button type="submit" className="btn btn-primary">Save</button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}

function Copy({ value, display, className }: { value: string; display?: string; className?: string }) {
  const [status, setStatus] = useState<"idle" | "ok" | "err">("idle");
  return (
    <button
      type="button"
      className={`copy-btn ${className ?? ""}`}
      title={`Copy ${value}`}
      onClick={(e) => {
        e.stopPropagation();
        void copyTextToClipboard(value).then((ok) => {
          setStatus(ok ? "ok" : "err");
          window.setTimeout(() => setStatus("idle"), 1500);
        });
      }}
    >
      <span>{display ?? value}</span>
      {status === "ok" ? (
        <span className="copy-ok">✓ Copied</span>
      ) : status === "err" ? (
        <span className="copy-ok" style={{ color: "var(--crit)" }}>Select &amp; ⌘C</span>
      ) : (
        <span className="copy-ico" aria-hidden="true">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
        </span>
      )}
    </button>
  );
}

function CommandSnippet({ command }: { command: string }) {
  return (
    <div className="snippet-box command-snippet">
      <pre>{command}</pre>
      <Copy value={command} display="Copy" />
    </div>
  );
}

function Sparkline({
  values,
  secondary,
  warnAt = 80,
}: {
  values: number[];
  secondary?: number[];
  warnAt?: number;
}) {
  const buildPts = (arr: number[], maxVal: number) => {
    const data = arr.length > 1 ? arr : [0, arr[0] ?? 0];
    return data
      .map((v, i) => {
        const x = (i / Math.max(1, data.length - 1)) * 140;
        const y = 26 - (Math.min(v, maxVal) / Math.max(1, maxVal)) * 24;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  };

  const maxVal = secondary
    ? Math.max(1024, ...values, ...secondary)
    : Math.max(100, ...values);
  const latest = values[values.length - 1] ?? 0;
  const stroke =
    !secondary && latest >= 95
      ? "var(--crit)"
      : !secondary && latest >= warnAt
      ? "var(--warn)"
      : "var(--spark-stroke)";

  return (
    <svg width="100%" height="28" viewBox="0 0 140 28" preserveAspectRatio="none" aria-hidden="true">
      <polyline fill="none" stroke={stroke} strokeWidth="1.5" points={buildPts(values, maxVal)} />
      {secondary && (
        <polyline
          fill="none"
          stroke="var(--accent)"
          strokeOpacity="0.65"
          strokeWidth="1.5"
          points={buildPts(secondary, maxVal)}
        />
      )}
    </svg>
  );
}

function QrSvg({ uri }: { uri: string }) {
  const [svg, setSvg] = useState<string>("");
  useEffect(() => {
    QRCode.toString(uri, { type: "svg", margin: 0, color: { dark: "#18181B", light: "#FFFFFF" } })
      .then(setSvg)
      .catch(() => setSvg(""));
  }, [uri]);
  return <div className="qr-box" dangerouslySetInnerHTML={{ __html: svg }} />;
}

/** "0.2.0" < "0.2.1"; non-numeric parts count as 0. */
function isOlderVersion(a: string, b: string): boolean {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0);
  }
  return false;
}

function dockerRunPreview(name: string, image: string, hostPort: string, contPort: string, envText: string): string {
  const parts = ["docker run -d", `--name ${name.trim() || "<app-name>"}`, "--restart unless-stopped"];
  if (hostPort.trim() && contPort.trim()) parts.push(`-p ${hostPort.trim()}:${contPort.trim()}`);
  for (const line of envText.split("\n")) {
    const idx = line.indexOf("=");
    if (idx > 0) parts.push(`-e ${line.slice(0, idx).trim()}=${line.slice(idx + 1).trim()}`);
  }
  parts.push(image.trim());
  return parts.join(" \\\n  ");
}

const IS_DEMO = import.meta.env.MODE === "demo";
const INSTALL_COMMAND = "curl -fsSL https://get.rackdeck.dev | sh";
const JOIN_REQUESTS_URL = "/api/v1/join-requests";

export function App() {
  const route = useHash();
  const [demoBannerDismissed, setDemoBannerDismissed] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const saved = localStorage.getItem("rackdeck.theme");
    if (saved === "light" || saved === "dark") return saved;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("rackdeck.theme", theme);
  }, [theme]);

  const [nodes, setNodes] = useState<Node[]>([]);
  const [apps, setApps] = useState<ManagedApp[]>([]);
  const [samples, setSamples] = useState<Record<string, TelemetrySample[]>>({});
  const [connState, setConnState] = useState<"live" | "reconnecting" | "offline">("reconnecting");
  const [rttMs, setRttMs] = useState<number | null>(null);
  // Latest published Rackdeck release, and per-machine update progress/errors.
  const [latestVersion, setLatestVersion] = useState<string | null>(null);
  const [updateMsg, setUpdateMsg] = useState<Record<string, string>>({});
  // Which node is this controller, and is it password-protected (no password = localhost only).
  const [controller, setController] = useState<{ nodeId: string | null; passwordSet: boolean; relayConfigured?: boolean }>({
    nodeId: null,
    passwordSet: true,
  });
  const [connectHealth, setConnectHealth] = useState<{ enabled: boolean; active: boolean }>({
    enabled: false,
    active: false,
  });

  // Filters & pending states
  const [machineQuery, setMachineQuery] = useState("");
  const [machineStatusFilter, setMachineStatusFilter] = useState<"all" | "online" | "offline">("all");
  const [appFilter, setAppFilter] = useState<"all" | "docker" | "ai">("all");
  const [pendingApp, setPendingApp] = useState<Record<string, string>>({});
  const [inlineErr, setInlineErr] = useState<string | null>(null);
  const [appMessage, setAppMessage] = useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = useState<ManagedApp | null>(null);
  const removeDialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (removeTarget && removeDialog.current && !removeDialog.current.open) {
      removeDialog.current.showModal();
    }
  }, [removeTarget]);

  // Auth gate (when server sets RACKDECK_PASSWORD)
  const [authState, setAuthState] = useState<{ checked: boolean; required: boolean; authed: boolean }>({
    checked: false,
    required: false,
    authed: true,
  });
  const [loginPass, setLoginPass] = useState("");
  const [loginErr, setLoginErr] = useState<string | null>(null);

  // Deploy app drawer
  const [deployOpen, setDeployOpen] = useState(false);
  const [deployNodeId, setDeployNodeId] = useState("");
  const [depName, setDepName] = useState("");
  const [depImage, setDepImage] = useState("");
  const [depHostPort, setDepHostPort] = useState("");
  const [depContPort, setDepContPort] = useState("");
  const [depEnvText, setDepEnvText] = useState("");
  const [depBusy, setDepBusy] = useState(false);
  const [depErr, setDepErr] = useState<string | null>(null);

  // Logs & Terminal bottom drawer
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState<"logs" | "terminal">("logs");
  const [drawerApp, setDrawerApp] = useState<ManagedApp | null>(null);
  const [activeLogSub, setActiveLogSub] = useState<string | null>(null);
  const [logEntries, setLogEntries] = useState<Array<[number, string, string]>>([]);
  const [logFilter, setLogFilter] = useState("");
  const [logFollow, setLogFollow] = useState(true);
  const [termLines, setTermLines] = useState<string[]>(["Rackdeck interactive shell — type a command and press Enter."]);
  const [termCmd, setTermCmd] = useState("");
  const logsPreRef = useRef<HTMLPreElement | null>(null);

  // Network & Connect
  const [peers, setPeers] = useState<DiscoveredPeer[]>([]);
  const [scanning, setScanning] = useState(false);
  const [routes, setRoutes] = useState<ConnectRoute[]>([]);
  const [addingRoute, setAddingRoute] = useState(false);
  const [routeHost, setRouteHost] = useState("");
  const [routePort, setRoutePort] = useState("8080");
  const [routeTarget, setRouteTarget] = useState("");
  const [confirmDeleteRoute, setConfirmDeleteRoute] = useState<string | null>(null);
  const [connectSlugInput, setConnectSlugInput] = useState("");

  // Access & Audit
  const [tokens, setTokens] = useState<AccessTokenRecord[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [newAuditIds, setNewAuditIds] = useState<Set<string>>(new Set());
  const [assistantDrawerOpen, setAssistantDrawerOpen] = useState(false);
  const [assistantClient, setAssistantClient] = useState<Assistant>("Claude Code");
  const [assistantScope, setAssistantScope] = useState<"read" | "deploy">("read");
  const [assistantResult, setAssistantResult] = useState<AssistantSetup | null>(null);
  const [assistantBusy, setAssistantBusy] = useState(false);
  const [assistantError, setAssistantError] = useState("");
  const [disconnecting, setDisconnecting] = useState("");
  const [assistantsError, setAssistantsError] = useState("");

  const [joinRequests, setJoinRequests] = useState<JoinRequest[]>([]);
  const [joinRefresh, setJoinRefresh] = useState(0);
  const [joinLoadError, setJoinLoadError] = useState(false);
  const [joinActionError, setJoinActionError] = useState("");
  const [joinPending, setJoinPending] = useState(false);

  // Add machine dialog
  const [addMachineOpen, setAddMachineOpen] = useState(false);
  const [differentNetworkOpen, setDifferentNetworkOpen] = useState(false);
  const [joinCmd, setJoinCmd] = useState<string>("");
  const [joinCmdError, setJoinCmdError] = useState(false);
  const [joinCmdAttempt, setJoinCmdAttempt] = useState(0);
  const [pairOpen, setPairOpen] = useState(false);
  const [pairInvite, setPairInvite] = useState<PairingInvitation | null>(null);
  const [pairError, setPairError] = useState(false);
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));

  // ⌘K palette
  const [cmdOpen, setCmdOpen] = useState(false);
  const [cmdQuery, setCmdQuery] = useState("");
  const [cmdSel, setCmdSel] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const pingSentAt = useRef<number>(0);

  useEffect(() => {
    fetch("/api/v1/auth/status")
      .then((r) => r.json())
      .then((d) =>
        setAuthState({
          checked: true,
          required: Boolean(d.passwordRequired),
          authed: Boolean(d.authenticated),
        })
      )
      .catch(() => setAuthState({ checked: true, required: false, authed: true }));
  }, []);

  // Multiplexed WebSocket with immediate RTT ping on open
  useEffect(() => {
    if (!authState.checked || !authState.authed) return;
    let closed = false;
    let retryTimer: number | undefined;
    let pingTimer: number | undefined;

    function sendPing(ws: WebSocket) {
      if (ws.readyState === WebSocket.OPEN) {
        pingSentAt.current = performance.now();
        ws.send(JSON.stringify({ t: "ping", id: Date.now() }));
      }
    }

    function connect() {
      if (closed) return;
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${proto}//${location.host}/api/ws`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnState("live");
        sendPing(ws);
        pingTimer = window.setInterval(() => sendPing(ws), 5000);
      };

      ws.onmessage = (ev) => {
        const msg = JSON.parse(String(ev.data));
        if (msg.t === "snapshot") {
          setNodes(msg.nodes);
          setApps(msg.apps);
        } else if (msg.t === "node") {
          setNodes((prev) => {
            const exists = prev.some((n) => n.id === msg.node.id);
            return exists
              ? prev.map((n) => (n.id === msg.node.id ? msg.node : n))
              : [...prev, msg.node];
          });
        } else if (msg.t === "apps") {
          setApps(msg.apps);
        } else if (msg.t === "tm") {
          setSamples((prev) => {
            const list = prev[msg.nodeId] ?? [];
            return { ...prev, [msg.nodeId]: [...list.slice(-59), msg.s] };
          });
        } else if (msg.t === "pong") {
          setRttMs(Math.max(1, Math.round(performance.now() - pingSentAt.current)));
        } else if (msg.t === "log") {
          setLogEntries((prev) => [...prev.slice(-400), ...msg.lines]);
        } else if (msg.t === "term_out") {
          setTermLines((prev) => [...prev.slice(-300), msg.text]);
        } else if (msg.t === "audit") {
          const item = msg.ev as AuditEvent;
          setAudit((prev) => [item, ...prev.slice(0, 199)]);
          setNewAuditIds((prev) => new Set(prev).add(item.id));
          window.setTimeout(() => {
            setNewAuditIds((prev) => {
              const next = new Set(prev);
              next.delete(item.id);
              return next;
            });
          }, 650);
        }
      };

      ws.onclose = () => {
        window.clearInterval(pingTimer);
        if (closed) return;
        setConnState("reconnecting");
        // A restart or logout ends the session; show the login screen instead of retrying forever.
        fetch("/api/v1/auth/status")
          .then((r) => r.json())
          .then((d) => {
            if (d.passwordRequired && !d.authenticated) {
              setAuthState({ checked: true, required: true, authed: false });
            } else {
              retryTimer = window.setTimeout(connect, 2000);
            }
          })
          .catch(() => {
            retryTimer = window.setTimeout(connect, 2000);
          });
      };
    }

    connect();
    return () => {
      closed = true;
      window.clearInterval(pingTimer);
      window.clearTimeout(retryTimer);
      wsRef.current?.close();
    };
  }, [authState.checked, authState.authed]);

  useEffect(() => {
    if (!authState.checked || !authState.authed) return;
    const controller = new AbortController();
    let loading = false;
    async function refresh() {
      if (loading) return;
      loading = true;
      try {
        const res = await fetch(JOIN_REQUESTS_URL, { signal: controller.signal });
        if (!res.ok) throw new Error();
        const data: { requests: JoinRequest[] } = await res.json();
        if (controller.signal.aborted) return;
        setJoinRequests(data.requests);
        setJoinLoadError(false);
      } catch {
        if (!controller.signal.aborted) setJoinLoadError(true);
      } finally {
        loading = false;
      }
    }
    void refresh();
    const id = window.setInterval(refresh, 3000);
    return () => {
      controller.abort();
      window.clearInterval(id);
    };
  }, [authState.checked, authState.authed, joinRefresh]);

  useEffect(() => {
    fetch("https://api.github.com/repos/ctsoftwarellc/rackdeck/releases/latest")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d?.tag_name && setLatestVersion(String(d.tag_name).replace(/^v/, "")))
      .catch(() => {});
  }, []);

  // Poll real Connect tunnel status cleanly
  useEffect(() => {
    const check = () => {
      fetch("/api/v1/health")
        .then((r) => r.json())
        .then((d) => {
          setConnectHealth({ enabled: Boolean(d.connectEnabled), active: Boolean(d.connectActive) });
          setController({ nodeId: d.nodeId ?? null, passwordSet: Boolean(d.passwordSet), relayConfigured: Boolean(d.relayConfigured) });
        })
        .catch(() => {});
    };
    check();
    const id = window.setInterval(check, 4000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (!addMachineOpen || !differentNetworkOpen) return;
    const request = new AbortController();
    setJoinCmd("");
    setJoinCmdError(false);
    fetch("/api/v1/join-token", { method: "POST", signal: request.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error();
        const data = await res.json();
        if (!request.signal.aborted) setJoinCmd(data.command);
      })
      .catch(() => {
        if (!request.signal.aborted) setJoinCmdError(true);
      });
    return () => request.abort();
  }, [addMachineOpen, differentNetworkOpen, joinCmdAttempt]);

  // Live countdown while the QR code is visible
  useEffect(() => {
    if (!pairOpen || !pairInvite) return;
    setNowSec(Math.floor(Date.now() / 1000));
    const id = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 250);
    return () => window.clearInterval(id);
  }, [pairOpen, pairInvite]);

  // Auto-scroll logs when Follow is on
  useEffect(() => {
    if (logFollow && logsPreRef.current) {
      logsPreRef.current.scrollTop = logsPreRef.current.scrollHeight;
    }
  }, [logEntries, logFollow]);

  // Load route-specific data & auto-scan Tailnet on /network
  useEffect(() => {
    if (route.page === "network") {
      fetch("/api/v1/connect/routes")
        .then((r) => r.json())
        .then((d) => setRoutes(d.routes ?? []))
        .catch(() => {});
      runScan();
    } else if (route.page === "access" || route.page === "audit") {
      if (route.page === "access") {
        setAssistantsError("");
        fetch("/api/v1/tokens")
          .then((res) => {
            if (!res.ok) throw new Error();
            return res.json();
          })
          .then((data) => setTokens(data.tokens ?? []))
          .catch(() => setAssistantsError("Could not load connected assistants."));
      }
      fetch("/api/v1/audit")
        .then((r) => r.json())
        .then((d) => setAudit(d.events ?? []))
        .catch(() => {});
    }
  }, [route.page]);

  // Global keyboard shortcuts
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdOpen((v) => !v);
        setCmdSel(0);
      } else if (e.key === "Escape") {
        setCmdOpen(false);
        setAddMachineOpen(false);
        setPairOpen(false);
        setDeployOpen(false);
        closeDrawer();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  async function runScan() {
    setScanning(true);
    try {
      const res = await fetch("/api/v1/discovery/scan", { method: "POST" });
      const data = await res.json();
      setPeers(data.peers ?? []);
    } finally {
      setScanning(false);
    }
  }

  async function resolveJoinRequest(request: JoinRequest, method: "POST" | "DELETE") {
    setJoinPending(true);
    setJoinActionError("");
    const failure = `Could not ${method === "POST" ? "allow" : "ignore"} ${request.name}.`;
    try {
      const res = await fetch(`${JOIN_REQUESTS_URL}/${encodeURIComponent(request.key)}`, { method });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        setJoinActionError(data?.error ? `${failure} ${data.error}` : failure);
      }
    } catch {
      setJoinActionError(failure);
    } finally {
      setJoinPending(false);
      setJoinRefresh((version) => version + 1);
    }
  }

  async function loadPairInvite() {
    setPairOpen(true);
    setPairInvite(null);
    setPairError(false);
    try {
      const res = await fetch("/api/v1/pair", { method: "POST" });
      if (!res.ok) throw new Error();
      setNowSec(Math.floor(Date.now() / 1000));
      setPairInvite(await res.json());
    } catch {
      setPairError(true);
    }
  }

  function openAddMachine() {
    setDifferentNetworkOpen(false);
    setJoinCmd("");
    setJoinCmdError(false);
    setAddMachineOpen(true);
  }

  // Rackdeck account (hosted Connect): is this dashboard linked, and the pending link code if signing in.
  const [account, setAccount] = useState<{ linked: boolean; active: boolean; slugs: string[]; accountUrl?: string } | null>(null);
  const [accountErr, setAccountErr] = useState<string | null>(null);
  const [linkReq, setLinkReq] = useState<{ userCode: string; url: string; pollToken: string } | null>(null);

  function loadAccount() {
    fetch("/api/v1/account")
      .then(async (r) => {
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.error ?? "couldn't check your account");
        setAccount(d);
        setAccountErr(null);
      })
      .catch((e) => setAccountErr(e.message));
  }

  useEffect(() => {
    if (route.page === "network") loadAccount();
  }, [route.page]);

  async function startAccountLink(node: Node) {
    const slug = (connectSlugInput.trim() || node.connectSlug || node.name)
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32);
    setAccountErr(null);
    const r = await fetch("/api/v1/account/link", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ slug }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) return setAccountErr(d.error ?? "couldn't start sign-in");
    setLinkReq(d);
    window.open(d.url, "_blank", "noopener");
  }

  // Poll the relay until the code is approved or expires.
  useEffect(() => {
    if (!linkReq) return;
    const id = window.setInterval(async () => {
      const r = await fetch("/api/v1/account/link/poll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ pollToken: linkReq.pollToken }),
      });
      const d = await r.json().catch(() => ({}));
      if (d.status === "linked") {
        setLinkReq(null);
        loadAccount();
      } else if (d.status === "expired" || !r.ok) {
        setLinkReq(null);
        setAccountErr(d.error ?? "The sign-in code expired. Try again.");
      }
    }, 2000);
    return () => window.clearInterval(id);
  }, [linkReq]);

  async function toggleConnect(node: Node) {
    const slug = (connectSlugInput.trim() || node.connectSlug || node.name).toLowerCase();
    const res = await fetch("/api/v1/connect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: !node.connectEnabled, slug }),
    });
    const data = await res.json();
    if (data.node) {
      setNodes((prev) => prev.map((n) => (n.id === data.node.id ? data.node : n)));
      setConnectHealth((prev) => ({ ...prev, enabled: data.node.connectEnabled }));
    }
  }



  async function saveNewRoute(e: React.FormEvent) {
    e.preventDefault();
    const host = routeHost.trim();
    if (!host) return;
    const [nodeId, targetApp] = routeTarget.includes("::")
      ? routeTarget.split("::")
      : [nodes[0]?.id ?? "", "rackdeck"];
    const res = await fetch("/api/v1/connect/routes", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ host, nodeId, targetApp, targetPort: Number(routePort) || 8080 }),
    });
    const data = await res.json();
    if (data.route) {
      setRoutes((prev) => [data.route, ...prev]);
      setAddingRoute(false);
      setRouteHost("");
    }
  }

  async function deleteRoute(id: string) {
    await fetch(`/api/v1/connect/routes/${id}`, { method: "DELETE" });
    setRoutes((prev) => prev.filter((r) => r.id !== id));
    setConfirmDeleteRoute(null);
  }

  function openAssistantDrawer() {
    setAssistantClient("Claude Code");
    setAssistantScope("read");
    setAssistantResult(null);
    setAssistantError("");
    setAssistantDrawerOpen(true);
  }

  function closeAssistantDrawer() {
    if (assistantBusy) return;
    setAssistantResult(null);
    setAssistantDrawerOpen(false);
  }

  async function connectAssistant(e: React.FormEvent) {
    e.preventDefault();
    if (assistantBusy) return;
    setAssistantBusy(true);
    setAssistantError("");
    const date = new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" });
    const name = assistantClient + " · " + date;
    try {
      const res = await fetch("/api/v1/tokens", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, client: assistantClient, scope: assistantScope, expiresInDays: 90 }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setTokens((prev) => [data.record, ...prev.filter((token) => token.id !== data.record.id)]);
      setAssistantResult(assistantSetup(assistantClient, location.origin, data.record.id, data.token));
    } catch (error) {
      setAssistantError(error instanceof Error && error.message ? error.message : "Could not connect the assistant.");
    } finally {
      setAssistantBusy(false);
    }
  }

  async function disconnectAssistant(token: AccessTokenRecord) {
    setDisconnecting(token.id);
    setAssistantsError("");
    try {
      const res = await fetch("/api/v1/tokens/" + encodeURIComponent(token.id), { method: "DELETE" });
      if (!res.ok) throw new Error();
      setTokens((prev) => prev.filter((item) => item.id !== token.id));
    } catch {
      setAssistantsError("Could not disconnect " + token.name + ".");
    } finally {
      setDisconnecting("");
    }
  }

  async function runAppAction(app: ManagedApp, action: keyof typeof appActionProgress, deleteData = false) {
    const key = appKey(app);
    setInlineErr(null);
    setAppMessage(null);
    setPendingApp((prev) => ({ ...prev, [key]: appActionProgress[action] }));
    try {
      const query = deleteData ? "?deleteData=true" : "";
      const url = `/api/v1/nodes/${encodeURIComponent(app.nodeId)}/apps/${encodeURIComponent(app.id)}/${action}${query}`;
      const res = await fetch(url, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? "App action failed.");
      if (action === "remove") {
        setApps((prev) => prev.filter((item) => item.nodeId !== app.nodeId || item.id !== app.id));
      }
      setAppMessage(data.message ?? (action === "remove" ? "App removed." : null));
    } catch (e) {
      setInlineErr(e instanceof Error ? e.message : "App action failed.");
    } finally {
      setPendingApp((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    }
  }

  function renderAppControls(app: ManagedApp, withLogs = false) {
    const busy = Boolean(pendingApp[appKey(app)]);
    const updateReason = app.canUpdate === undefined
      ? "Update Rackdeck on this machine first."
      : "This app has no saved Rackdeck install settings.";
    return (
      <div className="app-controls">
        {app.type !== "system" && (app.state === "running" ? (
          <>
            <button type="button" className="btn btn-sm" disabled={busy} onClick={() => runAppAction(app, "restart")}>Restart</button>
            <button type="button" className="btn btn-sm btn-danger" disabled={busy} onClick={() => runAppAction(app, "stop")}>Stop</button>
          </>
        ) : (
          <button type="button" className="btn btn-sm" disabled={busy} onClick={() => runAppAction(app, "start")}>Start</button>
        ))}
        {app.type === "docker" && (
          <>
            <span title={app.canUpdate ? undefined : updateReason} tabIndex={app.canUpdate ? undefined : 0}>
              <button type="button" className="btn btn-sm" disabled={busy || !app.canUpdate}
                onClick={() => runAppAction(app, "update")}>Update</button>
            </span>
            <button type="button" className="btn btn-sm btn-danger" disabled={busy} onClick={() => setRemoveTarget(app)}>Remove</button>
          </>
        )}
        {withLogs && <button type="button" className="btn btn-sm" disabled={busy} onClick={() => openLogs(app)}>Logs</button>}
      </div>
    );
  }

  function renderAppFeedback(nodeId?: string) {
    const updating = Object.entries(pendingApp).some(([key, progress]) =>
      progress === appActionProgress.update && (!nodeId || key.startsWith(nodeId + "/")));
    return (
      <>
        {inlineErr && <div className="inline-err" role="alert">{inlineErr}</div>}
        {(updating || appMessage) && (
          <p className="app-feedback" role="status">{updating ? "Updating… this can take a few minutes" : appMessage}</p>
        )}
      </>
    );
  }

  async function submitLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoginErr(null);
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: loginPass }),
    });
    if (res.ok) {
      setAuthState({ checked: true, required: true, authed: true });
      setLoginPass("");
    } else {
      setLoginErr("Invalid password");
    }
  }

  function openCustomImage(nodeId = "") {
    setDeployNodeId(nodeId);
    setDepErr(null);
    setDeployOpen(true);
  }

  function addInstalledApp(app: ManagedApp) {
    setApps((prev) => [...prev.filter((item) => item.nodeId !== app.nodeId || item.id !== app.id), app]);
  }

  async function submitDeploy(e: React.FormEvent) {
    e.preventDefault();
    if (depBusy || !deployNode || deployNode.status !== "online" || deployNode.docker !== "running" || !depName.trim() || !depImage.trim()) return;
    setDepBusy(true);
    setDepErr(null);
    const env: Record<string, string> = {};
    for (const line of depEnvText.split("\n")) {
      const idx = line.indexOf("=");
      if (idx > 0) env[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
    try {
      const res = await fetch(`/api/v1/nodes/${encodeURIComponent(deployNode.id)}/deploy`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: depName.trim(),
          image: depImage.trim(),
          hostPort: depHostPort ? Number(depHostPort) : undefined,
          containerPort: depContPort ? Number(depContPort) : undefined,
          env,
        }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({ error: "Deploy failed" }));
        setDepErr(d.error ?? "Deploy failed");
      } else {
        setDeployOpen(false);
        setDepName("");
        setDepImage("");
        setDepHostPort("");
        setDepContPort("");
        setDepEnvText("");
      }
    } catch {
      setDepErr("Could not reach the dashboard. Check the Apps page before trying again.");
    } finally {
      setDepBusy(false);
    }
  }

  function closeDrawer() {
    if (activeLogSub && wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ t: "unsub", sub: activeLogSub }));
    }
    setActiveLogSub(null);
    setDrawerOpen(false);
    setDrawerApp(null);
  }

  function openLogs(app: ManagedApp) {
    if (activeLogSub && wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ t: "unsub", sub: activeLogSub }));
    }
    const sub = `log-${Date.now()}`;
    setDrawerApp(app);
    setDrawerTab("logs");
    setDrawerOpen(true);
    setActiveLogSub(sub);
    setLogEntries([]);
    setLogFollow(true);
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({ t: "sub", ch: "logs", sub, nodeId: app.nodeId, appId: app.id })
      );
    }
  }

  function runTerminalCmd(e: React.FormEvent) {
    e.preventDefault();
    const cmd = termCmd.trim();
    if (!cmd) return;
    setTermLines((prev) => [...prev.slice(-300), `$ ${cmd}`]);
    setTermCmd("");
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ t: "term_exec", sub: "term-1", cmd }));
    }
  }

  // Filtered machines
  const filteredNodes = useMemo(() => {
    const q = machineQuery.trim().toLowerCase();
    return nodes.filter((n) => {
      if (machineStatusFilter === "online" && n.status !== "online") return false;
      if (machineStatusFilter === "offline" && n.status === "online") return false;
      if (!q) return true;
      return (
        n.name.toLowerCase().includes(q) ||
        n.os.toLowerCase().includes(q) ||
        (n.lanIp ?? "").includes(q) ||
        (n.tailscaleIp ?? "").includes(q)
      );
    });
  }, [nodes, machineQuery, machineStatusFilter]);

  const behind = (n: Node) => Boolean(latestVersion && n.status === "online" && isOlderVersion(n.version, latestVersion));
  const behindNodes = nodes.filter(behind);

  async function updateNode(n: Node) {
    const isController = n.id === primaryNode?.id;
    setUpdateMsg((m) => ({ ...m, [n.id]: "Updating…" }));
    try {
      const r = await fetch(`/api/v1/nodes/${encodeURIComponent(n.id)}/update`, { method: "POST" });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error ?? `update failed (${r.status})`);
      if (!d.updatedTo) {
        setUpdateMsg((m) => ({ ...m, [n.id]: "Already up to date" }));
      } else if (isController) {
        setUpdateMsg((m) => ({ ...m, [n.id]: `Updated to ${d.updatedTo}, restarting…` }));
        window.setTimeout(() => location.reload(), 5000);
      } else {
        setUpdateMsg((m) => ({ ...m, [n.id]: `Updated to ${d.updatedTo}` }));
      }
    } catch (e) {
      setUpdateMsg((m) => ({ ...m, [n.id]: e instanceof Error ? e.message : String(e) }));
    }
  }

  async function removeNode(n: Node) {
    if (!confirm(`Remove ${n.name}? It disappears from the dashboard and its agent can't check in again. To add it back, use + Add machine.`)) return;
    const r = await fetch(`/api/v1/nodes/${encodeURIComponent(n.id)}`, { method: "DELETE" });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      setUpdateMsg((m) => ({ ...m, [n.id]: d.error ?? `remove failed (${r.status})` }));
      return;
    }
    setNodes((prev) => prev.filter((x) => x.id !== n.id));
    location.hash = "#/";
  }

  // Joined machines first; the controller restarts itself, so it goes last.
  async function updateAll() {
    const remotes = behindNodes.filter((n) => n.id !== primaryNode?.id);
    await Promise.all(remotes.map(updateNode));
    const self = behindNodes.find((n) => n.id === primaryNode?.id);
    if (self) await updateNode(self);
  }

  const primaryNode = nodes.find((n) => n.id === controller.nodeId) ?? nodes[0] ?? null;
  const detailNode =
    route.page === "machine"
      ? nodes.find((n) => n.id === route.id) ?? primaryNode
      : primaryNode;
  const deployNode = nodes.find((node) => node.id === deployNodeId) ?? (nodes.length === 1 ? nodes[0] : undefined);
  const detailSamples = detailNode ? samples[detailNode.id] ?? [] : [];
  const latestSample = detailSamples[detailSamples.length - 1];

  // ⌘K Palette items (dynamic: Navigate + Machines + Services + Actions)
  const paletteItems = useMemo(() => {
    const q = cmdQuery.trim().toLowerCase();
    const list: Array<{ group: string; label: string; meta?: string; run: () => void }> = [];
    const navs = [
      { label: "Machines", meta: "#/", run: () => { location.hash = "#/"; } },
      { label: "Apps", meta: "#/apps", run: () => { location.hash = "#/apps"; } },
      { label: "Network & Connect", meta: "#/network", run: () => { location.hash = "#/network"; } },
      { label: "Access Controls", meta: "#/access", run: () => { location.hash = "#/access"; } },
      { label: "Audit", meta: "#/audit", run: () => { location.hash = "#/audit"; } },
    ];
    navs
      .filter((x) => !q || x.label.toLowerCase().includes(q))
      .slice(0, 8)
      .forEach((x) => list.push({ group: "Navigate", ...x }));

    nodes
      .filter((n) => !q || n.name.toLowerCase().includes(q) || (n.lanIp ?? "").includes(q))
      .slice(0, 8)
      .forEach((n) =>
        list.push({
          group: "Machines",
          label: n.name,
          meta: n.lanIp ?? n.tailscaleIp ?? n.kind,
          run: () => { location.hash = `#/machines/${encodeURIComponent(n.id)}`; },
        })
      );

    apps
      .filter((a) => !q || a.name.toLowerCase().includes(q))
      .slice(0, 8)
      .forEach((a) => {
        const hostName = nodes.find((n) => n.id === a.nodeId)?.name ?? a.nodeId;
        list.push({
          group: "Services",
          label: `${a.name} · ${hostName}`,
          meta: "Open logs",
          run: () => {
            location.hash = `#/machines/${encodeURIComponent(a.nodeId)}`;
            openLogs(a);
          },
        });
      });

    const acts = [
      { label: "Add machine", meta: "Machines", run: openAddMachine },
      { label: "Pair a machine (QR)", meta: "Pairing", run: loadPairInvite },
      {
        label: "Connect an AI assistant",
        meta: "Access",
        run: () => {
          location.hash = "#/access";
          openAssistantDrawer();
        },
      },
      {
        label: `Switch to ${theme === "light" ? "dark" : "light"} mode`,
        meta: "Theme",
        run: () => setTheme((t) => (t === "light" ? "dark" : "light")),
      },
    ];
    acts
      .filter((x) => !q || x.label.toLowerCase().includes(q))
      .slice(0, 8)
      .forEach((x) => list.push({ group: "Actions", ...x }));

    return list;
  }, [cmdQuery, nodes, apps, theme]);

  const connectedAssistants = tokens.filter((token) => !token.revoked);
  const onlineCount = nodes.filter((n) => n.status === "online").length;

  if (authState.checked && authState.required && !authState.authed) {
    return (
      <div className="backdrop" style={{ background: "var(--bg)" }}>
        <form className="modal" onSubmit={submitLogin}>
          <div className="card-head">
            <h1 className="card-title">Sign in to Rackdeck</h1>
          </div>
          <div className="card-pad" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div className="field">
              <label>Owner password</label>
              <input
                className="input"
                type="password"
                autoFocus
                style={{ width: "100%" }}
                value={loginPass}
                onChange={(e) => setLoginPass(e.target.value)}
                required
              />
            </div>
            {loginErr && <div style={{ color: "var(--crit)", fontSize: 13 }}>{loginErr}</div>}
            <button type="submit" className="btn btn-primary">Sign in</button>
          </div>
        </form>
      </div>
    );
  }

  function renderAuditTable(events: AuditEvent[]) {
    return (
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id} className={newAuditIds.has(ev.id) ? "audit-new" : ""}>
                <td className="mono" title={new Date(ev.ts * 1000).toISOString()}>
                  {fmtTime(ev.ts)}
                </td>
                <td className="mono">{ev.actor}</td>
                <td>{ev.action}</td>
                <td className="mono">{ev.target}</td>
                <td>
                  <span className={`pill ${ev.ok ? "ok" : "crit"}`}>{ev.ok ? "Allowed" : ev.reason ?? "Denied"}</span>
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={5} style={{ color: "var(--text-2)" }}>
                  No audit events recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <>
      {IS_DEMO && !demoBannerDismissed && (
        <div className="demo-banner" role="region" aria-label="Demo notice">
          <div className="demo-banner-inner">
            <span>
              Live demo with sample data.{" "}
              <a
                href="https://github.com/ctsoftwarellc/rackdeck"
                target="_blank"
                rel="noopener noreferrer"
              >
                Install Rackdeck
              </a>
            </span>
            <button
              type="button"
              className="demo-banner-close"
              aria-label="Dismiss demo banner"
              onClick={() => setDemoBannerDismissed(true)}
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* 56px Top Bar */}
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand-row">
            <a className="brand-link" href="#/">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.2">
                <rect x="4" y="4" width="16" height="16" rx="4" />
                <circle cx="12" cy="12" r="3" fill="var(--accent)" stroke="none" />
              </svg>
              <span>Rackdeck</span>
            </a>
            {IS_DEMO && (
              <span className="demo-badge" title="Live demo using sample data">
                Sample data
              </span>
            )}
            {primaryNode && (
              <>
                <span className="brand-sep">/</span>
                <span className="fleet-tag">{primaryNode.name.toLowerCase()}</span>
              </>
            )}
          </div>

          <div className="topbar-right">
            <button
              type="button"
              className="search-trigger"
              aria-label="Search"
              onClick={() => {
                setCmdOpen(true);
                setCmdSel(0);
              }}
            >
              <span className="search-trigger-left">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="7" />
                  <path d="m20 20-3.5-3.5" />
                </svg>
                <span className="search-trigger-text">Search…</span>
              </span>
              <span className="kbd">⌘K</span>
            </button>

            <span className={`pill ${connState === "live" ? "ok" : connState === "reconnecting" ? "warn" : "crit"}`}>
              <span className={`dot ${connState === "live" ? "ok" : connState === "reconnecting" ? "warn" : "crit"}`} />
              {connState === "live" ? `Live${rttMs !== null ? ` · ${rttMs}ms` : ""}` : "Reconnecting…"}
            </span>

            <button
              type="button"
              className="btn btn-icon"
              title={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
              aria-label="Toggle color theme"
              onClick={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
            >
              {theme === "light" ? (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                  <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />
                </svg>
              ) : (
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                  <circle cx="12" cy="12" r="4" />
                  <path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4m11.4-11.4 1.4-1.4" />
                </svg>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* 44px Horizontal Tab Strip */}
      <nav className="tabbar" aria-label="Main navigation">
        <div className="tabbar-inner">
          <a href="#/" className={`tab-link ${route.page === "machines" || route.page === "machine" ? "active" : ""}`}>
            Machines
          </a>
          <a href="#/apps" className={"tab-link" + (route.page === "apps" ? " active" : "")}>
            Apps
          </a>
          <a href="#/network" className={`tab-link ${route.page === "network" ? "active" : ""}`}>
            Network &amp; Connect
          </a>
          <a href="#/access" className={`tab-link ${route.page === "access" ? "active" : ""}`}>
            Access Controls
          </a>
          <a href="#/audit" className={`tab-link ${route.page === "audit" ? "active" : ""}`}>
            Audit
          </a>
        </div>
      </nav>

      {/* Main Content */}
      <main className={`main ${connState !== "live" ? "stale" : ""}`}>
        {/* MACHINES LIST #/ */}
        {route.page === "machines" && (
          <>
            <div className="page-head">
              <div>
                <h1 className="page-title">Machines</h1>
                <p className="page-sub">
                  {nodes.length} machine{nodes.length === 1 ? "" : "s"} · {onlineCount} online
                </p>
              </div>
              <button type="button" className="btn btn-primary" onClick={openAddMachine}>
                + Add machine
              </button>
            </div>

            <div className="join-requests" aria-live="polite" aria-relevant="additions">
              {joinRequests.map((request) => (
                <section className="card card-pad join-request" key={request.key}>
                  <div>
                    <h2 className="card-title">{request.name} wants to join</h2>
                    <p className="page-sub">{request.os} · {request.ip ?? "IP address unavailable"}</p>
                    <div className="pair-code">{request.code}</div>
                    <p className="page-sub">Check this matches the code on that computer.</p>
                  </div>
                  <div className="join-actions">
                    <button
                      type="button"
                      className="btn btn-primary"
                      aria-label={`Allow ${request.name}`}
                      disabled={joinPending}
                      onClick={() => resolveJoinRequest(request, "POST")}
                    >
                      Allow
                    </button>
                    <button
                      type="button"
                      className="btn"
                      aria-label={`Ignore ${request.name}`}
                      disabled={joinPending}
                      onClick={() => resolveJoinRequest(request, "DELETE")}
                    >
                      Ignore
                    </button>
                  </div>
                </section>
              ))}
            </div>
            {joinLoadError && <p className="inline-err" role="alert">Could not load join requests.</p>}
            {joinActionError && <p className="inline-err" role="alert">{joinActionError}</p>}

            <div className="toolbar">
              <div className="filter-wrap">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="7" />
                  <path d="m20 20-3.5-3.5" />
                </svg>
                <input
                  className="input"
                  placeholder="Filter by name, IP, or OS…"
                  value={machineQuery}
                  onChange={(e) => setMachineQuery(e.target.value)}
                />
              </div>

              <div className="segmented" role="group" aria-label="Filter machine status">
                {(["all", "online", "offline"] as const).map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={`seg-btn ${machineStatusFilter === s ? "active" : ""}`}
                    onClick={() => setMachineStatusFilter(s)}
                  >
                    {s[0].toUpperCase() + s.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {latestVersion && behindNodes.length > 0 && (
              <div
                className="card"
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, padding: "12px 16px", marginBottom: 12, flexWrap: "wrap" }}
              >
                <span>
                  Rackdeck {latestVersion} is out. {behindNodes.length === 1 ? "1 machine is" : `${behindNodes.length} machines are`} on an older version.
                </span>
                <button type="button" className="btn btn-primary" onClick={updateAll}>
                  Update all
                </button>
              </div>
            )}
            <div className="card tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Machine</th>
                    <th>Addresses</th>
                    <th className="hide-sm">CPU / RAM / GPU</th>
                    <th>Services</th>
                    <th className="hide-sm">Access</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredNodes.map((n) => {
                    const s = (samples[n.id] ?? []).slice(-1)[0];
                    const cpu = Math.round(s?.cpu ?? 0);
                    const ramPct = Math.min(100, Math.round(((s?.memMb ?? 0) / Math.max(1, n.hw.ramTotalMb)) * 100));
                    const gpuPct = s?.gpu?.[0] !== undefined ? Math.round(s.gpu[0]) : null;
                    const nodeApps = apps.filter((a) => a.nodeId === n.id);
                    const runningApps = nodeApps.filter((a) => a.state === "running").length;
                    const hwTag =
                      n.hw.accel.kind === "apple"
                        ? n.hw.accel.chip
                        : n.hw.accel.kind === "nvidia"
                        ? n.hw.accel.gpus[0]?.name ?? "NVIDIA GPU"
                        : `${n.hw.cpuCores} vCPU`;

                    return (
                      <tr
                        key={n.id}
                        className="clickable"
                        onClick={() => {
                          location.hash = `#/machines/${encodeURIComponent(n.id)}`;
                        }}
                      >
                        <td>
                          <div className="machine-name">
                            <span
                              className={`dot ${n.status === "online" ? "ok" : "off"}`}
                              role="img"
                              aria-label={n.status === "online" ? "Online" : "Offline"}
                              title={n.status === "online" ? "Online" : "Offline"}
                            />
                            <a
                              href={`#/machines/${encodeURIComponent(n.id)}`}
                              className="machine-link"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {n.name}
                            </a>
                          </div>
                          <div className="machine-sub">
                            {n.os} · {hwTag}
                          </div>
                        </td>
                        <td>
                          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 2 }}>
                            {n.lanIp && <Copy value={n.lanIp} />}
                            {n.tailscaleIp && <Copy value={n.tailscaleIp} />}
                            {!n.lanIp && !n.tailscaleIp && <span className="mono">—</span>}
                          </div>
                        </td>
                        <td className="hide-sm">
                          <div className="mini-meters">
                            <div className="mini-meter">
                              <span>CPU</span>
                              <div className="m-track"><div className={meterFillClass(cpu)} style={{ width: `${cpu}%` }} /></div>
                              <span>{cpu}%</span>
                            </div>
                            <div className="mini-meter">
                              <span>{n.hw.accel.kind === "apple" ? "UNI" : "RAM"}</span>
                              <div className="m-track"><div className={meterFillClass(ramPct)} style={{ width: `${ramPct}%` }} /></div>
                              <span>{ramPct}%</span>
                            </div>
                            {gpuPct !== null && (
                              <div className="mini-meter">
                                <span>GPU</span>
                                <div className="m-track"><div className={meterFillClass(gpuPct)} style={{ width: `${gpuPct}%` }} /></div>
                                <span>{gpuPct}%</span>
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="mono">{runningApps}/{nodeApps.length}</td>
                        <td className="hide-sm">
                          <span className={`pill ${n.connectEnabled ? "accent" : "neutral"}`}>
                            {n.connectEnabled ? "Connect" : "Owner"}
                          </span>
                        </td>
                        <td>
                          {n.status === "online" ? (
                            <span style={{ color: "var(--ok)", fontWeight: 500 }}>Connected</span>
                          ) : (
                            <span className="mono">{fmtAgo(n.lastSeen)}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {filteredNodes.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ color: "var(--text-2)" }}>
                        {machineQuery ? `No machines match "${machineQuery}".` : "No machines online yet."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* MACHINE DETAIL #/machines/:id */}
        {route.page === "machine" && detailNode && (
          <>
            <div className="breadcrumb">
              <a href="#/">Machines</a>
              <span>/</span>
              <span>{detailNode.name}</span>
            </div>

            <div className="page-head">
              <div>
                <h1 className="page-title">
                  <span>{detailNode.name}</span>
                  <span className={`pill ${detailNode.status === "online" ? "ok" : "neutral"}`}>
                    {detailNode.status === "online" ? "Connected" : "Offline"}
                  </span>
                </h1>
                <div className="page-sub" style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                  <span>{detailNode.os} · {detailNode.hw.cpuCores} cores · Rackdeck {detailNode.version}</span>
                  {detailNode.lanIp && <Copy value={detailNode.lanIp} />}
                  {detailNode.tailscaleIp && <Copy value={detailNode.tailscaleIp} />}
                  {detailNode.connectEnabled && detailNode.connectSlug && (
                    <a href={`https://${detailNode.connectSlug}.rackdev.app`} target="_blank" rel="noopener noreferrer">
                      {detailNode.connectSlug}.rackdev.app
                    </a>
                  )}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                {updateMsg[detailNode.id] && (
                  <span role="status" style={{ fontSize: 12.5, color: "var(--text-2)" }}>
                    {updateMsg[detailNode.id]}
                  </span>
                )}
                {behind(detailNode) && (
                  <button type="button" className="btn" onClick={() => updateNode(detailNode)}>
                    Update to {latestVersion}
                  </button>
                )}
                {detailNode.id !== primaryNode?.id && (
                  <button type="button" className="btn" onClick={() => removeNode(detailNode)}>
                    Remove
                  </button>
                )}
                {detailNode.id === primaryNode?.id && (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      setDrawerTab("terminal");
                      setDrawerOpen(true);
                    }}
                  >
                    Terminal
                  </button>
                )}
                <a href="#/apps" className="btn btn-primary">Browse apps</a>
                <button type="button" className="btn" onClick={() => openCustomImage(detailNode.id)}>Custom image</button>
              </div>
            </div>

            {detailNode.status !== "online" && (
              <section className="card card-pad offline-help">
                <h2 className="card-title">Why is it offline?</h2>
                <p className="page-sub">
                  Last seen{" "}
                  {detailNode.lastSeen
                    ? <time dateTime={new Date(detailNode.lastSeen * 1000).toISOString()}>{fmtAgo(detailNode.lastSeen)}</time>
                    : "never"}
                  .
                </p>
                <p>On that computer, run:</p>
                <CommandSnippet command="rackdeck doctor" />
                <p>It checks whether the agent is running and looks for the dashboard if it can’t reach the saved address.</p>
              </section>
            )}

            {/* Stat Grid with Sparklines including dual-polyline Network */}
            <div className="stat-grid">
              <div className="card card-pad">
                <div className="stat-label">CPU</div>
                <div className="stat-val">{Math.round(latestSample?.cpu ?? 0)}%</div>
                <Sparkline values={detailSamples.map((s) => s.cpu)} />
              </div>

              <div className="card card-pad">
                <div className="stat-label">
                  {detailNode.hw.accel.kind === "apple" ? "Unified Memory" : "Memory"}
                </div>
                <div className="stat-val">{fmtGb(latestSample?.memMb ?? 0)}</div>
                <div className="stat-sub">of {fmtGb(detailNode.hw.ramTotalMb)}</div>
                <Sparkline
                  values={detailSamples.map((s) => (s.memMb / Math.max(1, detailNode.hw.ramTotalMb)) * 100)}
                />
              </div>

              {detailNode.hw.accel.kind === "nvidia" && (
                <div className="card card-pad">
                  <div className="stat-label">GPU / VRAM</div>
                  <div className="stat-val">{Math.round(latestSample?.gpu?.[0] ?? 0)}%</div>
                  <div className="stat-sub">
                    {fmtGb(latestSample?.vramMb?.[0] ?? 0)} / {fmtGb(detailNode.hw.accel.gpus[0]?.vramTotalMb ?? 0)}
                    {latestSample?.tempC ? ` · ${Math.round(latestSample.tempC)}°C` : ""}
                  </div>
                  <Sparkline values={detailSamples.map((s) => s.gpu?.[0] ?? 0)} />
                </div>
              )}

              <div className="card card-pad">
                <div className="stat-label">Network</div>
                <div className="stat-val" style={{ fontSize: 18 }}>
                  ↓ {fmtRate(latestSample?.netRxBps ?? 0)}
                </div>
                <div className="stat-sub">↑ {fmtRate(latestSample?.netTxBps ?? 0)}</div>
                <Sparkline
                  values={detailSamples.map((s) => s.netRxBps)}
                  secondary={detailSamples.map((s) => s.netTxBps)}
                />
              </div>

              <div className="card card-pad">
                <div className="stat-label">Disk &amp; Uptime</div>
                <div className="stat-val">{fmtUptime(detailNode.uptimeSecs)}</div>
                <div className="stat-sub">
                  Disk {latestSample?.diskGb ?? 0} / {detailNode.hw.diskTotalGb} GB
                </div>
              </div>
            </div>

            {/* Services Card */}
            <div className="card">
              <div className="card-head">
                <h2 className="card-title">Services</h2>
                <div className="segmented">
                  {(["all", "docker", "ai"] as const).map((f) => (
                    <button
                      key={f}
                      type="button"
                      className={`seg-btn ${appFilter === f ? "active" : ""}`}
                      onClick={() => setAppFilter(f)}
                    >
                      {f === "all" ? "All" : f === "docker" ? "Docker" : "AI"}
                    </button>
                  ))}
                </div>
              </div>

              {renderAppFeedback(detailNode.id)}

              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Kind</th>
                      <th>Status</th>
                      <th className="hide-sm">Image / Model</th>
                      <th style={{ textAlign: "right" }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {apps
                      .filter((a) => a.nodeId === detailNode.id)
                      .filter((a) => appFilter === "all" || a.type === appFilter)
                      .map((app) => {
                        const pend = pendingApp[appKey(app)];
                        return (
                          <tr key={app.id}>
                            <td>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                                <span style={{ fontWeight: 500 }}>{app.name}</span>
                                {updateDot(app)}
                                {app.ports.map((p) => (
                                  <Copy key={p} value={`${detailNode.lanIp ?? "127.0.0.1"}:${p}`} display={`:${p}`} />
                                ))}
                              </div>
                            </td>
                            <td>
                              <span className={`pill ${app.type === "ai" ? "accent" : "neutral"}`}>
                                {app.type === "system" ? "System" : app.type === "ai" ? "AI" : "Docker"}
                              </span>
                            </td>
                            <td>
                              <span
                                className={`pill ${
                                  pend
                                    ? "accent"
                                    : app.state === "running"
                                    ? "ok"
                                    : app.state === "error"
                                    ? "crit"
                                    : "neutral"
                                }`}
                              >
                                {pend ?? app.state}
                              </span>
                            </td>
                            <td className="mono hide-sm">{app.model ?? app.image ?? "—"}</td>
                            <td style={{ textAlign: "right" }}>
                              {renderAppControls(app, true)}
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>

              {detailNode.docker === "absent" && (
                <div className="dashed-empty">
                  <div>
                    <div style={{ fontWeight: 500 }}>Docker isn't installed on this machine.</div>
                    <div style={{ fontSize: 12.5, color: "var(--text-2)" }}>
                      Native services and local AI runners still appear above.
                    </div>
                  </div>
                  <Copy
                    value={
                      detailNode.os.toLowerCase().includes("mac")
                        ? "brew install --cask orbstack"
                        : "curl -fsSL https://get.docker.com | sh"
                    }
                  />
                </div>
              )}
            </div>
          </>
        )}

        {/* NETWORK & CONNECT #/network */}
        {route.page === "network" && (
          <>
            <div className="page-head">
              <div>
                <h1 className="page-title">Network &amp; Connect</h1>
              </div>
            </div>

            <div className="stack-sections">
              <section className="card card-pad">
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 20 }}>
                  <div>
                    <h2 className="card-title" style={{ marginBottom: 6 }}>
                      Tailscale
                      <span className={`pill ${primaryNode?.tailscaleIp ? "ok" : "neutral"}`}>
                        {primaryNode?.tailscaleIp ? `Detected · ${primaryNode.tailscaleIp}` : "Not detected"}
                      </span>
                      <Help title="Tailscale">
                        <p>Rackdeck checks for Tailscale with the read-only <span className="mono">tailscale ip</span> and <span className="mono">tailscale status</span> commands. It never signs into your Tailscale account.</p>
                        <p>Already on Tailscale? You don't need Connect. Open Rackdeck at this machine's Tailscale IP from any device on your tailnet.</p>
                      </Help>
                    </h2>
                  </div>
                  <div>
                    <h2 className="card-title" style={{ marginBottom: 6 }}>
                      Rackdeck Connect
                      <span className="pill neutral">Coming soon</span>
                      <Help title="Rackdeck Connect">
                        <p>Reach your dashboard from anywhere without Tailscale. This machine opens an encrypted connection out to a relay, which gives you an address like <span className="mono">you.rackdev.app</span>.</p>
                        <p>No router ports and no VPN app on your phone. Hosted connectivity is part of Rackdeck Cloud, which isn't live yet. You can run your own relay today.</p>
                      </Help>
                    </h2>
                    {controller.relayConfigured && (<>
                    <div style={{ marginTop: 12, fontSize: 13, color: "var(--text-2)" }} role="status">
                      {linkReq ? (
                        <>
                          Approve code <span className="mono" style={{ color: "var(--text-1)", fontWeight: 600 }}>{linkReq.userCode}</span> in
                          the tab that just opened.{" "}
                          <a href={linkReq.url} target="_blank" rel="noopener">Open it again</a>
                        </>
                      ) : account?.linked ? (
                        <>
                          Linked to your Rackdeck account
                          {account.slugs.length > 0 && <> as <span className="mono">{account.slugs.join(", ")}</span></>}.{" "}
                          {account.active ? "Connect subscription active." : "No active subscription yet."}{" "}
                          {account.accountUrl && (
                            <a href={account.accountUrl} target="_blank" rel="noopener">
                              Manage account
                            </a>
                          )}
                        </>
                      ) : (
                        primaryNode && (
                          <button type="button" className="btn" onClick={() => startAccountLink(primaryNode)}>
                            Sign in to Rackdeck
                          </button>
                        )
                      )}
                      {accountErr && <div style={{ marginTop: 6, color: "var(--crit)" }}>{accountErr}</div>}
                    </div>
                    <details style={{ marginTop: 10, fontSize: 13, color: "var(--text-2)" }}>
                      <summary style={{ cursor: "pointer", color: "var(--text-1)" }}>Tunnel</summary>
                      {primaryNode && (
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <input
                            className="input"
                            style={{ width: 150, fontFamily: "var(--mono)" }}
                            placeholder={primaryNode.connectSlug ?? "my-fleet"}
                            value={connectSlugInput}
                            onChange={(e) => setConnectSlugInput(e.target.value)}
                          />
                          <button type="button" className="btn" onClick={() => toggleConnect(primaryNode)}>
                            {primaryNode.connectEnabled ? "Disconnect tunnel" : "Connect tunnel"}
                          </button>
                        </div>
                      )}
                    </details>
                    </>)}
                  </div>
                </div>
              </section>

              {/* 1. Tailnet Discovery */}
              <section className="card">
                <div className="card-head">
                  <h2 className="card-title">
                    Tailnet discovery
                    {scanning && <span className="pill accent">Scanning…</span>}
                  </h2>
                  <button type="button" className="btn btn-sm" onClick={runScan} disabled={scanning}>
                    Rescan
                  </button>
                </div>
                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>Peer</th>
                        <th>Tailnet IP</th>
                        <th>Rackdeck</th>
                        <th style={{ textAlign: "right" }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {peers.map((p) => (
                        <tr key={p.id}>
                          <td>
                            <div className="machine-name">
                              <span className={`dot ${p.online ? "ok" : "off"}`} />
                              <span>{p.hostname}</span>
                            </div>
                            <div className="machine-sub">{p.os}</div>
                          </td>
                          <td><Copy value={p.ip} /></td>
                          <td>
                            <span className={`pill ${p.rackdeckVersion ? "ok" : "neutral"}`}>
                              {p.rackdeckVersion ? `Installed v${p.rackdeckVersion}` : "Not installed"}
                            </span>
                          </td>
                          <td style={{ textAlign: "right" }}>
                            {p.rackdeckVersion ? (
                              <button type="button" className="btn btn-primary btn-sm" onClick={openAddMachine}>
                                Add
                              </button>
                            ) : (
                              <Copy value="curl -fsSL https://get.rackdeck.dev | sh" display="Copy install cmd" />
                            )}
                          </td>
                        </tr>
                      ))}
                      {peers.length === 0 && (
                        <tr>
                          <td colSpan={4} style={{ color: "var(--text-2)" }}>
                            {scanning
                              ? "Probing Tailscale peers on port 7420…"
                              : "No other Tailscale devices found. Sign into Tailscale on this machine, or add a machine with a join command instead."}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              {/* 2. Connect Routes */}
              <section className="card">
                <div className="card-head">
                  <h2 className="card-title">
                    Connect routes
                    <span
                      className={`pill ${
                        connectHealth.active ? "ok" : connectHealth.enabled ? "warn" : "neutral"
                      }`}
                    >
                      {connectHealth.active
                        ? "● Connected"
                        : connectHealth.enabled
                        ? "Relay unreachable"
                        : "Off"}
                    </span>
                  </h2>
                  <button
                    type="button"
                    className="btn btn-sm btn-primary"
                    onClick={() => {
                      setAddingRoute((v) => !v);
                      if (nodes[0] && apps[0]) setRouteTarget(`${nodes[0].id}::${apps[0].name}`);
                    }}
                  >
                    + New route
                  </button>
                </div>

                {addingRoute && (
                  <form
                    onSubmit={saveNewRoute}
                    style={{
                      padding: "12px 16px",
                      borderBottom: "1px solid var(--border)",
                      background: "var(--surface-2)",
                      display: "flex",
                      gap: 8,
                      flexWrap: "wrap",
                      alignItems: "center",
                    }}
                  >
                    <input
                      className="input"
                      placeholder="app.rackdev.app"
                      value={routeHost}
                      onChange={(e) => setRouteHost(e.target.value)}
                      required
                    />
                    <select className="select" value={routeTarget} onChange={(e) => setRouteTarget(e.target.value)}>
                      {nodes.map((n) => (
                        <optgroup key={n.id} label={n.name}>
                          {apps
                            .filter((a) => a.nodeId === n.id)
                            .map((a) => (
                              <option key={a.id} value={`${n.id}::${a.name}`}>
                                {n.name} › {a.name}
                              </option>
                            ))}
                        </optgroup>
                      ))}
                    </select>
                    <input
                      className="input"
                      style={{ width: 88 }}
                      placeholder="Port"
                      value={routePort}
                      onChange={(e) => setRoutePort(e.target.value)}
                    />
                    <button type="submit" className="btn btn-primary btn-sm">Save</button>
                    <button type="button" className="btn btn-sm" onClick={() => setAddingRoute(false)}>Cancel</button>
                  </form>
                )}

                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th>Route</th>
                        <th>Target</th>
                        <th>Tunnel</th>
                        <th style={{ textAlign: "right" }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {routes.map((r) => {
                        const hostNode = nodes.find((n) => n.id === r.nodeId)?.name ?? r.nodeId;
                        return (
                          <tr key={r.id}>
                            <td><Copy value={`https://${r.host}`} display={r.host} /></td>
                            <td className="mono">{hostNode} › {r.targetApp} :{r.targetPort}</td>
                            <td>
                              <span
                                className={`pill ${
                                  connectHealth.active ? "ok" : connectHealth.enabled ? "warn" : "neutral"
                                }`}
                              >
                                {connectHealth.active
                                  ? "● Connected"
                                  : connectHealth.enabled
                                  ? "Relay unreachable"
                                  : "Off"}
                              </span>
                            </td>
                            <td style={{ textAlign: "right" }}>
                              {confirmDeleteRoute === r.id ? (
                                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12 }}>
                                  <span>Delete?</span>
                                  <button type="button" className="btn btn-sm btn-danger" onClick={() => deleteRoute(r.id)}>Yes</button>
                                  <button type="button" className="btn btn-sm" onClick={() => setConfirmDeleteRoute(null)}>No</button>
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  className="btn btn-sm btn-danger"
                                  onClick={() => setConfirmDeleteRoute(r.id)}
                                >
                                  Delete
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                      {routes.length === 0 && (
                        <tr>
                          <td colSpan={4} style={{ color: "var(--text-2)" }}>
                            No public routes configured yet. Click + New route to expose a service.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          </>
        )}

        {route.page === "apps" && (
          <AppCatalog nodes={nodes} apps={apps} onInstalled={addInstalledApp} onCustomImage={() => openCustomImage()}
            installedApps={
              <section className="installed-apps">
                {renderAppFeedback()}
                {apps.some((app) => app.type === "docker") && (
                  <>
                    <h2 className="catalog-heading">Installed</h2>
                    <div className="catalog-grid">
                      {apps.filter((app) => app.type === "docker").map((app) => (
                        <article key={appKey(app)} className="card card-pad catalog-app">
                          <h3 className="card-title">{app.name} {updateDot(app)}</h3>
                          <p>{nodes.find((node) => node.id === app.nodeId)?.name ?? app.nodeId} · {pendingApp[appKey(app)] ?? app.state}</p>
                          <div className="catalog-actions">{renderAppControls(app)}</div>
                        </article>
                      ))}
                    </div>
                  </>
                )}
              </section>
            } />
        )}

        {/* ACCESS CONTROLS #/access */}
        {route.page === "access" && (
          <>
            <div className="page-head">
              <h1 className="page-title">Access Controls</h1>
            </div>

            <div className="stack-sections">
              <section className="card card-pad assistant-card">
                <h2 className="card-title">
                  AI assistants
                  <Help title="AI assistants">
                    <h3 className="card-title">For other MCP clients</h3>
                    <div className="assistant-address"><Copy value={location.origin + "/mcp"} /></div>
                    <p>Assistants can read machine status and app logs, or manage apps with your permission, and can never open a terminal.</p>
                    <p>The Audit log shows app changes and leaves out reads.</p>
                    <p>Try asking “Install Jellyfin on my NAS”.</p>
                  </Help>
                </h2>
                <p>Let Claude Code, Codex or Cursor check on your machines and manage apps for you.</p>
                <button type="button" className="btn btn-primary" onClick={openAssistantDrawer}>
                  Connect an assistant
                </button>
                <div className="assistant-list">
                  <h3 className="card-title">Connected assistants</h3>
                  {connectedAssistants.length ? (
                    <ul>
                      {connectedAssistants.map((token) => (
                        <li key={token.id}>
                          <div className="assistant-summary">
                            <strong>{token.name}</strong>
                            <span>{token.scope === "read" ? "Look only" : "Manages apps"}</span>
                            <span>{token.lastUsedAt ? "Last used " + fmtAgo(token.lastUsedAt).toLowerCase() : "Never used"}</span>
                            {token.expiresAt && token.expiresAt <= Date.now() / 1000 && <span className="pill neutral">Expired</span>}
                          </div>
                          <button type="button" className="btn btn-sm" disabled={Boolean(disconnecting)}
                            aria-label={"Disconnect " + token.name} onClick={() => disconnectAssistant(token)}>
                            {disconnecting === token.id ? "Disconnecting…" : "Disconnect"}
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : <p>No assistants connected yet.</p>}
                  {assistantsError && <p className="inline-err" role="alert">{assistantsError}</p>}
                </div>
              </section>
              <SecretsCard nodes={nodes} />

              <section className="card">
                <div className="card-head">
                  <h2 className="card-title">
                    Audit trail
                    <span className="pill ok">● Live</span>
                  </h2>
                  <a href="#/audit" className="btn btn-sm">Full view</a>
                </div>
                {renderAuditTable(audit.slice(0, 20))}
              </section>
            </div>
          </>
        )}

        {/* AUDIT #/audit */}
        {route.page === "audit" && (
          <>
            <div className="page-head">
              <div>
                <h1 className="page-title">
                  Audit
                  <span className="pill ok">● Live</span>
                </h1>
                <p className="page-sub">Append-only operational log across UI actions and scoped MCP calls.</p>
              </div>
            </div>
            <div className="card">{renderAuditTable(audit)}</div>
          </>
        )}
      </main>

      {/* Bottom Logs & Terminal Drawer */}
      {drawerOpen && (
        <section className="logs-drawer" aria-label="Console drawer">
          <div className="logs-head">
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div className="segmented">
                <button
                  type="button"
                  className={`seg-btn ${drawerTab === "logs" ? "active" : ""}`}
                  onClick={() => setDrawerTab("logs")}
                >
                  Logs{drawerApp ? ` · ${drawerApp.name}` : ""}
                </button>
                <button
                  type="button"
                  className={`seg-btn ${drawerTab === "terminal" ? "active" : ""}`}
                  onClick={() => setDrawerTab("terminal")}
                >
                  Terminal{primaryNode ? ` · ${primaryNode.name}` : ""}
                </button>
              </div>
              {drawerTab === "logs" && (
                <input
                  className="input"
                  style={{ height: 26, width: 180, fontSize: 12 }}
                  placeholder="Filter logs…"
                  value={logFilter}
                  onChange={(e) => setLogFilter(e.target.value)}
                />
              )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {drawerTab === "logs" && (
                <>
                  <Copy value={logEntries.map((l) => `${fmtTime(l[0])} ${l[2]}`).join("\n")} display="Copy all" />
                  <button
                    type="button"
                    className={`btn btn-sm ${logFollow ? "btn-primary" : ""}`}
                    onClick={() => setLogFollow((v) => !v)}
                  >
                    {logFollow ? "Follow ✓" : "Follow"}
                  </button>
                </>
              )}
              <button type="button" className="btn btn-sm" aria-label="Close console drawer" onClick={closeDrawer}>✕</button>
            </div>
          </div>

          {drawerTab === "logs" ? (
            <pre className="logs-pre" ref={logsPreRef}>
              {logEntries.length === 0 ? (
                <span style={{ color: "var(--text-3)" }}>
                  {drawerApp ? `Streaming logs for ${drawerApp.name}…` : "Select a service to view logs."}
                </span>
              ) : (
                logEntries
                  .filter(([, , text]) => !logFilter || text.toLowerCase().includes(logFilter.toLowerCase()))
                  .map(([ts, , text], idx) => (
                    <div key={idx}>
                      <span className="log-ts">{fmtTime(ts)}</span>
                      <span>{text}</span>
                    </div>
                  ))
              )}
            </pre>
          ) : IS_DEMO ? (
            <div className="demo-term-disabled" role="status">
              <p>
                The browser terminal is disabled in this live demo.{" "}
                <a
                  href="https://github.com/ctsoftwarellc/rackdeck#install"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Install Rackdeck
                </a>{" "}
                on your own machine to run shell commands from the dashboard.
              </p>
            </div>
          ) : (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
              <pre className="logs-pre" style={{ flex: 1 }}>
                {termLines.map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </pre>
              <form
                onSubmit={runTerminalCmd}
                style={{
                  display: "flex",
                  gap: 8,
                  padding: "8px 12px",
                  borderTop: "1px solid var(--border)",
                  background: "var(--surface)",
                }}
              >
                <span className="mono" style={{ alignSelf: "center" }}>$</span>
                <input
                  className="input"
                  style={{ flex: 1, fontFamily: "var(--mono)" }}
                  placeholder="uname -a, df -h, docker ps..."
                  value={termCmd}
                  onChange={(e) => setTermCmd(e.target.value)}
                />
                <button type="submit" className="btn btn-primary btn-sm">Run</button>
              </form>
            </div>
          )}
        </section>
      )}

      {removeTarget && (
        <dialog className="modal remove-app-modal" ref={removeDialog} aria-labelledby="remove-app-title"
          onClose={() => setRemoveTarget(null)}>
          <div className="card-head">
            <h2 className="card-title" id="remove-app-title">Remove {removeTarget.name}?</h2>
          </div>
          <form className="card-pad" onSubmit={(e) => {
            e.preventDefault();
            const deleteData = new FormData(e.currentTarget).has("deleteData");
            removeDialog.current?.close();
            void runAppAction(removeTarget, "remove", deleteData);
          }}>
            <label><input type="checkbox" name="deleteData" aria-describedby="remove-app-data-help" /> Also delete its data</label>
            <p id="remove-app-data-help">Deletes saved data in Docker. Keeps folders you linked.</p>
            <div className="app-controls">
              <button type="button" className="btn" autoFocus onClick={() => removeDialog.current?.close()}>Cancel</button>
              <button type="submit" className="btn btn-danger">Remove</button>
            </div>
          </form>
        </dialog>
      )}

      {deployOpen && (
        <div className="backdrop right" onClick={() => { if (!depBusy) setDeployOpen(false); }}>
          <aside className="side-drawer" role="dialog" aria-labelledby="custom-image-title" onClick={(e) => e.stopPropagation()}>
            <div className="card-head">
              <h2 className="card-title" id="custom-image-title">Custom image</h2>
              <button type="button" className="btn btn-sm" aria-label="Close custom image dialog" disabled={depBusy} onClick={() => setDeployOpen(false)}>✕</button>
            </div>
            <div className="side-drawer-body">
              <form onSubmit={submitDeploy} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <div className="field">
                  <label htmlFor="custom-image-computer">Computer</label>
                  <select id="custom-image-computer" className="input" autoFocus required disabled={depBusy} value={deployNode?.id ?? ""}
                    onChange={(event) => {
                      setDeployNodeId(event.target.value);
                      setDepErr(null);
                    }}>
                    <option value="" disabled>Choose a computer</option>
                    {nodes.map((node) => <option value={node.id} key={node.id}>{node.name}</option>)}
                  </select>
                </div>
                {deployNode && (dockerUnavailable(deployNode) || deployNode.status !== "online") && (
                  <p className="inline-err" style={{ margin: 0 }} role="status">
                    {dockerUnavailable(deployNode) || deployNode.name + " is offline."}
                  </p>
                )}
                <div className="field">
                  <label>App name</label>
                  <input className="input" style={{ width: "100%" }} placeholder="my-api" value={depName} onChange={(e) => setDepName(e.target.value)} required />
                </div>
                <div className="field">
                  <label>Docker image</label>
                  <input className="input" style={{ width: "100%", fontFamily: "var(--mono)" }} placeholder="ghcr.io/org/app:latest" value={depImage} onChange={(e) => setDepImage(e.target.value)} required />
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  <div className="field">
                    <label>Host port</label>
                    <input className="input" style={{ width: "100%" }} placeholder="8080" value={depHostPort} onChange={(e) => setDepHostPort(e.target.value)} />
                  </div>
                  <div className="field">
                    <label>Container port</label>
                    <input className="input" style={{ width: "100%" }} placeholder="8080" value={depContPort} onChange={(e) => setDepContPort(e.target.value)} />
                  </div>
                </div>
                <div className="field">
                  <label>Environment variables (KEY=VALUE per line)</label>
                  <textarea
                    className="input"
                    style={{ width: "100%", height: 84, padding: 8, fontFamily: "var(--mono)" }}
                    placeholder="NODE_ENV=production"
                    value={depEnvText}
                    onChange={(e) => setDepEnvText(e.target.value)}
                  />
                </div>
                {depImage.trim() && (
                  <div className="field">
                    <label>What Rackdeck will run</label>
                    <pre
                      className="input"
                      style={{ width: "100%", margin: 0, padding: 8, height: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", fontFamily: "var(--mono)", fontSize: 12 }}
                    >
                      {dockerRunPreview(depName, depImage, depHostPort, depContPort, depEnvText)}
                    </pre>
                  </div>
                )}
                {depErr && <p className="inline-err" role="alert">{depErr}</p>}
                {depBusy && <p role="status">Downloading and starting… this can take a few minutes for big apps.</p>}
                <button type="submit" className="btn btn-primary" disabled={depBusy || deployNode?.docker !== "running" || deployNode.status !== "online"}>
                  Install custom image
                </button>
              </form>
            </div>
          </aside>
        </div>
      )}

      {addMachineOpen && (
        <div className="backdrop" onClick={() => setAddMachineOpen(false)}>
          <div className="modal add-machine-modal" role="dialog" aria-labelledby="add-machine-title" onClick={(e) => e.stopPropagation()}>
            <div className="card-head">
              <h2 className="card-title" id="add-machine-title">Add machine</h2>
              <button type="button" className="btn btn-sm" aria-label="Close add machine dialog" autoFocus onClick={() => setAddMachineOpen(false)}>✕</button>
            </div>
            <div className="card-pad add-machine-body">
              {IS_DEMO && (
                <div className="demo-note">This demo uses sample machines.</div>
              )}
              <div className="add-machine-line">
                <p>On the other computer, open a terminal and run:</p>
                <Help title="Opening a terminal">
                  <p>On Mac, press ⌘ Space and type Terminal.</p>
                  <p>On Windows, open Ubuntu (WSL). On Linux, open Terminal.</p>
                </Help>
              </div>
              <CommandSnippet command={INSTALL_COMMAND} />
              <p>It finds this dashboard on your Wi-Fi and asks to join.</p>
              {!controller.passwordSet && (
                <p className="inline-err" role="alert">
                  Set a dashboard password before adding computers. Restart Rackdeck with <code>RACKDECK_PASSWORD</code> set.
                </p>
              )}
              <div className="add-machine-option">
                <div className="add-machine-line">
                  <p>Computer on a different network?</p>
                  <Help title="Computers on other networks">
                    <p>Computers on your home Wi-Fi find this dashboard on their own. A computer somewhere else, like a VPS or a friend's house, can't reach it through your router.</p>
                    <p>Ways to connect it:</p>
                    <p><strong>Tailscale</strong> (free). Install it on both computers and sign in to the same account. Then use the command under Different network.</p>
                    <p><strong>Rackdeck Cloud</strong> (coming soon). Connects computers anywhere with no setup. <a href="https://rackdeck.dev/#pricing" target="_blank" rel="noopener">Join the waitlist</a></p>
                  </Help>
                  <button
                    type="button"
                    className="btn btn-sm"
                    aria-expanded={differentNetworkOpen}
                    aria-controls="different-network-command"
                    onClick={() => {
                      setJoinCmd("");
                      setJoinCmdError(false);
                      setDifferentNetworkOpen(!differentNetworkOpen);
                    }}
                  >
                    Different network <span aria-hidden="true">{differentNetworkOpen ? "▴" : "▾"}</span>
                  </button>
                </div>
                <div id="different-network-command" hidden={!differentNetworkOpen}>
                  {primaryNode?.tailscaleIp && (
                    <p>This dashboard is on Tailscale, so this command works from any computer on your tailnet.</p>
                  )}
                  {joinCmd ? <CommandSnippet command={joinCmd} /> : joinCmdError ? (
                    <>
                      <p className="inline-err" role="alert">Could not make a join command.</p>
                      <button type="button" className="btn btn-sm" onClick={() => setJoinCmdAttempt((attempt) => attempt + 1)}>Try again</button>
                    </>
                  ) : <p role="status">Making a join command…</p>}
                  {joinCmd && <p>Works once and expires after 15 minutes.</p>}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {pairOpen && (() => {
        const remaining = pairInvite ? Math.max(0, pairInvite.expiresAt - nowSec) : 0;
        const expired = remaining === 0;
        return (
          <div className="backdrop" onClick={() => setPairOpen(false)}>
            <div className="modal" role="dialog" aria-label="Pair a machine" onClick={(e) => e.stopPropagation()}>
              <div className="card-head">
                <h2 className="card-title">Pair a machine</h2>
                <button type="button" className="btn btn-sm" aria-label="Close pairing dialog" autoFocus onClick={() => setPairOpen(false)}>✕</button>
              </div>
              <div className="card-pad qr-pairing">
                {IS_DEMO && <div className="demo-note">This QR code is a demo example.</div>}
                {pairInvite && (
                  <>
                    <div style={{ filter: expired ? "blur(4px)" : "none", opacity: expired ? 0.5 : 1 }}>
                      <QrSvg uri={pairInvite.qrUri} />
                      <Copy value={pairInvite.code6} display={pairInvite.code6} className="pair-code" />
                      <div className="mono">Fingerprint {pairInvite.fingerprint}</div>
                    </div>
                    <div className="qr-countdown">
                      {expired ? <button type="button" className="btn btn-primary" onClick={loadPairInvite}>Generate new code</button> : (
                        <>
                          <div className="mono">Expires in 0:{String(remaining).padStart(2, "0")}</div>
                          <div className="countdown-bar">
                            <div className={`countdown-fill ${remaining < 10 ? "low" : ""}`} style={{ width: `${Math.min(100, (remaining / 60) * 100)}%` }} />
                          </div>
                        </>
                      )}
                    </div>
                  </>
                )}
                {!pairInvite && (pairError ? (
                  <>
                    <p className="inline-err" role="alert">Could not load a QR code.</p>
                    <button type="button" className="btn btn-sm" onClick={loadPairInvite}>Try again</button>
                  </>
                ) : <p role="status">Making a QR code…</p>)}
              </div>
            </div>
          </div>
        );
      })()}

      {assistantDrawerOpen && (
        <div className="backdrop right" onClick={closeAssistantDrawer}>
          <aside className="side-drawer" role="dialog" aria-labelledby="assistant-dialog-title"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                e.stopPropagation();
                closeAssistantDrawer();
              }
            }}>
            <div className="card-head">
              <h2 className="card-title" id="assistant-dialog-title">{assistantResult ? "Set up " + assistantClient : "Connect an assistant"}</h2>
              <button type="button" className="btn btn-sm" aria-label="Close assistant setup" disabled={assistantBusy}
                onClick={closeAssistantDrawer}>✕</button>
            </div>
            <div className="side-drawer-body assistant-drawer">
              {assistantResult ? (
                <>
                  {assistantResult.kind === "command" ? (
                    <>
                      <p>Paste this command in a terminal.</p>
                      <CommandSnippet command={assistantResult.command} />
                    </>
                  ) : (
                    <>
                      <a href={assistantResult.link} className="btn btn-primary">Add to Cursor</a>
                      <details>
                        <summary>Or copy the config</summary>
                        <CommandSnippet command={assistantResult.config} />
                      </details>
                    </>
                  )}
                  <p>This setup is shown once.</p>
                  <p>Try asking “How are my machines doing?”</p>
                  <button type="button" className="btn" onClick={closeAssistantDrawer}>Done</button>
                </>
              ) : (
                <form className="assistant-form" onSubmit={connectAssistant}>
                  <fieldset disabled={assistantBusy}>
                    <legend>Which assistant?</legend>
                    <div className="assistant-options clients">
                      {ASSISTANTS.map((client, index) => (
                        <label key={client} className="assistant-option">
                          <input type="radio" name="assistant" value={client} checked={assistantClient === client}
                            autoFocus={index === 0} onChange={() => setAssistantClient(client)} />
                          <strong>{client}</strong>
                        </label>
                      ))}
                    </div>
                  </fieldset>
                  <fieldset disabled={assistantBusy}>
                    <legend>What can it do?</legend>
                    <div className="assistant-options">
                      <label className="assistant-option">
                        <input type="radio" name="assistant-scope" checked={assistantScope === "read"} onChange={() => setAssistantScope("read")} />
                        <span><strong>Look only</strong><small>See your machines and read app logs.</small></span>
                      </label>
                      <label className="assistant-option">
                        <input type="radio" name="assistant-scope" checked={assistantScope === "deploy"} onChange={() => setAssistantScope("deploy")} />
                        <span><strong>Look and manage apps</strong><small>Also start, stop, restart, install, update and remove apps.</small></span>
                      </label>
                    </div>
                    <p className="assistant-permission-note">It can never open a terminal.</p>
                  </fieldset>
                  {assistantError && <p className="inline-err" role="alert">{assistantError}</p>}
                  <button type="submit" className="btn btn-primary" disabled={assistantBusy}>
                    {assistantBusy ? "Connecting…" : "Connect"}
                  </button>
                </form>
              )}
            </div>
          </aside>
        </div>
      )}

      {/* ⌘K Command Palette (Full Keyboard Navigation) */}
      {cmdOpen && (
        <div className="backdrop top" onClick={() => setCmdOpen(false)}>
          <div className="palette" onClick={(e) => e.stopPropagation()}>
            <input
              className="palette-input"
              autoFocus
              placeholder="Jump to machine, service, or action…"
              value={cmdQuery}
              onChange={(e) => {
                setCmdQuery(e.target.value);
                setCmdSel(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setCmdSel((i) => (paletteItems.length ? (i + 1) % paletteItems.length : 0));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setCmdSel((i) => (paletteItems.length ? (i - 1 + paletteItems.length) % paletteItems.length : 0));
                } else if (e.key === "Enter" && paletteItems[cmdSel]) {
                  e.preventDefault();
                  paletteItems[cmdSel].run();
                  setCmdOpen(false);
                  setCmdQuery("");
                }
              }}
            />
            <div className="palette-list">
              {paletteItems.map((item, idx) => {
                const prevGroup = idx > 0 ? paletteItems[idx - 1].group : null;
                return (
                  <React.Fragment key={`${item.group}-${item.label}-${idx}`}>
                    {item.group !== prevGroup && <div className="palette-group">{item.group}</div>}
                    <button
                      type="button"
                      className={`palette-row ${idx === cmdSel ? "sel" : ""}`}
                      onMouseEnter={() => setCmdSel(idx)}
                      onClick={() => {
                        item.run();
                        setCmdOpen(false);
                        setCmdQuery("");
                      }}
                    >
                      <span>{item.label}</span>
                      {item.meta && <span className="mono">{item.meta}</span>}
                    </button>
                  </React.Fragment>
                );
              })}
              {paletteItems.length === 0 && (
                <div style={{ padding: "14px", color: "var(--text-2)", fontSize: 13 }}>No matching commands.</div>
              )}
            </div>
            <div className="palette-foot">↑↓ navigate · ↵ open · esc close</div>
          </div>
        </div>
      )}
    </>
  );
}
