# Rackdeck

**Lightweight Rust server management for mixed fleets — cloud VPS, home NVIDIA GPU rigs, and Apple Silicon Macs in one clean dashboard.**

Built as a single Rust binary (`rackdeck`) with an embedded React UI and bundled SQLite (WAL). Works 100% free on your home LAN or existing Tailscale/WireGuard network with **no account required** and **zero product telemetry**.

---

## Quickstart (Account-Free)

### Run locally or on a Linux VPS
```bash
# Build from source (requires Rust + Bun)
cd ui && bun install && bun run build && cd ..
cargo build --release -p rackdeck -p rackdeck-relay

# Start all-in-one control plane + local node (http://127.0.0.1:7420)
./target/release/rackdeck
```

For public/internet-facing deployments, set an owner password to enable HttpOnly session login:
```bash
RACKDECK_PASSWORD="choose-a-strong-password" ./target/release/rackdeck
```

### Join a second machine (VPS, 5090 rig, or Mac)
1. Open the dashboard → click **`+ Add machine`**.
2. Copy the generated 15-minute join command (or scan the QR code from the companion app).
3. Run it on your remote machine:
```bash
./target/release/rackdeck agent --controller http://<controller-ip>:7420 --token <rd_join_...>
```

---

## What v0.1 Manages

- **Per-Host Telemetry:** Live CPU, RAM (labeled **Unified Memory** on Apple Silicon), Disk, Network (`↓`/`↑`), and NVIDIA GPU utilization/VRAM/temperature via `nvidia-smi`. *(Note: telemetry and local AI runners are tracked **per host** — Rackdeck does not pool VRAM across separate machines.)*
- **Docker Containers:** List containers, **Deploy** new Docker images (with ports, env vars, and quick presets), `Start` / `Stop` / `Restart`, and stream live `docker logs -f`.
- **Existing Local AI Runners:** Detects running `ninfer`, `mlx_lm.server`, `vllm`, and `ollama serve` processes per host so you see them alongside Docker apps.
- **Browser Terminal (Owner-Only):** Fast interactive shell tab in the bottom drawer with every command recorded in the audit log.
- **LAN & Tailscale Discovery:** Probes Tailscale peers via `tailscale status --json` on port `7420` and generates 60-second QR pairing invitations.
- **Scoped MCP (`/mcp`, Streamable HTTP `2025-11-25`):** Give Cursor, Claude Code, or Codex `read` (`node_health`, `container_logs_tail`) or `deploy` (`app_action`, `deploy_app`) tokens with full audit logging and **zero SSH keys**. Terminal access is never grantable to MCP tokens.
- **Optional Rackdeck Connect (`rackdeck-relay`):** Self-hostable or managed binary tunnel relay (`rackdeck.connect.v1`) for remote access and `*.rackdev.app` / custom HTTPS routes through CGNAT.

> **Looking for a 300+ one-click Docker Compose app catalog today?** Start with [Coolify](https://coolify.io/docs/services/all) — it is far more mature for one-click app templates. Rackdeck is built for people who want a tiny, fast Rust control plane unifying Linux VPSs, NVIDIA GPU boxes, and Macs in a clean Tailscale-style console.

---

## Support Matrix (v0.1)

| Target | Control Plane (`rackdeck`) | Remote Agent (`rackdeck agent`) | Notes |
| :--- | :--- | :--- | :--- |
| **macOS (Apple Silicon `arm64`)** | Tested | Tested | Unified Memory telemetry, native `mlx_lm` / `ollama` detection, Docker optional (OrbStack/Docker Desktop). |
| **Linux (`x86_64` / `arm64`)** | Supported | Supported | Ubuntu 24.04 / Debian recommended; Docker CLI for containers; `nvidia-smi` for NVIDIA GPU/VRAM/temp (`ninfer`, `vLLM`, `Ollama`). |
| **Relay (`rackdeck-relay`)** | — | — | Tested on Linux / macOS; designed for $5–$7 AWS Lightsail + Caddy auto-TLS. |

---

## Permissions, Privacy & Relay Boundaries

- **Zero Product Telemetry:** The open-source binaries send zero analytics, crash reports, or phone-home pings. The only outbound connections `rackdeck` makes are:
  1. Checking in to your own controller (in `rackdeck agent` mode).
  2. Opening a Connect WebSocket tunnel **only** if you explicitly enable Connect.
- **Listening Ports:** `rackdeck` listens on `RACKDECK_PORT` (default `7420`). `rackdeck-relay` listens on `RACKDECK_RELAY_PORT` (default `7430`).
- **Auth & Scoping:**
  - Setting `RACKDECK_PASSWORD` enforces `HttpOnly; SameSite=Lax` cookie sessions on all web UI and `/api/ws` routes.
  - MCP bearer tokens are stored as SHA-256 hashes, scoped to `read` or `deploy`, revocable instantly, and never grant shell access.
  - Join tokens expire after 15 minutes and are single-use; pairing invitations expire after 60 seconds.
- **Relay TLS & Offline Exit Path:**
  - Public HTTPS routes (`*.rackdev.app` or custom domains — kept on a separate registrable domain from `rackdeck.dev` for cookie/origin isolation) terminate TLS at Caddy in front of `rackdeck-relay`; the agent-to-relay tunnel authenticates with an Ed25519 challenge-response handshake (`rackdeck.connect.v1`).
  - If `rackdeck-relay` goes down or you cancel Connect, **your local dashboard, LAN access, Tailscale access, Docker containers, and local SQLite database keep working normally** with zero lock-in.

See [SECURITY.md](./SECURITY.md) and [ARCHITECTURE.md](./ARCHITECTURE.md) for full details.

---

## License & Pricing

- **Core (`rackdeck`, `rackdeck-relay`, embedded UI):** **Apache-2.0** — free to self-host forever with unlimited machines on your own LAN or Tailscale.
- **Optional Managed Services (upcoming):**
  - **Rackdeck Connect ($9/mo):** Hosted global relay, `*.rackdev.app` + custom auto-TLS domains, and push notifications so you don't have to manage Tailscale/CGNAT.
  - **Rackdeck Cloud ($19/mo):** Managed control plane + Connect + encrypted Litestream S3 backups.
