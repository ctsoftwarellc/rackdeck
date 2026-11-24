# Rackdeck

**All your machines in one clean, secure dashboard — home PCs, NVIDIA GPU rigs, Apple Silicon Macs, and cloud VPSs.**

Built as a single Rust binary (`rackdeck`, ~4.7 MB) with an embedded React UI and bundled SQLite (WAL). Works 100% free on your home LAN or existing Tailscale/WireGuard network with **no account required** and **zero product telemetry**.

[Quickstart](#quickstart-account-free) · **[Set up with an AI agent](#set-up-with-an-ai-agent)** · [What v0.1 manages](#what-v01-manages) · [Support matrix](#support-matrix-v01) · [Security](#permissions-privacy--relay-boundaries)

---

## Quickstart (Account-Free)

### Install prebuilt binary (Linux `x86_64` & macOS Apple Silicon)
```bash
curl -fsSL https://get.rackdeck.dev | sh

# Start all-in-one control plane + local node (http://127.0.0.1:7420)
RACKDECK_PASSWORD="choose-a-strong-password" rackdeck
```

### Or build from source (requires Rust + Bun)
```bash
cd ui && bun install && bun run build && cd ..
cargo build --release -p rackdeck -p rackdeck-relay
RACKDECK_PASSWORD="choose-a-strong-password" ./target/release/rackdeck
```

### Join a second machine (VPS, GPU rig, or Mac)
1. Open the dashboard → click **`+ Add machine`**.
2. Copy the generated 15-minute join command (or scan the QR code from your phone).
3. Run it on your remote machine:
```bash
rackdeck agent --controller http://<controller-ip>:7420 --token <rd_join_...>
```

---

## Set up with an AI agent

Using **Claude Code, Codex, Cursor, OpenCode, or Antigravity**? Copy the prompt below and paste it into your agent — it will install Rackdeck on your machine, set a strong password, wire up a background service so it survives reboots, and verify everything is running cleanly.

```text
Install and set up Rackdeck (https://github.com/ctsoftwarellc/rackdeck) on this machine so I can manage my servers, containers, and local GPUs/models from one dashboard.

Please do the following step by step:
1. Check this machine's OS, CPU arch, whether Docker is installed, whether nvidia-smi or Apple Silicon is present, and whether Tailscale is connected (`tailscale ip -4`).
2. Install the Rackdeck binary using:
   curl -fsSL https://get.rackdeck.dev | sh
   (If my OS/arch isn't in prebuilt releases yet, clone https://github.com/ctsoftwarellc/rackdeck and build from source with bun + cargo.)
3. Create a persistent data directory (`~/.local/share/rackdeck` on macOS/user Linux or `/var/lib/rackdeck` for system-wide Linux) and generate a strong random password for `RACKDECK_PASSWORD` (ask me if I prefer my own).
4. Set up Rackdeck as a background service that starts on boot:
   - On Linux: create and enable a systemd service running `/usr/local/bin/rackdeck` with `RACKDECK_PORT=7420`, `RACKDECK_DB=<data-dir>/rackdeck.db`, and `RACKDECK_PASSWORD` in an env file with `0600` permissions.
   - On macOS: create and load a LaunchAgent plist (`~/Library/LaunchAgents/dev.rackdeck.plist`) with `RACKDECK_PORT=7420`, `RACKDECK_DB=<data-dir>/rackdeck.db`, and `RACKDECK_PASSWORD`.
   - Do NOT open any router ports or expose port 7420 publicly to the internet unless I explicitly ask.
5. Verify it is healthy with `curl -sf http://127.0.0.1:7420/api/v1/health`.
6. Give me:
   - The local URL (`http://127.0.0.1:7420`) and Tailscale URL (if Tailscale is running)
   - My login password and where the env/service file lives
   - The exact one-liner to add my next machine (`rackdeck agent --controller ... --token ...`)
   - Ask if I also want to link a second machine or set up a read-only MCP token.
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
