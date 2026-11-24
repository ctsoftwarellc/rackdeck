# Rackdeck

One dashboard for the computers you own: a Mac, a GPU box, a home server, a VPS.

Rackdeck is a single file of about 6 MB with the web dashboard built in. It used about 13 MB of RAM on an M-series MacBook in our testing. It doesn't need Docker, Postgres or Redis; its data lives in one SQLite file. It's open source under Apache-2.0, needs no account, and sends no analytics.

**[Try the live demo](https://rackdeck.dev/demo/)** · [Install](#install) · [Add a machine](#add-a-machine) · [Features](#what-you-can-do) · [Security](docs/security.md)

## Install

```bash
curl -fsSL https://get.rackdeck.dev | sh
RACKDECK_PASSWORD='choose-a-strong-password' rackdeck
```

Open http://localhost:7420 and log in with that password.

Without `RACKDECK_PASSWORD`, Rackdeck only listens on this machine, so nothing else on your network can reach it. Set a password to open it from your phone or another computer, or to add machines.

To run the dashboard as a background service that starts at boot:

```bash
curl -fsSL https://get.rackdeck.dev | RACKDECK_PASSWORD='choose-a-strong-password' sh -s -- --service
```

## Add a machine

1. In the dashboard, click **+ Add machine** and copy the command.
2. Run it on the other machine.

The machine shows up within a few seconds. The command works once and expires after 15 minutes. The installer tries each of the dashboard's addresses (Tailscale and your home network) and uses the one that answers, sets the agent up as a service, and tells you plainly if something is wrong, such as an expired command.

Joined machines connect out to the dashboard, so you don't open any ports on them. Their check-ins are encrypted and signed both ways. On Windows, use WSL with systemd turned on; the installer explains how if it's off.

## What you can do

- **See every machine at once.** Live CPU, memory, disk, network, and NVIDIA GPU use, VRAM and temperature. Machines that stop reporting show as offline within about 20 seconds.
- **Manage apps.** Docker containers and local model servers (Ollama, vLLM, `mlx_lm`). Start, stop, restart, deploy an image, and follow logs.
- **Use a terminal in the browser** on the dashboard's machine. Owner only, and each session goes in the audit log.
- **Push secrets to your machines.** Set an environment variable once, like `CLAUDE_CODE_OAUTH_TOKEN`, pick machines, and new terminals on those machines have it. Values are encrypted in storage and on the way.
- **Let AI coding tools help.** The built-in MCP server lets Claude Code, Codex or Cursor read status or deploy apps with a token you scope and can revoke. Tokens never get a terminal.
- **Update everything with one button.** When a new version is out, **Update all** updates each joined machine and then the dashboard, without reinstalling.
- **Find your tailnet.** If Tailscale is installed, Rackdeck lists your other devices. It only reads; it never signs into your Tailscale account.
- **Check the audit log** for joins, updates, app actions, secret changes and AI tool calls.

## Platforms

| | Dashboard | Agent | Prebuilt download |
| --- | --- | --- | --- |
| macOS, Apple Silicon | Yes | Yes | Yes |
| Linux, x86_64 | Yes | Yes | Yes |
| Linux, arm64 (Raspberry Pi 4/5) | Builds, not yet tested | Builds, not yet tested | Not yet, [build from source](#build-from-source) |
| Windows | Through WSL | Through WSL | Linux build inside WSL |

## Set up with an AI agent

Paste this into Claude Code, Codex or Cursor on the machine you want as the dashboard:

```text
Install Rackdeck (https://github.com/ctsoftwarellc/rackdeck) on this machine as a background service.
1. Generate a strong password, or ask me for one.
2. Run: curl -fsSL https://get.rackdeck.dev | RACKDECK_PASSWORD='<password>' sh -s -- --service
3. Check it's healthy: curl -sf http://127.0.0.1:7420/api/v1/health
4. Tell me the URL to open, the password, and how to add my next machine (+ Add machine in the dashboard).
Don't open router ports or expose port 7420 to the internet.
```

## Build from source

Needs Rust and Bun.

```bash
cd ui && bun install && bun run build && cd ..
cargo build --release -p rackdeck
RACKDECK_PASSWORD='choose-a-strong-password' ./target/release/rackdeck
```

## Security

How the dashboard, agents and relay connect, how check-ins and secrets are encrypted, and the known limits: [docs/security.md](docs/security.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Pricing

- **Rackdeck Community** is free forever. Everything in this repository, self-hosted, with no limit on machines.
- **Rackdeck Cloud** ($19/month or $190/year) will host the dashboard, connectivity, remote MCP access, updates and backups for you. It isn't open yet.

## License

Apache-2.0
