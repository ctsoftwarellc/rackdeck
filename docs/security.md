# Rackdeck security and connectivity

This page explains how Rackdeck's parts connect, what each connection protects, and where the limits are. It describes the code in this repository. If something here doesn't match the code, the code wins, and please [report it](#reporting-a-problem).

## The parts

| Part | Runs on | What it does |
| --- | --- | --- |
| **Dashboard** (`rackdeck`) | One machine you choose | Serves the web UI and API on port 7420. Stores everything in one SQLite file. Also manages the machine it runs on. |
| **Agent** (`rackdeck agent`) | Every other machine | Reports stats, apps and results to the dashboard every 2 seconds and runs the actions you start. Same binary as the dashboard. |
| **Relay** (`rackdeck-relay`) | A server with a public IP (optional) | Gives a dashboard a public address without opening router ports. Only used if you turn on Connect. |

## Who connects to whom

```
 browser ──HTTPS or LAN──▶ dashboard :7420 ◀──check-ins (encrypted)── agent
                                 │
                                 └──outbound WebSocket (wss://)──▶ relay ◀── browser (public address)
```

- Agents always dial out to the dashboard, so you open no ports on joined machines.
- The dashboard only dials out to the relay, and only when you turn Connect on.
- Nothing connects to a Rackdeck server we run unless you choose a hosted relay.

## Dashboard access

- **No password, no network.** Without `RACKDECK_PASSWORD`, the dashboard listens on `127.0.0.1` only, so nothing else on your network can reach it. Setting a password opens it to your network.
- **Sessions.** Logging in sets an `HttpOnly; SameSite=Lax` cookie. Long-lived web sockets recheck the session before privileged actions, so logging out cuts off an open terminal.
- **Terminal.** Only the logged-in owner can open the terminal, and only on the dashboard's own machine. Each session is written to the audit log (which machine, when). Command text is not stored.
- **Connect needs a password.** Tunnel traffic reaches the dashboard from the machine itself, so the dashboard refuses to turn Connect on without a password.

## Joining a machine

1. **+ Add machine** creates a join token that works once and expires after 15 minutes. Tokens live in memory, so restarting the dashboard cancels unused ones.
2. The join command carries every address the dashboard has (Tailscale and LAN) plus the dashboard's public key (`--key`).
3. The installer tries each address and keeps the first that answers. It checks the token by sending only its SHA-256 hash, so the token itself isn't sent in the clear.
4. The agent's first check-in is encrypted to the dashboard's key and includes the token. The dashboard records the agent's own public key and the token is used up.

The dashboard refuses a join that claims to be the dashboard's own machine.

## Check-ins between agents and the dashboard

Check-ins travel over plain HTTP on your LAN or tailnet, so Rackdeck encrypts and authenticates them itself:

- The dashboard has a static X25519 key, derived from its signing key in `rackdeck.key`. Each agent has its own static X25519 key, created on first run and kept in `agent.json` (mode 0600).
- Every check-in uses a fresh X25519 key. The channel key is SHA-256 over a fixed label, the two Diffie-Hellman results (fresh key with the dashboard's key, agent key with the dashboard's key), and both public keys. Requests and replies are sealed with ChaCha20-Poly1305.
- Only the real dashboard can read a request, because opening it needs the dashboard's private key. Only the real agent can read the reply. A request or reply that someone tampered with fails to open and is dropped.
- The agent pins the dashboard's key from the join command. Someone on the network can't pose as the dashboard without that key.

**Older agents.** Agents from before encrypted check-ins used a bearer key over HTTP. When one updates, it pins the dashboard key from its next check-in, proves itself once with its old key, and switches over. From then on the dashboard refuses the old key for that machine. That pinning step trusts the network once, the way SSH trusts a new host.

## Secrets

- You set a secret once in the dashboard and pick which machines get it.
- **At rest:** values are encrypted with ChaCha20-Poly1305 under a key derived from `rackdeck.key`. The database holds no plain text. Someone with both the database and `rackdeck.key` can decrypt them, so protect the data directory.
- **In transit:** values only travel inside encrypted check-ins, and only when a machine's copy is out of date.
- **On each machine:** they are written to `~/.config/rackdeck/secrets.env`, readable only by you (0600). On Linux the agent runs as root and sets the file's owner to the user who installed it. The installer adds a line to `~/.bashrc` and `~/.zshrc` so new shells load the file.
- The API never returns values, only names and machines. The audit log records the name, never the value.
- Names that change which programs run are refused: `PATH`, `HOME`, `SHELL`, `IFS`, `ENV`, `BASH_ENV`, `PROMPT_COMMAND`, and anything starting with `LD_` or `DYLD_`.

## AI tools (MCP)

- The dashboard has a built-in MCP server at `/mcp`. Claude Code, Codex and Cursor connect with a token.
- Tokens are shown once and stored only as SHA-256 hashes. Each token can read, or read and deploy, and can be limited to certain machines. Tokens never get a terminal, network settings or token management.
- Every call is in the audit log, and tokens can be revoked at any time.

## Updates

- The **Update** button and `rackdeck update` download the latest release from GitHub over HTTPS and swap the file in place.
- **Limit:** the downloaded file isn't yet checked against the published `SHA256SUMS.txt` or a signature, so updates trust GitHub and HTTPS.

## The relay (Connect)

- The dashboard opens an outbound `wss://` connection to the relay and proves who it is by signing a fresh random challenge with its Ed25519 key.
- A public name like `you.rackdev.app` belongs to the first key that claims it. Another key can't take it over.
- On a relay that requires a subscription, a tunnel is only allowed while the account is active. Stripe webhooks must carry a valid signature no older than 5 minutes.
- If the relay goes away, your dashboard, LAN and Tailscale access, apps and data keep working. Nothing depends on it.

## What Rackdeck sends out

The open-source binaries send no analytics, crash reports or usage pings. The outbound connections they make:

- Agents check in to your dashboard.
- When you open the dashboard, your browser asks GitHub for the latest version number. The dashboard and agents download a release only when you click Update or run `rackdeck update`.
- The dashboard connects to a relay only if you turn Connect on.

## Known limits

- Updates aren't checked against checksums or signatures yet.
- The first contact for an older agent pins the dashboard key without proof (see [Older agents](#check-ins-between-agents-and-the-dashboard)).
- The dashboard serves plain HTTP. Use it on your LAN or tailnet, or put HTTPS in front of it before exposing it any other way.
- Anyone who can run commands as you on a machine can read that machine's secrets file.

## Reporting a problem

Please don't open a public issue for a vulnerability. Report it privately through GitHub Security Advisories on this repository with steps to reproduce and the version (`rackdeck --version`).
