# Security Policy

## Reporting a Vulnerability

Please do **not** open public GitHub issues for security vulnerabilities. Report issues privately via GitHub Security Advisories (or email `security@rackdeck.dev` once configured) with reproduction steps and affected commit/version.

## Security Model (v0.1)

1. **Local vs. Public Exposure:**
   - By default, `rackdeck` is designed for localhost, trusted home LAN, or private Tailscale networks.
   - Before exposing `rackdeck` over public HTTPS, always set `RACKDECK_PASSWORD` and place it behind a TLS reverse proxy (e.g., Caddy in `deploy/aws-lightsail/Caddyfile`).
2. **Authentication & Secrets:**
   - Owner browser sessions use `HttpOnly; SameSite=Lax` cookies (`rackdeck_session`).
   - MCP tokens are generated with 192 bits of CSPRNG entropy, shown once on creation, and stored only as SHA-256 digests in SQLite.
   - MCP tokens are strictly limited to `read` or `deploy` capabilities; interactive shell (`TermExec`), network route mutation, and token management always require an owner session.
   - Node enrollment join tokens are single-use and expire after 15 minutes; QR pairing invitations expire after 60 seconds.
3. **Relay & Billing Verification:**
   - `rackdeck-relay` authenticates agent tunnels using strict Ed25519 signature verification over a fresh 256-bit nonce + audience challenge, with monotonic session generation fencing.
   - Stripe webhook payloads (`POST /_rackdeck/stripe/webhook`) are verified using constant-time HMAC-SHA256 when `RACKDECK_STRIPE_WEBHOOK_SECRET` is configured.
4. **Input Validation:**
   - Container deploys validate container names (`[A-Za-z0-9_-]`, max 63 chars), reject whitespace in image names, validate environment variable keys, and pass arguments directly to `docker` via `Command::args` (never shell-interpolated).
