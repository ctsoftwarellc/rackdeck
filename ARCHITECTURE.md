# Rackdeck v0.1 — Rust Clean Architecture & Control Panel Design

Synthesized from the **Sol 6.2** Rust systems blueprint and **Opus 5.5** dark-luxury operational UI/UX spec.

## Hexagonal Dependency Graph

Binaries (`rackdeck`, `rackdeck-relay`) are thin composition roots. Infrastructure adapters depend inward on `rackdeck-core` ports and `rackdeck-protocol` wire DTOs; `rackdeck-core` has zero platform, HTTP, or SQLite dependencies.

```text
rackdeck (bin) ──► rackdeck-api ──► rackdeck-protocol
   │                  │
   ├──► rackdeck-node ─┼──► rackdeck-core (domain + ports + authz)
   ├──► rackdeck-store ┤
   ├──► rackdeck-discovery
   └──► rackdeck-connect (feature = "client")

rackdeck-relay (bin) ──► rackdeck-connect (feature = "relay")
                    ├──► rackdeck-store
                    └──► rackdeck-core
```

## Key Design Decisions

1. **All-in-One Single Binary (`rackdeck`):** Boots the control plane, in-process local node sampler, SQLite WAL store (on a dedicated bounded worker thread), multiplexed `/api/ws`, REST actions, `2025-11-25` Streamable HTTP `/mcp`, and embedded React UI (`rust-embed`) in one process targeting ≤15–20 MB idle RSS.
2. **Binary Connect Tunnel (`rackdeck.connect.v1`):** `[type:u8, flags:u8, stream_id:u32, length:u32, payload]` in network byte order over WSS, Ed25519 challenge-response auth with session generation fencing, zero whole-body buffering, and per-tenant byte metering for $5–$7 AWS Lightsail relays.
3. **Operational Dark-Luxury UI (`ui/`):** Adapted from `DESIGN.md` for 8-hour daily ops—56px icon rail, 48px context header (`NodeSwitcher`, `⌘K` palette, `● Live RTT` pill), hardware-aware telemetry tiles (NVIDIA VRAM/temp, Apple Silicon Unified Memory, or clean no-GPU), Apps & AI runners table (`ninfer`, `MLX`, `vLLM`, `Ollama`, Docker), resizable bottom Logs/Terminal drawer, LAN/Tailscale discovery + 2-second QR pairing, Rackdeck Connect routes, and scoped MCP tokens + audit trail.
