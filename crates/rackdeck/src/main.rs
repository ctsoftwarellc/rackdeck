use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rackdeck_api::{build_router, update, AgentBus, ApiState, AssetProvider};
use rackdeck_core::{FleetRepository, FleetService, NodeOps, NodeStatus};
use rackdeck_discovery::NetworkDiscovery;
use rackdeck_node::LocalNodeAdapter;
use rackdeck_protocol::{AgentCommand, AgentCommandResult, AgentOp, AgentOutput, ServerWsEvent};
use rackdeck_store::SqliteStore;
use rust_embed::Embed;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing_subscriber::EnvFilter;

#[derive(Embed)]
#[folder = "../../ui/dist"]
struct EmbeddedUi;

struct UiAssetProvider;

impl AssetProvider for UiAssetProvider {
    fn get_asset(&self, path: &str) -> Option<(Vec<u8>, String)> {
        let file = EmbeddedUi::get(path)?;
        let mime = mime_guess::from_path(path)
            .first_or_octet_stream()
            .as_ref()
            .to_string();
        Some((file.data.into_owned(), mime))
    }
}

fn load_or_create_signing_key(db_path: &str) -> SigningKey {
    if db_path == ":memory:" {
        let mut csprng = rand::rngs::OsRng;
        return SigningKey::generate(&mut csprng);
    }
    let key_path = std::path::Path::new(db_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("rackdeck.key");

    if let Ok(bytes) = std::fs::read(&key_path) {
        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return SigningKey::from_bytes(&arr);
        }
    }

    let mut csprng = rand::rngs::OsRng;
    let key = SigningKey::generate(&mut csprng);
    if std::fs::write(&key_path, key.to_bytes()).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    key
}

pub async fn build_all_in_one_state(
    port: u16,
    db_path: &str,
    relay_ws_url: String,
    embed_ui: bool,
) -> Result<ApiState, String> {
    let store = SqliteStore::open(db_path).map_err(|e| e.to_string())?;
    let local_node = Arc::new(LocalNodeAdapter::new(port));
    let initial_node = local_node.inspect_node().await.map_err(|e| e.to_string())?;
    let initial_apps = local_node.list_apps().await.unwrap_or_default();
    let initial_sample = local_node.sample().await.ok();
    store
        .upsert_node(initial_node.clone())
        .await
        .map_err(|e| e.to_string())?;

    // Remote machines are online once they check in; until then they're offline, not "last known".
    for mut n in store.list_nodes().await.unwrap_or_default() {
        if n.id != initial_node.id && n.status != NodeStatus::Offline {
            n.status = NodeStatus::Offline;
            let _ = store.upsert_node(n).await;
        }
    }

    let signing_key = Arc::new(load_or_create_signing_key(db_path));
    let (ws_tx, _) = broadcast::channel::<ServerWsEvent>(256);

    let agent_bus = Arc::new(AgentBus::default());
    let fleet_svc = Arc::new(FleetService {
        fleet: store.clone(),
        audit: store.clone(),
        local_node: local_node.clone(),
        local_node_id: initial_node.id.clone(),
        remote: agent_bus.clone(),
    });

    let state = ApiState {
        local_node_id: initial_node.id.clone(),
        listen_port: port,
        relay_ws_url,
        signing_key,
        fleet_svc,
        fleet_repo: store.clone(),
        route_repo: store.clone(),
        token_repo: store.clone(),
        audit_repo: store.clone(),
        discovery: Arc::new(NetworkDiscovery),
        local_node: local_node.clone(),
        latest_sample: Arc::new(RwLock::new(initial_sample)),
        latest_apps: Arc::new(RwLock::new(initial_apps)),
        remote_apps: Arc::new(RwLock::new(HashMap::new())),
        join_tokens: Arc::new(RwLock::new(HashMap::new())),
        agent_bus,
        owner_password: std::env::var("RACKDECK_PASSWORD").ok().filter(|s| !s.is_empty()),
        owner_sessions: Arc::new(RwLock::new(HashMap::new())),
        ws_tx,
        connect_handle: Arc::new(Mutex::new(None)),
        assets: if embed_ui {
            Some(Arc::new(UiAssetProvider))
        } else {
            None
        },
    };

    // Background 1Hz telemetry + 5s app refresh sampler
    let bg_state = state.clone();
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            tick += 1;
            if let Ok(sample) = bg_state.local_node.sample().await {
                *bg_state.latest_sample.write().await = Some(sample.clone());
                let _ = bg_state.ws_tx.send(ServerWsEvent::Tm {
                    node_id: bg_state.local_node_id.clone(),
                    s: sample,
                });
            }
            if tick % 5 == 0 {
                mark_stale_nodes_offline(&bg_state).await;
                if let Ok(apps) = bg_state.local_node.list_apps().await {
                    *bg_state.latest_apps.write().await = apps.clone();
                    let mut combined = apps;
                    for list in bg_state.remote_apps.read().await.values() {
                        combined.extend(list.clone());
                    }
                    let _ = bg_state.ws_tx.send(ServerWsEvent::Apps {
                        node_id: bg_state.local_node_id.clone(),
                        apps: combined,
                    });
                }
            }
        }
    });

    Ok(state)
}

/// Agents that stopped checking in: flag offline and drop their cached apps so nothing shows "running".
async fn mark_stale_nodes_offline(state: &ApiState) {
    for id in state.agent_bus.take_stale().await {
        state.remote_apps.write().await.remove(&id);
        if let Ok(Some(mut node)) = state.fleet_repo.get_node(&id).await {
            node.status = NodeStatus::Offline;
            let _ = state.fleet_repo.upsert_node(node.clone()).await;
            let _ = state.ws_tx.send(ServerWsEvent::Node { node });
        }
    }
}

/// What an agent remembers between runs: its machine id and the key the controller issued.
#[derive(Default)]
struct AgentState {
    node_id: String,
    agent_key: Option<String>,
}

fn agent_state_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("RACKDECK_AGENT_STATE") {
        return p.into();
    }
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => std::path::Path::new(&home).join(".config/rackdeck/agent.json"),
        _ => "/var/lib/rackdeck/agent.json".into(),
    }
}

fn save_agent_state(path: &std::path::Path, st: &AgentState) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let json = serde_json::json!({ "nodeId": st.node_id, "agentKey": st.agent_key }).to_string();
    if let Err(e) = std::fs::write(path, json) {
        tracing::warn!("couldn't save agent state to {}: {e}", path.display());
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

async fn run_remote_agent(controller: String, initial_token: String) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let state_path = agent_state_path();
    let mut saved = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .map(|v| AgentState {
            node_id: v["nodeId"].as_str().unwrap_or_default().to_string(),
            agent_key: v["agentKey"].as_str().map(str::to_string),
        })
        .unwrap_or_default();
    if saved.node_id.is_empty() {
        // Hostname plus a random suffix, so two boxes called `ubuntu` stay separate machines.
        let base = LocalNodeAdapter::new(7420).node_id().to_string();
        saved.node_id = format!("{base}-{:06x}", rand::random::<u32>() & 0xff_ffff);
        save_agent_state(&state_path, &saved);
    }
    let local = Arc::new(LocalNodeAdapter::new(7420).with_node_id(saved.node_id.clone()));
    let host_port = controller
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .ok_or("invalid controller url")?
        .to_string();

    // A saved key survives restarts; the one-time join token is only a fallback for first contact.
    let mut join_token = Some(initial_token);
    let mut bearer = match saved.agent_key.clone() {
        Some(k) => k,
        None => join_token.take().unwrap_or_default(),
    };
    let mut enrolled = false;
    let mut last_err: Option<String> = None;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    // Finished command results wait here until a check-in delivers them.
    let mut results: Vec<AgentCommandResult> = Vec::new();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<AgentCommandResult>();
    tracing::info!("rackdeck agent connecting to {controller} as {}", local.callsign());

    loop {
        // Check in every 2s, or right away when a command finishes so the UI isn't kept waiting.
        tokio::select! {
            _ = interval.tick() => {}
            Some(r) = done_rx.recv() => results.push(r),
        }
        while let Ok(r) = done_rx.try_recv() {
            results.push(r);
        }
        let node = match local.inspect_node().await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("local node inspection failed: {e}");
                continue;
            }
        };
        let sample = local.sample().await.ok();
        let apps = local.list_apps().await.unwrap_or_default();
        let payload = serde_json::json!({ "node": node, "sample": sample, "apps": apps, "results": results }).to_string();

        let connect_res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&host_port),
        )
        .await;

        let mut stream = match connect_res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let msg = format!("cannot connect to {host_port}: {e}");
                if last_err.as_deref() != Some(&msg) {
                    tracing::warn!("{msg} (check controller IP/port or try LAN IP if inside WSL)");
                    last_err = Some(msg);
                }
                continue;
            }
            Err(_) => {
                let msg = format!("timed out connecting to {host_port} after 5s");
                if last_err.as_deref() != Some(&msg) {
                    tracing::warn!("{msg} (Tailscale/firewall may be blocking route — try controller LAN IP)");
                    last_err = Some(msg);
                }
                continue;
            }
        };

        let req = format!(
            "POST /api/v1/agent/checkin HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        if let Err(e) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(req.as_bytes()),
        )
        .await
        {
            let msg = format!("failed writing checkin to {host_port}: {e}");
            if last_err.as_deref() != Some(&msg) {
                tracing::warn!("{msg}");
                last_err = Some(msg);
            }
            continue;
        }

        let mut raw = String::new();
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_string(&mut raw),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                let msg = format!("failed reading response from {host_port}: {e}");
                if last_err.as_deref() != Some(&msg) {
                    tracing::warn!("{msg}");
                    last_err = Some(msg);
                }
                continue;
            }
            Err(_) => {
                let msg = format!("timed out waiting for response from {host_port}");
                if last_err.as_deref() != Some(&msg) {
                    tracing::warn!("{msg}");
                    last_err = Some(msg);
                }
                continue;
            }
        }

        let status_line = raw.lines().next().unwrap_or("").trim().to_string();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").trim();
        if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
            if status_line.contains(" 401") {
                if let Some(t) = join_token.take() {
                    tracing::info!("saved agent key was rejected, trying the join token instead");
                    bearer = t;
                    continue;
                }
            }
            let msg = format!("controller {host_port} rejected checkin: {status_line} ({body})");
            if last_err.as_deref() != Some(&msg) {
                tracing::warn!("{msg}");
                last_err = Some(msg);
            }
            continue;
        }

        if last_err.is_some() {
            tracing::info!("reconnected to controller {controller}");
            last_err = None;
        }

        // An update result has now reached the controller, so it's safe to restart into the new binary.
        let restart = results
            .iter()
            .any(|r| matches!(r.result, Ok(AgentOutput::Updated { version: Some(_) })));
        results.clear(); // delivered
        if restart {
            tracing::info!("updated, restarting agent");
            let err = update::restart_self();
            tracing::warn!("couldn't restart after update ({err}); exiting so the service manager restarts it");
            std::process::exit(1);
        }

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
            let commands: Vec<AgentCommand> = val
                .get("commands")
                .and_then(|c| serde_json::from_value(c.clone()).ok())
                .unwrap_or_default();
            for cmd in commands {
                let local = local.clone();
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    tracing::info!("running {:?} from controller", cmd.op);
                    let result = run_agent_command(local.as_ref(), cmd.op).await;
                    let _ = done_tx.send(AgentCommandResult { id: cmd.id, result });
                });
            }
            if let Some(k) = val.get("agentKey").and_then(|v| v.as_str()) {
                bearer = k.to_string();
                saved.agent_key = Some(bearer.clone());
                save_agent_state(&state_path, &saved);
                enrolled = true;
                tracing::info!("connected & enrolled with controller {controller} as {}", local.callsign());
            } else if !enrolled {
                enrolled = true;
                tracing::info!("connected to controller {controller} as {}", local.callsign());
            }
        }
    }
}

async fn run_agent_command(local: &LocalNodeAdapter, op: AgentOp) -> Result<AgentOutput, String> {
    match op {
        AgentOp::AppAction { app_id, action } => local.app_action(&app_id, action).await.map(|_| AgentOutput::Done),
        AgentOp::Deploy { spec } => local.deploy_app(spec).await.map(|app| AgentOutput::App { app }),
        AgentOp::Logs { app_id, lines } => local.tail_logs(&app_id, lines).await.map(|lines| AgentOutput::Lines { lines }),
        AgentOp::Update => return update::self_update().await.map(|version| AgentOutput::Updated { version }),
    }
    .map_err(|e| e.to_string())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    if matches!(args.get(1).map(|s| s.as_str()), Some("--help" | "-h" | "help")) {
        println!(
            "Rackdeck {}\n\nUsage:\n  rackdeck                                              Start control plane + local node (default :7420)\n  rackdeck agent --controller <URL> --token <TOKEN>     Join a remote machine to a controller\n  rackdeck update                                       Install the latest release over this binary\n\nEnvironment:\n  RACKDECK_PORT       HTTP listen port (default: 7420)\n  RACKDECK_DB         SQLite database path (default: rackdeck.db)\n  RACKDECK_PASSWORD   Require login; without it Rackdeck only listens on 127.0.0.1\n  RACKDECK_RELAY_URL  Connect relay WebSocket URL",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if matches!(args.get(1).map(|s| s.as_str()), Some("--version" | "-V")) {
        println!("rackdeck {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.get(1).map(|s| s.as_str()) == Some("update") {
        // Running services pick up the new binary on their next restart (or use Update in the dashboard).
        match update::self_update().await {
            Ok(Some(v)) => println!("Updated rackdeck {} -> {v}. Restart rackdeck (or its service) to use it.", update::CURRENT),
            Ok(None) => println!("rackdeck {} is already the latest.", update::CURRENT),
            Err(e) => {
                eprintln!("update failed: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }
    if args.get(1).map(|s| s.as_str()) == Some("agent") {
        let mut controller = std::env::var("RACKDECK_CONTROLLER").unwrap_or_default();
        let mut token = std::env::var("RACKDECK_JOIN_TOKEN").unwrap_or_default();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--controller" if i + 1 < args.len() => {
                    controller = args[i + 1].clone();
                    i += 2;
                }
                "--token" | "--join" if i + 1 < args.len() => {
                    token = args[i + 1].clone();
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if controller.is_empty() || token.is_empty() {
            eprintln!("Usage: rackdeck agent --controller <http://host:7420> --token <join-token>");
            std::process::exit(2);
        }
        return run_remote_agent(controller, token).await;
    }

    if let Some(cmd) = args.get(1) {
        // Don't fall through to starting the server on a typo or a command this version doesn't know.
        eprintln!("unknown command `{cmd}`. Run `rackdeck --help`.");
        std::process::exit(2);
    }

    let port: u16 = std::env::var("RACKDECK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7420);
    let db_path = std::env::var("RACKDECK_DB").unwrap_or_else(|_| "rackdeck.db".into());
    let relay_ws_url = std::env::var("RACKDECK_RELAY_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:7430/_rackdeck/tunnel".into());

    let state = build_all_in_one_state(port, &db_path, relay_ws_url, true).await?;
    let node_id = state.local_node_id.clone();

    let password_set = state.owner_password.is_some();
    let app = build_router(state);

    // Without a password anyone who can reach the port is the owner (terminal included),
    // so only listen on this machine until one is set.
    let ip = if password_set { [0, 0, 0, 0] } else { [127, 0, 0, 1] };
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((ip, port))).await?;
    if password_set {
        tracing::info!("rackdeck listening on port {port} on all interfaces (node={node_id})");
    } else {
        tracing::warn!(
            "no RACKDECK_PASSWORD set: only reachable from this machine at http://127.0.0.1:{port}. \
             Set RACKDECK_PASSWORD to open it to other devices and let machines join."
        );
    }
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rackdeck_connect::relay::{relay_router, RelayState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    async fn http_post_json(addr: SocketAddr, path: &str, body: &str, auth: Option<&str>) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let auth_hdr = auth
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{auth_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn end_to_end_all_in_one_mcp_and_binary_connect_relay() {
        // 1. Start Rackdeck Connect Relay on ephemeral port
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();
        let relay_state = RelayState::new("connect.rackdeck.dev", None);
        let relay_state_check = relay_state.clone();
        tokio::spawn(async move {
            let _ = axum::serve(relay_listener, relay_router(relay_state)).await;
        });

        // 2. Start All-in-One Rackdeck Server on ephemeral port
        let server_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let state = build_all_in_one_state(
            server_addr.port(),
            ":memory:",
            format!("ws://{relay_addr}/_rackdeck/tunnel"),
            false,
        )
        .await
        .unwrap();
        let app = build_router(state);
        tokio::spawn(async move {
            let _ = axum::serve(server_listener, app).await;
        });

        // 3. Verify live node inspection
        let nodes_res = http_get(server_addr, "/api/v1/nodes").await;
        assert!(nodes_res.contains("200 OK"), "nodes response: {nodes_res}");
        assert!(nodes_res.contains("cpuCores"));

        // 4. Create a read-scoped MCP token & verify read succeeds while deploy action is denied
        let create_res = http_post_json(
            server_addr,
            "/api/v1/tokens",
            r#"{"name":"cursor-test","client":"Cursor","scope":"read"}"#,
            None,
        )
        .await;
        assert!(create_res.contains("200 OK"));
        let body = create_res.split("\r\n\r\n").nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let token = parsed["token"].as_str().unwrap();

        let mcp_ok = http_post_json(
            server_addr,
            "/mcp",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"node_health","arguments":{}}}"#,
            Some(token),
        )
        .await;
        assert!(mcp_ok.contains("200 OK"));

        let mcp_denied = http_post_json(
            server_addr,
            "/mcp",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"app_action","arguments":{"appId":"docker:demo","action":"restart"}}}"#,
            Some(token),
        )
        .await;
        assert!(mcp_denied.contains("403 Forbidden"), "expected 403: {mcp_denied}");

        // 5. Enable Rackdeck Connect (Ed25519 challenge-response + binary wire proxy)
        let toggle_res = http_post_json(
            server_addr,
            "/api/v1/connect",
            r#"{"enabled":true,"slug":"home-box"}"#,
            None,
        )
        .await;
        assert!(toggle_res.contains("200 OK"));

        for _ in 0..30 {
            if relay_state_check.has_tunnel("home-box").await {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(relay_state_check.has_tunnel("home-box").await);

        // 6. Proxy HTTP through the binary Connect relay -> local Rackdeck server!
        let proxied = http_get(relay_addr, "/connect/home-box/api/v1/health").await;
        assert!(proxied.contains("200 OK"), "proxied response: {proxied}");
        assert!(proxied.contains("\"service\":\"rackdeck\""));

        // 7. Mint a 15-minute join token and enroll a remote GPU node via /api/v1/agent/checkin
        let join_res = http_post_json(server_addr, "/api/v1/join-token", "{}", None).await;
        assert!(join_res.contains("200 OK"));
        let join_body: serde_json::Value =
            serde_json::from_str(join_res.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let join_tok = join_body["token"].as_str().unwrap();

        // A join token can't be used to impersonate the controller itself.
        let local_id = http_get(server_addr, "/api/v1/health").await;
        let local_id = serde_json::from_str::<serde_json::Value>(local_id.split("\r\n\r\n").nth(1).unwrap())
            .unwrap()["nodeId"]
            .as_str()
            .unwrap()
            .to_string();

        let checkin_payload = r#"{"node":{"id":"node-home-5090","name":"HOME-5090","kind":"gpu","os":"Ubuntu 24.04","kernel":"6.11","status":"online","lastSeen":1700000000,"uptimeSecs":4200,"hw":{"cpuCores":16,"ramTotalMb":65536,"diskTotalGb":2000,"accel":{"kind":"nvidia","gpus":[{"idx":0,"name":"RTX 5090","vramTotalMb":32768}],"driver":"570","driverLoaded":true}},"docker":"running","version":"0.1.0","lanIp":"192.168.1.50","tailscaleIp":"100.88.1.50","connectSlug":"home-5090","connectEnabled":false},"sample":{"t":1700000000,"cpu":12.5,"memMb":16384,"diskGb":420,"netRxBps":12000,"netTxBps":4000,"gpu":[84.0],"vramMb":[27648],"tempC":68.0},"apps":[{"id":"ai:ninfer","nodeId":"node-home-5090","name":"ninfer","type":"ai","runner":"ninfer","model":"Qwen3.8-27B","state":"running","ports":[8080],"domains":[],"usage":{"cpu":4.0,"memMb":2048,"vramMb":27648}}]}"#;
        let spoof = checkin_payload.replacen(r#""id":"node-home-5090""#, &format!(r#""id":"{local_id}""#), 1);
        let spoof_res = http_post_json(server_addr, "/api/v1/agent/checkin", &spoof, Some(join_tok)).await;
        assert!(spoof_res.contains("403"), "controller id should be reserved: {spoof_res}");
        let checkin_res = http_post_json(
            server_addr,
            "/api/v1/agent/checkin",
            checkin_payload,
            Some(join_tok),
        )
        .await;
        assert!(checkin_res.contains("200 OK"), "checkin failed: {checkin_res}");
        assert!(checkin_res.contains("rd_agent_"));

        let fleet_after = http_get(server_addr, "/api/v1/nodes").await;
        assert!(fleet_after.contains("HOME-5090"), "remote node not in fleet: {fleet_after}");

        // 8. Verify MCP deploy_app tool is blocked for read-scoped tokens
        let deploy_denied = http_post_json(
            server_addr,
            "/mcp",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"deploy_app","arguments":{"name":"redis","image":"redis:7-alpine"}}}"#,
            Some(token),
        )
        .await;
        assert!(deploy_denied.contains("403 Forbidden"), "expected 403: {deploy_denied}");

        // 9. UI asks for logs on the remote node: controller queues the command, the agent
        //    picks it up on check-in and posts the result on the next one.
        let checkin_body: serde_json::Value =
            serde_json::from_str(checkin_res.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let agent_key = checkin_body["agentKey"].as_str().unwrap().to_string();
        let logs_req = tokio::spawn(async move {
            http_get(server_addr, "/api/v1/nodes/node-home-5090/apps/docker:abc/logs").await
        });
        let mut cmd = serde_json::Value::Null;
        for _ in 0..50 {
            let res = http_post_json(server_addr, "/api/v1/agent/checkin", checkin_payload, Some(&agent_key)).await;
            let body: serde_json::Value = serde_json::from_str(res.split("\r\n\r\n").nth(1).unwrap()).unwrap();
            if let Some(c) = body["commands"].as_array().and_then(|c| c.first()) {
                cmd = c.clone();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(cmd["op"]["kind"], "logs", "agent never received the logs command: {cmd}");
        assert_eq!(cmd["op"]["appId"], "docker:abc");

        let mut reply: serde_json::Value = serde_json::from_str(checkin_payload).unwrap();
        reply["results"] = serde_json::json!([{ "id": cmd["id"], "result": { "Ok": { "kind": "lines", "lines": ["hello from 5090"] } } }]);
        http_post_json(server_addr, "/api/v1/agent/checkin", &reply.to_string(), Some(&agent_key)).await;
        let logs_res = logs_req.await.unwrap();
        assert!(logs_res.contains("hello from 5090"), "remote logs not relayed: {logs_res}");
    }
}
