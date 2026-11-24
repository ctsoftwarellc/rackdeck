use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rackdeck_api::{build_router, ApiState, AssetProvider};
use rackdeck_core::{FleetRepository, FleetService, NodeOps};
use rackdeck_discovery::NetworkDiscovery;
use rackdeck_node::LocalNodeAdapter;
use rackdeck_protocol::ServerWsEvent;
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

    let signing_key = Arc::new(load_or_create_signing_key(db_path));
    let (ws_tx, _) = broadcast::channel::<ServerWsEvent>(256);

    let fleet_svc = Arc::new(FleetService {
        fleet: store.clone(),
        audit: store.clone(),
        local_node: local_node.clone(),
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
        agent_keys: Arc::new(RwLock::new(HashMap::new())),
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

async fn run_remote_agent(controller: String, initial_token: String) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let local = LocalNodeAdapter::new(7420);
    let host_port = controller
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .ok_or("invalid controller url")?
        .to_string();

    let mut bearer = initial_token;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    tracing::info!("rackdeck agent connecting to {controller} as {}", local.callsign());

    loop {
        interval.tick().await;
        let Ok(node) = local.inspect_node().await else { continue };
        let sample = local.sample().await.ok();
        let apps = local.list_apps().await.unwrap_or_default();
        let payload = serde_json::json!({ "node": node, "sample": sample, "apps": apps }).to_string();

        if let Ok(mut stream) = TcpStream::connect(&host_port).await {
            let req = format!(
                "POST /api/v1/agent/checkin HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            if stream.write_all(req.as_bytes()).await.is_ok() {
                let mut raw = String::new();
                if stream.read_to_string(&mut raw).await.is_ok() {
                    if let Some(body) = raw.split("\r\n\r\n").nth(1) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(body) {
                            if let Some(k) = val.get("agentKey").and_then(|v| v.as_str()) {
                                bearer = k.to_string();
                                tracing::info!("enrolled with controller; persistent agent key bound");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    if matches!(args.get(1).map(|s| s.as_str()), Some("--help" | "-h" | "help")) {
        println!(
            "Rackdeck {}\n\nUsage:\n  rackdeck                                              Start control plane + local node (default :7420)\n  rackdeck agent --controller <URL> --token <TOKEN>     Join a remote machine to a controller\n\nEnvironment:\n  RACKDECK_PORT       HTTP listen port (default: 7420)\n  RACKDECK_DB         SQLite database path (default: rackdeck.db)\n  RACKDECK_PASSWORD   Enable HttpOnly session login\n  RACKDECK_RELAY_URL  Connect relay WebSocket URL",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if matches!(args.get(1).map(|s| s.as_str()), Some("--version" | "-V")) {
        println!("rackdeck {}", env!("CARGO_PKG_VERSION"));
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

    let port: u16 = std::env::var("RACKDECK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7420);
    let db_path = std::env::var("RACKDECK_DB").unwrap_or_else(|_| "rackdeck.db".into());
    let relay_ws_url = std::env::var("RACKDECK_RELAY_URL")
        .unwrap_or_else(|_| "ws://127.0.0.1:7430/_rackdeck/tunnel".into());

    let state = build_all_in_one_state(port, &db_path, relay_ws_url, true).await?;
    let node_id = state.local_node_id.clone();
    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("rackdeck all-in-one listening on http://127.0.0.1:{port} (node={node_id})");
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

        let checkin_payload = r#"{"node":{"id":"node-home-5090","name":"HOME-5090","kind":"gpu","os":"Ubuntu 24.04","kernel":"6.11","status":"online","lastSeen":1700000000,"uptimeSecs":4200,"hw":{"cpuCores":16,"ramTotalMb":65536,"diskTotalGb":2000,"accel":{"kind":"nvidia","gpus":[{"idx":0,"name":"RTX 5090","vramTotalMb":32768}],"driver":"570","driverLoaded":true}},"docker":"running","version":"0.1.0","lanIp":"192.168.1.50","tailscaleIp":"100.88.1.50","connectSlug":"home-5090","connectEnabled":false},"sample":{"t":1700000000,"cpu":12.5,"memMb":16384,"diskGb":420,"netRxBps":12000,"netTxBps":4000,"gpu":[84.0],"vramMb":[27648],"tempC":68.0},"apps":[{"id":"ai:ninfer","nodeId":"node-home-5090","name":"ninfer","type":"ai","runner":"ninfer","model":"Qwen3.8-27B","state":"running","ports":[8080],"domains":[],"usage":{"cpu":4.0,"memMb":2048,"vramMb":27648}}]}"#;
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
    }
}
