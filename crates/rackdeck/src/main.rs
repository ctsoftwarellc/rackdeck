use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rackdeck_api::{build_router, seal, update, AgentBus, ApiState, AssetProvider};
use rackdeck_core::{
    now_unix_secs, AppActionResult, FleetRepository, FleetService, NodeOps, NodeStatus,
};
use rackdeck_discovery::NetworkDiscovery;
use rackdeck_node::LocalNodeAdapter;
use rackdeck_protocol::{
    AgentCommand, AgentCommandResult, AgentOp, AgentOutput, ServerWsEvent, MAX_CHECKIN_BODY_BYTES,
};
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

/// This machine's id, saved next to the database on first run. The hostname can change with the
/// network (Mac.attlocal.net vs Mac), and a new id would make the dashboard show its own machine twice.
fn dashboard_node(port: u16, db_path: &str) -> LocalNodeAdapter {
    let node = LocalNodeAdapter::new(port);
    if db_path == ":memory:" {
        return node;
    }
    let id_path = std::path::Path::new(db_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("node-id");
    match std::fs::read_to_string(&id_path).map(|s| s.trim().to_string()) {
        Ok(id) if !id.is_empty() => node.with_node_id(id),
        _ => {
            let _ = std::fs::write(&id_path, node.node_id());
            node
        }
    }
}

pub async fn build_all_in_one_state(
    port: u16,
    db_path: &str,
    relay_ws_url: String,
    embed_ui: bool,
) -> Result<ApiState, String> {
    let store = SqliteStore::open(db_path).map_err(|e| e.to_string())?;
    let local_node = Arc::new(dashboard_node(port, db_path));
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
        join_requests: Arc::new(RwLock::new(HashMap::new())),
        ignored_join_keys: Default::default(),
        agent_admission: Default::default(),
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
                    let _admission = bg_state.agent_admission.lock().await;
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
    let _admission = state.agent_admission.lock().await;
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
    /// Pre-0.2.4 bearer key. Dropped once the controller accepts sealed check-ins.
    agent_key: Option<String>,
    /// Controller's channel public key (hex), pinned from the join command.
    controller_key: Option<String>,
    /// This agent's channel secret (hex).
    channel_secret: Option<String>,
    /// Dashboard addresses, comma-separated. `rackdeck doctor` reads them.
    controllers: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
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
    let json = serde_json::json!({
        "nodeId": st.node_id,
        "agentKey": st.agent_key,
        "controllerKey": st.controller_key,
        "channelSecret": st.channel_secret,
        "controllers": st.controllers,
    })
    .to_string();
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

fn read_agent_state(path: &std::path::Path) -> Option<AgentState> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    Some(AgentState {
        node_id: v["nodeId"].as_str().unwrap_or_default().to_string(),
        agent_key: v["agentKey"].as_str().map(str::to_string),
        controller_key: v["controllerKey"].as_str().map(str::to_string),
        channel_secret: v["channelSecret"].as_str().map(str::to_string),
        controllers: v["controllers"].as_str().unwrap_or_default().to_string(),
    })
}

/// Load (or create) this machine's agent state, pinning `controller_key` if given.
fn load_agent_state(path: &std::path::Path, controller_key: Option<String>) -> AgentState {
    let mut saved = read_agent_state(path).unwrap_or_default();
    // The join command's key wins over a saved one: running a new join command means a new controller.
    if let Some(k) = controller_key.filter(|k| hex32(k).is_some()) {
        if saved.controller_key.as_deref() != Some(k.as_str()) {
            saved.controller_key = Some(k);
            saved.channel_secret = None;
            saved.controllers.clear();
        }
    }
    if saved.controller_key.is_some() && saved.channel_secret.is_none() {
        saved.channel_secret = Some(hex::encode(seal::random32()));
    }
    if saved.node_id.is_empty() {
        // Hostname plus a random suffix, so two boxes called `ubuntu` stay separate machines.
        let base = LocalNodeAdapter::new(7420).node_id().to_string();
        saved.node_id = format!("{base}-{:06x}", rand::random::<u32>() & 0xff_ffff);
    }
    save_agent_state(path, &saved);
    saved
}

/// The code shown in the installer and next to Allow on the dashboard.
fn pair_code_for(st: &AgentState) -> Option<String> {
    let ck = st.controller_key.as_deref().and_then(hex32)?;
    let cs = st.channel_secret.as_deref().and_then(hex32)?;
    Some(seal::pair_code(&ck, &seal::public(&cs)))
}

/// Ask the home network for Rackdeck dashboards: (url, key hex, name). Blocking, takes `wait`.
fn find_dashboards(wait: std::time::Duration) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") else { return out };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let port: u16 = std::env::var("RACKDECK_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7420);
    // 255.255.255.255 doesn't reach every interface (or this machine, on macOS), so also try the
    // primary network's own broadcast address.
    // ponytail: assumes a /24 home network; read real netmasks if people report misses on bigger ones.
    let mut targets = vec![std::net::Ipv4Addr::BROADCAST];
    if let Some(std::net::IpAddr::V4(ip)) = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("1.1.1.1:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .ok()
        .map(|a| a.ip())
    {
        let [a, b, c, _] = ip.octets();
        targets.push(std::net::Ipv4Addr::new(a, b, c, 255));
    }
    let end = std::time::Instant::now() + wait;
    let mut next_send = std::time::Instant::now();
    let mut buf = [0u8; 1024];
    while std::time::Instant::now() < end {
        if std::time::Instant::now() >= next_send {
            for dst in &targets {
                let _ = sock.send_to(seal::FIND_MSG, (*dst, port));
            }
            next_send += std::time::Duration::from_millis(700);
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        add_find_reply(&mut out, from, &buf[..n]);
    }
    out
}

fn add_find_reply(out: &mut Vec<(String, String, String)>, sender: SocketAddr, data: &[u8]) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let (Some(key), Some(name), Some(port)) = (
        v["key"].as_str().and_then(hex32),
        v["name"].as_str(),
        v["port"].as_u64(),
    ) else {
        return;
    };
    let Ok(port) = u16::try_from(port) else {
        return;
    };
    if port == 0 {
        return;
    }
    let addr = format!("http://{}", SocketAddr::new(sender.ip(), port));
    let key = hex::encode(key);
    if !out.iter().any(|(url, k, _)| *url == addr && *k == key) {
        out.push((
            addr,
            key,
            name.chars()
                .filter(|c| !c.is_control() && !matches!(c, '\u{2028}' | '\u{2029}'))
                .collect(),
        ));
    }
}

/// Answer `find_dashboards` broadcasts from machines on the home network. Private addresses only,
/// so a dashboard on a public IP can't be used to bounce traffic at someone.
fn spawn_find_responder(port: u16, name: String, key_hex: String) {
    tokio::spawn(async move {
        let sock = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("home-network discovery is off (UDP {port}: {e})");
                return;
            }
        };
        let reply = serde_json::json!({ "name": name, "port": port, "key": key_hex }).to_string();
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
            let local = match from.ip() {
                std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
                std::net::IpAddr::V6(_) => false,
            };
            if local && &buf[..n] == seal::FIND_MSG {
                let _ = sock.send_to(reply.as_bytes(), from).await;
            }
        }
    });
}

/// `rackdeck doctor`: plain answers for "why does the dashboard show this machine offline?"
async fn doctor() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates: Vec<std::path::PathBuf> = [
        std::env::var("RACKDECK_AGENT_STATE").ok().map(Into::into),
        Some(std::path::Path::new(&home).join(".config/rackdeck/agent.json")),
        Some("/var/lib/rackdeck/agent.json".into()),
    ]
    .into_iter()
    .flatten()
    .collect();
    let path = candidates.iter().find(|p| p.exists());
    let Some(path) = path else {
        println!("This computer hasn't joined a dashboard yet.");
        println!("Run the install command here: curl -fsSL https://get.rackdeck.dev | sh");
        return;
    };
    let Some(st) = read_agent_state(path) else {
        println!("Can't read {}. Run it with sudo: sudo rackdeck doctor", path.display());
        return;
    };

    let (running, restart) = if cfg!(target_os = "macos") {
        let ok = std::process::Command::new("launchctl").args(["list", "dev.rackdeck.agent"]).output().is_ok_and(|o| o.status.success());
        (ok, "launchctl kickstart -k gui/$(id -u)/dev.rackdeck.agent")
    } else {
        let ok = std::process::Command::new("systemctl").args(["is-active", "--quiet", "rackdeck-agent"]).status().is_ok_and(|s| s.success());
        (ok, "sudo systemctl restart rackdeck-agent")
    };
    if running {
        println!("✓ The Rackdeck agent is running.");
    } else {
        println!("✗ The Rackdeck agent isn't running. Start it: {restart}");
    }

    let hosts: Vec<String> = st.controllers.split(',').map(|h| h.trim().trim_start_matches("http://").to_string()).filter(|h| !h.is_empty()).collect();
    let mut reached = None;
    for h in &hosts {
        let Ok(Ok(mut s)) = tokio::time::timeout(std::time::Duration::from_secs(3), tokio::net::TcpStream::connect(h)).await else { continue };
        let _ = s.write_all(format!("GET /api/v1/health HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n").as_bytes()).await;
        let mut body = String::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_string(&mut body)).await;
        if body.contains("\"rackdeck\"") {
            reached = Some(h.clone());
            break;
        }
    }
    match &reached {
        Some(h) => println!("✓ This computer can reach the dashboard at {h}."),
        None => {
            println!("✗ Can't reach the dashboard at {}.", if hosts.is_empty() { "its saved address".into() } else { hosts.join(" or ") });
            let found = tokio::task::spawn_blocking(|| find_dashboards(std::time::Duration::from_secs(2))).await.unwrap_or_default();
            match found.iter().find(|(_, k, _)| Some(k.as_str()) == st.controller_key.as_deref()) {
                Some((url, _, name)) => println!("  Found it on this network at {url} ({name}). Its address changed; the agent switches to it on its own within a minute."),
                None if !found.is_empty() => println!("  Found a different dashboard ({}), not the one this computer joined. To move it, use + Add machine on that dashboard.", found[0].2),
                None => println!("  Nothing answered on this network either. Check the dashboard computer is on and awake, and that both computers are on the same Wi-Fi or Tailscale."),
            }
        }
    }
    if running && reached.is_some() {
        if let Some(code) = pair_code_for(&st) {
            println!("\nBoth look fine. If the dashboard still shows it offline, check for an Allow request there with code {code}.");
        }
        let log = if cfg!(target_os = "macos") { "tail -n 30 ~/Library/Logs/rackdeck-agent.log" } else { "journalctl -u rackdeck-agent -n 30" };
        println!("The agent's log may say more: {log}");
    }
}

struct CheckinReply {
    status: u16,
    body: String,
}

impl CheckinReply {
    fn rejection(&self) -> String {
        serde_json::from_str::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| format!("HTTP {}", self.status))
    }

    fn pending(&self) -> bool {
        self.status == 403
            && serde_json::from_str::<serde_json::Value>(&self.body)
                .is_ok_and(|v| v["pending"].as_bool() == Some(true))
    }

    fn decode(&self, key: Option<[u8; 32]>) -> Result<serde_json::Value, String> {
        if self.status != 200 {
            return Err(self.rejection());
        }
        let value: serde_json::Value = match key {
            Some(key) => {
                let plain = hex::decode(&self.body)
                    .ok()
                    .and_then(|ct| seal::open_response(&key, &ct))
                    .ok_or("couldn't open the dashboard's reply")?;
                serde_json::from_slice(&plain)
            }
            None => serde_json::from_str(&self.body),
        }
        .map_err(|_| "invalid check-in reply")?;
        if value["ok"].as_bool() != Some(true) {
            return Err("dashboard did not accept the check-in".into());
        }
        Ok(value)
    }
}

async fn send_checkin(
    host: &str,
    auth_header: &str,
    payload: &str,
) -> Result<CheckinReply, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let timeout = Duration::from_secs(5);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(host))
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let request = format!(
        "POST /api/v1/agent/checkin HTTP/1.1\r\nHost: {host}\r\n{auth_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "sending check-in timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    tokio::time::timeout(timeout, stream.read_to_string(&mut raw))
        .await
        .map_err(|_| "waiting for reply timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("invalid HTTP reply")?;
    let mut status_line = head.split_whitespace();
    if !matches!(status_line.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err("invalid HTTP reply".into());
    }
    let status = status_line
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or("invalid HTTP status")?;
    Ok(CheckinReply {
        status,
        body: body.trim().to_string(),
    })
}

fn controller_hosts(urls: &str) -> impl Iterator<Item = &str> {
    urls.split(',').filter_map(|url| {
        let host = url
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        host.split('/').next().filter(|h| !h.is_empty())
    })
}

fn sealed_checkin(
    ck: &[u8; 32],
    cs: &[u8; 32],
    payload: &str,
) -> Result<(String, String, [u8; 32]), String> {
    let (header, body, key) =
        seal::seal_request(ck, cs, payload.as_bytes()).ok_or("invalid dashboard key")?;
    Ok((format!("X-Rackdeck-Seal: {header}"), hex::encode(body), key))
}

async fn run_join_request(controller: &str, key: String) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let host = controller_hosts(controller)
        .next()
        .ok_or("invalid dashboard address")?;
    let ck = hex32(&key).ok_or("invalid dashboard key")?;
    let saved = load_agent_state(&agent_state_path(), Some(key));
    let cs = saved
        .channel_secret
        .as_deref()
        .and_then(hex32)
        .ok_or("missing agent key")?;
    let local = LocalNodeAdapter::new(7420).with_node_id(saved.node_id);
    let node = local.inspect_node().await?;
    let code = seal::pair_code(&ck, &seal::public(&cs));
    let mut payload = serde_json::json!({ "node": node, "apps": [], "joinRequestOnly": true });
    let mut confirmed = false;
    let deadline = Instant::now() + Duration::from_secs(900);
    loop {
        payload["timestamp"] = serde_json::json!(now_unix_secs());
        let (header, body, key) = sealed_checkin(&ck, &cs, &payload.to_string())?;
        let reply = match send_checkin(host, &header, &body).await {
            Ok(reply) => reply,
            Err(e) if confirmed && Instant::now() < deadline => {
                tracing::warn!("Waiting for the dashboard: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let pending = reply.pending();
        if !pending {
            reply.decode(Some(key))?;
        }
        if !confirmed {
            println!(
                "Your dashboard should show a request from {} with code {code}.",
                node.name
            );
            print!("Does it? [y/N] ");
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                println!("Nothing was installed.");
                std::process::exit(3);
            }
            confirmed = true;
            if pending {
                println!("Click Allow on your dashboard. Waiting for approval...");
            }
        }
        if !pending {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("The join request expired. Run the installer again.".into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

const MAX_CHECKIN_PLAIN_BYTES: usize = MAX_CHECKIN_BODY_BYTES / 2 - 16;
const MAX_RESULT_BYTES: usize = 64 * 1024;

fn cap_command_result(result: &mut AgentCommandResult) {
    if serde_json::to_vec(result).is_ok_and(|bytes| bytes.len() <= MAX_RESULT_BYTES) {
        return;
    }
    if let Ok(AgentOutput::Lines { lines }) = &mut result.result {
        let mut remaining = MAX_RESULT_BYTES - 256;
        let mut kept = Vec::new();
        for line in lines.iter().rev() {
            let bytes = serde_json::to_vec(line).map_or(usize::MAX, |v| v.len() + 1);
            if bytes > remaining {
                // JSON escaping takes at most six bytes per input byte.
                let suffix = remaining.saturating_sub(3) / 6;
                let mut start = line.len().saturating_sub(suffix);
                while !line.is_char_boundary(start) {
                    start += 1;
                }
                if start < line.len() {
                    kept.push(line[start..].to_string());
                }
                break;
            }
            remaining -= bytes;
            kept.push(line.clone());
        }
        kept.push("[Rackdeck trimmed older log output.]".into());
        kept.reverse();
        *lines = kept;
    } else {
        result.result = Err("This result was too large to send to the dashboard.".into());
    }
}

async fn run_remote_agent(
    controller: String,
    initial_token: String,
    controller_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let state_path = agent_state_path();
    let mut saved = load_agent_state(&state_path, controller_key);
    let mut secrets_version: Option<String> = None;
    let local = Arc::new(LocalNodeAdapter::new(7420).with_node_id(saved.node_id.clone()));
    let mut hosts = Vec::new();
    for host in controller_hosts(&saved.controllers).chain(controller_hosts(&controller)) {
        if !hosts.iter().any(|h| h == host) {
            hosts.push(host.to_string());
        }
    }
    if hosts.is_empty() {
        return Err("invalid controller url".into());
    }
    saved.controllers = hosts.join(",");
    save_agent_state(&state_path, &saved);
    let mut host_idx = 0usize;

    // A saved key survives restarts; the one-time join token is only a fallback for first contact.
    // No token at all means we found the dashboard on the home network and wait for Allow.
    let mut join_token = Some(initial_token).filter(|t| !t.is_empty());
    let mut fails_in_row = 0usize;
    let mut last_find = std::time::Instant::now();
    let mut bearer = match saved.agent_key.clone() {
        Some(k) => k,
        None => join_token.take().unwrap_or_default(),
    };
    let mut enrolled = false;
    let mut last_err: Option<String> = None;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    // Finished command results wait here until a check-in delivers them.
    let mut results: VecDeque<(AgentCommandResult, Instant)> = VecDeque::new();
    let mut rediscovered = None;
    let mut restart_pending = false;
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<AgentCommandResult>();
    tracing::info!("rackdeck agent connecting to {controller} as {}", local.callsign());

    loop {
        // Check in every 2s, or right away when a command finishes so the UI isn't kept waiting.
        tokio::select! {
            _ = interval.tick() => {}
            Some(r) = done_rx.recv() => results.push_back((r, Instant::now())),
        }
        while let Ok(r) = done_rx.try_recv() {
            results.push_back((r, Instant::now()));
        }
        while results
            .front()
            .is_some_and(|(_, since)| since.elapsed() >= Duration::from_secs(600))
        {
            results.pop_front();
            tracing::warn!("The dashboard did not receive an old command result.");
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
        let mut payload = serde_json::json!({ "node": node, "sample": sample, "apps": apps, "results": [], "appManagement": true });
        let sealing = saved
            .controller_key
            .as_deref()
            .and_then(hex32)
            .zip(saved.channel_secret.as_deref().and_then(hex32));
        if let Some((_, _)) = sealing {
            let token = join_token
                .clone()
                .or_else(|| bearer.starts_with("rd_join_").then(|| bearer.clone()));
            payload["joinToken"] = serde_json::json!(token);
            payload["agentKey"] = serde_json::json!(saved.agent_key);
            payload["secretsVersion"] = serde_json::json!(secrets_version);
            payload["timestamp"] = serde_json::json!(now_unix_secs());
        }
        let mut size = payload.to_string().len();
        if size > MAX_CHECKIN_PLAIN_BYTES - MAX_RESULT_BYTES - 1 {
            tracing::warn!("The app list is too large to send to the dashboard.");
            payload["apps"] = serde_json::json!([]);
            size = payload.to_string().len();
        }
        if size > MAX_CHECKIN_PLAIN_BYTES - MAX_RESULT_BYTES - 1 {
            tracing::warn!("The machine report is too large to send to the dashboard.");
            payload["sample"] = serde_json::Value::Null;
            size = payload.to_string().len();
            if size > MAX_CHECKIN_PLAIN_BYTES - MAX_RESULT_BYTES - 1 {
                continue;
            }
        }
        let batch = payload["results"].as_array_mut().unwrap();
        for (result, _) in &results {
            let value = serde_json::to_value(result)?;
            size += value.to_string().len() + 1;
            if size > MAX_CHECKIN_PLAIN_BYTES {
                break;
            }
            batch.push(value);
        }
        let sent = batch.len();
        let payload = payload.to_string();
        let host = hosts[host_idx].clone();
        let sealed = sealing.is_some();
        let val = match async {
            let (auth_hdr, payload, reply_key) = match sealing {
                Some((ck, cs)) => {
                    let (header, body, key) = sealed_checkin(&ck, &cs, &payload)?;
                    (header, body, Some(key))
                }
                None => (format!("Authorization: Bearer {bearer}"), payload, None),
            };
            let reply = send_checkin(&host, &auth_hdr, &payload).await?;
            if reply.status == 401 && reply_key.is_none() {
                if let Some(t) = join_token.take() {
                    bearer = t;
                }
            }
            if reply.pending() {
                return Err(format!(
                    "waiting for you to click Allow on the dashboard (code {})",
                    pair_code_for(&saved).unwrap_or_default()
                ));
            }
            reply.decode(reply_key)
        }
        .await
        {
            Ok(val) => val,
            Err(reason) => {
                host_idx = (host_idx + 1) % hosts.len();
                fails_in_row = fails_in_row.saturating_add(1);
                rediscover(
                    &mut hosts,
                    &mut host_idx,
                    &mut last_find,
                    fails_in_row,
                    &saved,
                    &mut rediscovered,
                )
                .await;
                let msg = format!("check-in to {host}: {reason}");
                if last_err.as_deref() != Some(&msg) {
                    tracing::warn!("{msg}");
                    last_err = Some(msg);
                }
                continue;
            }
        };

        if sealed {
            fails_in_row = 0;
            if last_err.take().is_some() {
                tracing::info!("reconnected to the dashboard at {host}");
            }
            if rediscovered.as_deref() == Some(&host) {
                hosts.swap(0, host_idx);
                host_idx = 0;
                saved.controllers = hosts.join(",");
                save_agent_state(&state_path, &saved);
                rediscovered = None;
            }
        }

        // Only the batches just acknowledged are retired. A restart also needs a verified seal.
        restart_pending |= results
            .drain(..sent)
            .any(|(r, _)| matches!(r.result, Ok(AgentOutput::Updated { version: Some(_) })));
        if restart_pending && sealed {
            if let Ok(_guard) = local.try_app_operation() {
                tracing::info!("updated, restarting agent");
                let err = update::restart_self();
                tracing::warn!("couldn't restart after update ({err}); exiting so the service manager restarts it");
                std::process::exit(1);
            }
        }

        if sealed && (join_token.is_some() || saved.agent_key.is_some() || !bearer.is_empty()) {
            // Accepted on the sealed channel: the join token is spent and the old bearer key retired.
            join_token = None;
            bearer.clear();
            saved.agent_key = None;
            save_agent_state(&state_path, &saved);
        }
        if !sealed && saved.controller_key.is_none() {
            // Agent from before sealed check-ins: pin the key this controller reports, then switch over.
            if let Some(k) = val
                .get("controllerKey")
                .and_then(|v| v.as_str())
                .filter(|k| hex32(k).is_some())
            {
                saved.controller_key = Some(k.to_string());
                saved.channel_secret = Some(hex::encode(seal::random32()));
                save_agent_state(&state_path, &saved);
            }
        }
        if let Some(sec) = val.get("secrets").filter(|_| sealed) {
            let Ok(vars) = serde_json::from_value::<std::collections::BTreeMap<String, String>>(
                sec["vars"].clone(),
            ) else {
                tracing::warn!("The dashboard sent invalid secret settings.");
                continue;
            };
            match seal::write_secrets_file(&vars) {
                Ok(()) => {
                    secrets_version = sec["version"].as_str().map(str::to_string);
                    tracing::info!("secrets updated ({} set)", vars.len());
                }
                Err(e) => tracing::warn!("couldn't write secrets file: {e}"),
            }
        }
        let commands: Vec<AgentCommand> = val
            .get("commands")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .unwrap_or_default();
        for cmd in commands
            .into_iter()
            .filter(|cmd| !cmd.id.is_empty() && cmd.id.len() <= 128)
        {
            let local = local.clone();
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                let result = run_agent_command(local.as_ref(), cmd.op).await;
                let mut result = AgentCommandResult { id: cmd.id, result };
                cap_command_result(&mut result);
                let _ = done_tx.send(result);
            });
        }
        if let Some(k) = val
            .get("agentKey")
            .and_then(|v| v.as_str())
            .filter(|_| !sealed)
        {
            bearer = k.to_string();
            saved.agent_key = Some(bearer.clone());
            save_agent_state(&state_path, &saved);
            enrolled = true;
            tracing::info!(
                "connected & enrolled with controller {controller} as {}",
                local.callsign()
            );
        } else if !enrolled {
            enrolled = true;
            tracing::info!(
                "connected to controller {controller} as {}",
                local.callsign()
            );
        }
    }
}

/// When no saved address answers (say the dashboard got a new IP from the router), look for it on
/// the home network. Only a dashboard with the pinned key counts. At most every 30s.
async fn rediscover(
    hosts: &mut Vec<String>,
    host_idx: &mut usize,
    last_find: &mut std::time::Instant,
    fails_in_row: usize,
    saved: &AgentState,
    rediscovered: &mut Option<String>,
) {
    if fails_in_row < hosts.len() || last_find.elapsed() < std::time::Duration::from_secs(30) {
        return;
    }
    *last_find = std::time::Instant::now();
    let Some(pinned) = saved.controller_key.clone() else { return };
    let found = tokio::task::spawn_blocking(|| find_dashboards(std::time::Duration::from_secs(2))).await.unwrap_or_default();
    let Some((url, _, _)) = found.into_iter().find(|(_, k, _)| *k == pinned) else { return };
    let host = url.trim_start_matches("http://").to_string();
    if !hosts.contains(&host) {
        if let Some(previous) = rediscovered.replace(host.clone()) {
            hosts.retain(|h| *h != previous);
        }
        tracing::info!("trying a discovered dashboard address {host}");
        hosts.push(host.clone());
    }
    *host_idx = hosts.iter().position(|h| *h == host).unwrap();
}

async fn run_agent_command(local: &LocalNodeAdapter, op: AgentOp) -> Result<AgentOutput, String> {
    match &op {
        AgentOp::AppAction { app_id, action } => {
            tracing::info!(?action, %app_id, "running app action")
        }
        AgentOp::Deploy { spec, .. } => tracing::info!(app = %spec.name, "running deploy"),
        AgentOp::Logs { app_id, .. } => tracing::info!(%app_id, "fetching app logs"),
        AgentOp::Update => tracing::info!("running agent update"),
    }
    match op {
        AgentOp::AppAction { app_id, action } => {
            local
                .app_action(&app_id, action)
                .await
                .map(|result| match result {
                    AppActionResult::Done => AgentOutput::Done,
                    AppActionResult::Updated => AgentOutput::AppUpdated { changed: true },
                    AppActionResult::AlreadyUpToDate => AgentOutput::AppUpdated { changed: false },
                })
        }
        AgentOp::Deploy {
            spec,
            fresh_volumes,
        } => local
            .deploy_app(spec, fresh_volumes)
            .await
            .map(|app| AgentOutput::App { app: Box::new(app) }),
        AgentOp::Logs { app_id, lines } => local
            .tail_logs(&app_id, lines)
            .await
            .map(|lines| AgentOutput::Lines { lines }),
        AgentOp::Update => {
            let _guard = local.try_app_operation().map_err(|e| e.to_string())?;
            return update::self_update()
                .await
                .map(|version| AgentOutput::Updated { version });
        }
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
            "Rackdeck {}\n\nUsage:\n  rackdeck                                              Start control plane + local node (default :7420)\n  rackdeck agent --controller <URL> --token <TOKEN>     Join a remote machine to a controller\n  rackdeck update                                       Install the latest release over this binary\n  rackdeck doctor                                       Explain why this machine shows as offline\n  rackdeck join-request --controller <URL> --key <KEY>  Request approval on the home network\n\nEnvironment:\n  RACKDECK_PORT       HTTP listen port (default: 7420)\n  RACKDECK_DB         SQLite database path (default: rackdeck.db)\n  RACKDECK_PASSWORD   Require login; without it Rackdeck only listens on 127.0.0.1\n  RACKDECK_RELAY_URL  Connect relay WebSocket URL",
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
    if args.get(1).map(|s| s.as_str()) == Some("doctor") {
        doctor().await;
        return Ok(());
    }
    if args.get(1).map(|s| s.as_str()) == Some("find") {
        // For the installer: one dashboard per line, "url key name".
        for (url, key, name) in find_dashboards(std::time::Duration::from_secs(2)) {
            println!("{url} {key} {name}");
        }
        return Ok(());
    }
    if args.get(1).map(|s| s.as_str()) == Some("pair-code") {
        // For the installer: set up this machine's keys for the found dashboard and print the code.
        let Some(key) = args.get(2).filter(|k| hex32(k).is_some()) else {
            eprintln!("Usage: rackdeck pair-code <dashboard-key>");
            std::process::exit(2);
        };
        let st = load_agent_state(&agent_state_path(), Some(key.clone()));
        println!("{}", pair_code_for(&st).unwrap_or_default());
        return Ok(());
    }
    if matches!(
        args.get(1).map(|s| s.as_str()),
        Some("agent" | "join-request")
    ) {
        let mut controller = std::env::var("RACKDECK_CONTROLLER").unwrap_or_default();
        let mut token = std::env::var("RACKDECK_JOIN_TOKEN").unwrap_or_default();
        let mut controller_key = std::env::var("RACKDECK_CONTROLLER_KEY").ok();
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
                "--controller-key" | "--key" if i + 1 < args.len() => {
                    controller_key = Some(args[i + 1].clone());
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if args[1] == "join-request" {
            return run_join_request(
                &controller,
                controller_key.ok_or("A dashboard key is required.")?,
            )
            .await;
        }
        let has_key = controller_key.is_some() || read_agent_state(&agent_state_path()).is_some_and(|s| s.controller_key.is_some());
        if controller.is_empty() || (token.is_empty() && !has_key) {
            eprintln!("Usage: rackdeck agent --controller <http://host:7420> (--token <join-token> | --key <dashboard-key>)");
            std::process::exit(2);
        }
        return run_remote_agent(controller, token, controller_key).await;
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
    if password_set {
        let name = state.fleet_repo.get_node(&node_id).await.ok().flatten().map(|n| n.name).unwrap_or_else(|| node_id.clone());
        let key = hex::encode(seal::public(&seal::controller_secret(&state.signing_key.to_bytes())));
        spawn_find_responder(port, name, key);
    }
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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rackdeck_connect::relay::{relay_router, RelayState};
    use rackdeck_core::RemoteDispatch;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: rackdeck_session=test-sid\r\nConnection: close\r\n\r\n");
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
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: rackdeck_session=test-sid\r\nContent-Type: application/json\r\n{auth_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    async fn checkin_test_dashboard() -> (ApiState, SocketAddr) {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let mut state =
            build_all_in_one_state(addr.port(), ":memory:", "ws://127.0.0.1:7430".into(), false)
                .await
                .unwrap();
        state.owner_password = None;
        let app = build_router(state.clone());
        tokio::spawn(async move {
            axum::serve(
                server,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (state, addr)
    }

    async fn test_agent_node(state: &ApiState, id: &str) -> rackdeck_core::Node {
        let mut node = state
            .fleet_repo
            .get_node(&state.local_node_id)
            .await
            .unwrap()
            .unwrap();
        node.id = id.into();
        node.name = id.into();
        node
    }

    fn sealed_test_payload(
        state: &ApiState,
        agent: &[u8; 32],
        payload: &serde_json::Value,
    ) -> (String, String, [u8; 32]) {
        let controller = seal::public(&seal::controller_secret(&state.signing_key.to_bytes()));
        sealed_checkin(&controller, agent, &payload.to_string()).unwrap()
    }

    #[tokio::test]
    async fn replay_cannot_update_node_or_take_queued_commands() {
        let (state, addr) = checkin_test_dashboard().await;
        let agent = seal::random32();
        let id = "replay-test";
        let hash = format!("x25519:{}", hex::encode(seal::public(&agent)));
        state
            .fleet_repo
            .set_agent_key_hash(id, &hash)
            .await
            .unwrap();
        let mut node = test_agent_node(&state, id).await;
        let mut body = serde_json::json!({"node":node,"apps":[],"timestamp":now_unix_secs()});
        let (header, payload, key) = sealed_test_payload(&state, &agent, &body);
        let host = addr.to_string();
        assert!(send_checkin(&host, &header, &payload)
            .await
            .unwrap()
            .decode(Some(key))
            .is_ok());

        node.last_seen += 1;
        state.fleet_repo.upsert_node(node.clone()).await.unwrap();
        let caller = state.agent_bus.tail_logs(id, "docker:test", 5);
        let agent_loop = async {
            let rejected = send_checkin(&host, &header, &payload).await.unwrap();
            assert_eq!(rejected.status, 401);
            assert_eq!(
                state
                    .fleet_repo
                    .get_node(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .last_seen,
                node.last_seen
            );

            let (header, payload, key) = sealed_test_payload(&state, &agent, &body);
            let reply = send_checkin(&host, &header, &payload)
                .await
                .unwrap()
                .decode(Some(key))
                .unwrap();
            let commands = reply["commands"].as_array().unwrap();
            assert_eq!(commands.len(), 1);
            body["results"] = serde_json::json!([{ "id": commands[0]["id"], "result": { "Ok": { "kind": "lines", "lines": ["still queued"] } } }]);
            let (header, payload, key) = sealed_test_payload(&state, &agent, &body);
            assert!(send_checkin(&host, &header, &payload)
                .await
                .unwrap()
                .decode(Some(key))
                .is_ok());
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(caller, agent_loop)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap(), ["still queued"]);
    }

    #[tokio::test]
    async fn enrollment_cannot_replace_a_machine_with_the_same_id() {
        let (state, addr) = checkin_test_dashboard().await;
        let host = addr.to_string();
        let node = test_agent_node(&state, "ubuntu").await;
        let first = seal::random32();
        let second = seal::random32();
        let mut body = serde_json::json!({"node":node,"apps":[],"joinRequestOnly":true});
        for agent in [&first, &second] {
            let (header, payload, _) = sealed_test_payload(&state, agent, &body);
            assert!(send_checkin(&host, &header, &payload)
                .await
                .unwrap()
                .pending());
        }
        body["node"]["name"] = serde_json::json!("changed");
        let (header, payload, _) = sealed_test_payload(&state, &second, &body);
        assert!(send_checkin(&host, &header, &payload)
            .await
            .unwrap()
            .pending());
        let first = hex::encode(seal::public(&first));
        let second_pub = hex::encode(seal::public(&second));
        assert_eq!(state.join_requests.read().await[&second_pub].name, "ubuntu");
        let allow = |key: &str| format!("/api/v1/join-requests/{key}");
        assert!(http_post_json(addr, &allow(&first), "{}", None)
            .await
            .contains("200 OK"));

        let message = "A machine called ubuntu is already joined. Remove it on its page first, then try again.";
        let refused = http_post_json(addr, &allow(&second_pub), "{}", None).await;
        assert!(
            refused.contains("403") && refused.contains(message),
            "{refused}"
        );
        body["node"]["name"] = serde_json::json!("ubuntu");
        let (header, payload, _) = sealed_test_payload(&state, &second, &body);
        let refused = send_checkin(&host, &header, &payload).await.unwrap();
        assert_eq!(refused.status, 403);
        assert!(!refused.pending());
        assert!(refused.rejection().contains(message));

        let join = http_post_json(addr, "/api/v1/join-token", "{}", None).await;
        let json: serde_json::Value =
            serde_json::from_str(join.split_once("\r\n\r\n").unwrap().1).unwrap();
        let token = json["token"].as_str().unwrap();
        body["joinRequestOnly"] = serde_json::json!(false);
        body["joinToken"] = serde_json::json!(token);
        let (header, payload, _) = sealed_test_payload(&state, &second, &body);
        let refused = send_checkin(&host, &header, &payload).await.unwrap();
        assert_eq!(refused.status, 403);
        assert!(refused.rejection().contains(message));
        let old = http_post_json(
            addr,
            "/api/v1/agent/checkin",
            &body.to_string(),
            Some(token),
        )
        .await;
        assert!(old.contains("403") && old.contains(message), "{old}");
        assert_eq!(
            state.fleet_repo.agent_key_hash("ubuntu").await.unwrap(),
            Some(format!("x25519:{first}"))
        );
    }

    #[tokio::test]
    async fn origin_must_match_for_owner_writes_and_websocket_upgrades() {
        let (_, addr) = checkin_test_dashboard().await;
        let status = |request: String| async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut line = String::new();
            tokio::io::AsyncBufReadExt::read_line(
                &mut tokio::io::BufReader::new(stream),
                &mut line,
            )
            .await
            .unwrap();
            line.split_whitespace().nth(1).unwrap().to_string()
        };
        let post = |origin: &str, extra: &str, path: &str| {
            let body = if path == "/mcp" {
                r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#
            } else {
                "{}"
            };
            format!(
                "POST {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let ws = |origin: &str| {
            format!(
            "GET /api/ws HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        };
        let foreign = "http://unrelated.example";
        let own = format!("http://{addr}");
        let https = format!("https://{addr}");
        assert_eq!(status(post(foreign, "", "/api/v1/join-token")).await, "403");
        assert_eq!(status(post(&https, "", "/api/v1/join-token")).await, "403");
        assert_eq!(
            status(post(
                &https,
                "X-Forwarded-Proto: https\r\n",
                "/api/v1/join-token"
            ))
            .await,
            "200"
        );
        assert_eq!(status(post(&own, "", "/api/v1/join-token")).await, "200");
        assert_eq!(
            status(post(foreign, "Authorization: Bearer unknown\r\n", "/mcp")).await,
            "401"
        );
        assert_eq!(status(ws(foreign)).await, "403");
        let rebound = format!("unrelated.example:{}", addr.port());
        let request = ws(&format!("http://{rebound}"))
            .replace(&format!("Host: {addr}"), &format!("Host: {rebound}"));
        assert_eq!(status(request).await, "403");
        assert_eq!(status(ws(&format!("http://{}", addr.ip()))).await, "403");
        assert_eq!(status(ws(&own)).await, "101");
    }

    #[test]
    fn log_results_fit_the_wire_budget_after_json_escaping() {
        let mut result = AgentCommandResult {
            id: "cmd-test".into(),
            result: Ok(AgentOutput::Lines {
                lines: vec!["é\0\"".repeat(MAX_RESULT_BYTES), "latest".into()],
            }),
        };
        cap_command_result(&mut result);
        assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_RESULT_BYTES);
        let Ok(AgentOutput::Lines { lines }) = result.result else {
            panic!("logs were discarded")
        };
        assert!(lines.first().unwrap().contains("trimmed older log output"));
        assert_eq!(lines.last().unwrap(), "latest");
    }

    #[test]
    fn find_replies_use_sender_ip_validate_ports_and_strip_controls() {
        let mut found = Vec::new();
        let key = "a1".repeat(32);
        let sender = "192.168.10.8:1024".parse().unwrap();
        let mut reply = serde_json::json!({"key":key,"name":"Home\r\n\u{1b}Box\u{2028}", "port":7420,"ip":"192.168.1.6"});
        add_find_reply(&mut found, sender, reply.to_string().as_bytes());
        assert_eq!(
            found,
            [(
                "http://192.168.10.8:7420".into(),
                key.clone(),
                "HomeBox".into()
            )]
        );
        reply["key"] = serde_json::json!(key.to_ascii_uppercase());
        add_find_reply(
            &mut found,
            "192.168.10.8:9000".parse().unwrap(),
            reply.to_string().as_bytes(),
        );
        for port in [0, 65536] {
            reply["port"] = serde_json::json!(port);
            add_find_reply(&mut found, sender, reply.to_string().as_bytes());
        }
        assert_eq!(found.len(), 1);
        reply["port"] = serde_json::json!(65535);
        add_find_reply(&mut found, sender, reply.to_string().as_bytes());
        add_find_reply(
            &mut found,
            "192.168.10.9:1024".parse().unwrap(),
            reply.to_string().as_bytes(),
        );
        assert_eq!(found.len(), 3);
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
        let mut state = build_all_in_one_state(
            server_addr.port(),
            ":memory:",
            format!("ws://{relay_addr}/_rackdeck/tunnel"),
            false,
        )
        .await
        .unwrap();
        // Connect requires a password, so run the test as a logged-in owner.
        state.owner_password = Some("test-password".into());
        state.owner_sessions.write().await.insert("test-sid".into(), u64::MAX);
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
        // MCP tool failures come back as a readable result, not an HTTP error.
        assert!(mcp_denied.contains("\"isError\":true") && mcp_denied.to_lowercase().contains("forbidden"), "expected a refused tool call: {mcp_denied}");

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
        assert!(deploy_denied.contains("\"isError\":true") && deploy_denied.to_lowercase().contains("forbidden"), "expected a refused tool call: {deploy_denied}");

        let manage_res = http_post_json(
            server_addr,
            "/api/v1/tokens",
            r#"{"name":"app-manager","client":"Codex","scope":"deploy"}"#,
            None,
        ).await;
        let manage_body: serde_json::Value =
            serde_json::from_str(manage_res.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let manage_token = manage_body["token"].as_str().unwrap();
        let remove_path = "/api/v1/nodes/node-home-5090/apps/docker:abc/remove";
        let delete_path = format!("{remove_path}?deleteData=true");
        let refused = http_post_json(server_addr, &delete_path, "{}", Some(manage_token)).await;
        assert!(refused.contains("403") && refused.contains("Only the owner"), "{refused}");
        for (path, auth) in [(remove_path, Some(manage_token)), (&delete_path, None)] {
            let old_agent = http_post_json(server_addr, path, "{}", auth).await;
            assert!(old_agent.contains("409") && old_agent.contains("Update Rackdeck on this machine first."), "{old_agent}");
        }
        for tool in ["remove_app", "update_app"] {
            let call = serde_json::json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": tool, "arguments": { "nodeId": "node-home-5090", "appId": "docker:abc" } }
            });
            let refused = http_post_json(server_addr, "/mcp", &call.to_string(), Some(token)).await;
            assert!(refused.contains("\"isError\":true") && refused.contains("requires deploy scope"), "{refused}");
        }
        let refused = http_post_json(
            server_addr,
            "/mcp",
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"remove_app","arguments":{"appId":"docker:abc","deleteData":true}}}"#,
            None,
        ).await;
        assert!(refused.contains("\"isError\":true") && refused.contains("Only the owner"), "{refused}");

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
