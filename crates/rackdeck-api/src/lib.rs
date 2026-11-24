use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rackdeck_connect::client::{spawn_connect_client, ConnectClientConfig, ConnectClientHandle};
use rackdeck_core::{
    now_unix_secs, AppAction, AppActionResult, AuditEvent, AuditRepository, Capability, ConnectRoute, CoreError,
    DeploySpec, DiscoveryPort, FleetRepository, FleetService, ManagedApp, Node, NodeOps, Principal,
    RouteRepository, TelemetrySample, TlsState, TokenRepository, TokenScope,
};
use rackdeck_discovery::create_pairing_invitation;
use rackdeck_protocol::{AgentCommandResult, AgentOutput, ClientWsCommand, ServerWsEvent};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, Mutex, RwLock};

mod agent_bus;
pub mod seal;
pub mod update;
pub use agent_bus::AgentBus;

pub trait AssetProvider: Send + Sync {
    fn get_asset(&self, path: &str) -> Option<(Vec<u8>, String)>;
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    pub key: String,
    pub node_id: String,
    pub name: String,
    pub os: String,
    pub ip: Option<String>,
    pub code: String,
    pub at: u64,
}

#[derive(Clone)]
pub struct ApiState {
    pub local_node_id: String,
    pub listen_port: u16,
    pub relay_ws_url: String,
    pub signing_key: Arc<SigningKey>,
    pub fleet_svc: Arc<FleetService>,
    pub fleet_repo: Arc<dyn FleetRepository>,
    pub route_repo: Arc<dyn RouteRepository>,
    pub token_repo: Arc<dyn TokenRepository>,
    pub audit_repo: Arc<dyn AuditRepository>,
    pub discovery: Arc<dyn DiscoveryPort>,
    pub local_node: Arc<dyn NodeOps>,
    pub latest_sample: Arc<RwLock<Option<TelemetrySample>>>,
    pub latest_apps: Arc<RwLock<Vec<ManagedApp>>>,
    pub remote_apps: Arc<RwLock<HashMap<String, Vec<ManagedApp>>>>,
    pub join_tokens: Arc<RwLock<HashMap<String, u64>>>,
    /// Machines that found this dashboard on the home network and are waiting for the owner to click Allow.
    /// Keyed by the agent's public key (hex).
    pub join_requests: Arc<RwLock<HashMap<String, JoinRequest>>>,
    pub ignored_join_keys: Arc<Mutex<HashMap<String, u64>>>,
    pub agent_admission: Arc<Mutex<()>>,
    pub agent_bus: Arc<AgentBus>,
    pub owner_password: Option<String>,
    pub owner_sessions: Arc<RwLock<HashMap<String, u64>>>,
    pub ws_tx: broadcast::Sender<ServerWsEvent>,
    pub connect_handle: Arc<Mutex<Option<ConnectClientHandle>>>,
    pub assets: Option<Arc<dyn AssetProvider>>,
}

pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/login", post(auth_login))
        .route("/api/v1/auth/logout", post(auth_logout))
        .route("/api/v1/nodes", get(list_nodes))
        .route("/api/v1/nodes/{node_id}/apps", get(list_node_apps))
        .route("/api/v1/nodes/{node_id}/deploy", post(deploy_node_app))
        .route("/api/v1/nodes/{node_id}/apps/{app_id}/{action}", post(run_app_action))
        .route("/api/v1/nodes/{node_id}/apps/{app_id}/logs", get(get_app_logs))
        .route("/api/v1/nodes/{node_id}/update", post(update_node))
        .route("/api/v1/nodes/{node_id}", axum::routing::delete(remove_node))
        .route("/api/v1/secrets", get(list_secrets))
        .route("/api/v1/secrets/{name}", axum::routing::put(put_secret).delete(delete_secret))
        .route("/api/v1/discovery/scan", post(scan_network))
        .route("/api/v1/join-token", post(issue_join_token))
        .route(
            "/api/v1/agent/checkin",
            post(agent_checkin).layer(DefaultBodyLimit::max(
                rackdeck_protocol::MAX_CHECKIN_BODY_BYTES,
            )),
        )
        .route("/api/v1/agent/join-check", get(join_check))
        .route("/api/v1/join-requests", get(list_join_requests))
        .route("/api/v1/join-requests/{key}", post(allow_join_request).delete(ignore_join_request))
        .route("/api/v1/pair", post(start_pairing))
        .route("/api/v1/connect", post(toggle_connect))
        .route("/api/v1/account", get(account_status))
        .route("/api/v1/account/link", post(account_link))
        .route("/api/v1/account/link/poll", post(account_link_poll))
        .route("/api/v1/connect/routes", get(list_routes).post(add_route))
        .route("/api/v1/connect/routes/{id}", delete(remove_route))
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/tokens/{id}", delete(revoke_token))
        .route("/api/v1/audit", get(list_audit))
        .route("/api/ws", get(ws_handler))
        .route("/mcp", post(mcp_handler))
        .fallback(get(serve_embedded_ui))
        .layer(middleware::from_fn_with_state(
            state.owner_password.is_none(),
            check_origin,
        ))
        .with_state(state)
}

async fn check_origin(State(local_only): State<bool>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let path = request.uri().path();
    let mcp_bearer = path == "/mcp"
        && headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|v| !v.is_empty());
    // The bundled TLS proxies set this header and connect over loopback.
    let proxied_scheme = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .filter(|peer| peer.0.ip().is_loopback())
        .and_then(|_| headers.get("x-forwarded-proto"))
        .and_then(|v| v.to_str().ok())
        .filter(|s| matches!(*s, "http" | "https"));
    let scheme = request
        .uri()
        .scheme_str()
        .or(proxied_scheme)
        .unwrap_or("http");
    if (path == "/api/ws" || (request.method() != Method::GET && !mcp_bearer))
        && !origin_matches(scheme, headers, local_only)
    {
        return err_res(CoreError::Forbidden(
            "This request must come from the dashboard.".into(),
        ));
    }
    next.run(request).await
}

fn origin_matches(scheme: &str, headers: &HeaderMap, local_only: bool) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = host.parse::<axum::http::uri::Authority>() else {
        return false;
    };

    if local_only {
        // A browser can send a matching Host and Origin for a domain that resolves to loopback.
        let hostname = authority.host().trim_matches(['[', ']']);
        if !hostname
            .trim_end_matches('.')
            .eq_ignore_ascii_case("localhost")
            && !hostname
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            return false;
        }
    }
    origins.next().is_none() && origin.as_bytes() == format!("{scheme}://{host}").as_bytes()
}

fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some(val) = part.trim().strip_prefix("rackdeck_session=") {
            return Some(val.to_string());
        }
    }
    None
}

async fn is_valid_owner_session(headers: &HeaderMap, state: &ApiState) -> bool {
    session_still_valid(state, extract_session_cookie(headers).as_deref()).await
}

/// Re-checked per privileged socket message so logout or expiry cuts off an open socket.
async fn session_still_valid(state: &ApiState, sid: Option<&str>) -> bool {
    if state.owner_password.is_none() {
        return true;
    }
    let Some(sid) = sid else { return false };
    state
        .owner_sessions
        .read()
        .await
        .get(sid)
        .is_some_and(|&exp| now_unix_secs() <= exp)
}

async fn resolve_principal(headers: &HeaderMap, state: &ApiState) -> Result<Principal, Response> {
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(raw_token) = auth.strip_prefix("Bearer ") {
            let hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
            let rec = state
                .token_repo
                .find_by_hash(&hash)
                .await
                .map_err(|e| err_res(e))?;
            let Some(rec) = rec else {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid bearer token" })),
                )
                    .into_response());
            };
            if rec.revoked {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "token revoked" })),
                )
                    .into_response());
            }
            if let Some(exp) = rec.expires_at {
                if now_unix_secs() > exp {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({ "error": "token expired" })),
                    )
                        .into_response());
                }
            }
            let _ = state.token_repo.touch_token(&rec.id, now_unix_secs()).await;
            return Ok(Principal::ScopedToken {
                token_id: rec.id,
                name: rec.name,
                scope: rec.scope,
                node_ids: rec.node_ids,
            });
        }
    }
    if !is_valid_owner_session(headers, state).await {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "authentication required" })),
        )
            .into_response());
    }
    Ok(Principal::Owner {
        label: "you (web)".into(),
    })
}

async fn auth_status(State(state): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    let password_required = state.owner_password.is_some();
    let authenticated = is_valid_owner_session(&headers, &state).await;
    Json(serde_json::json!({
        "passwordRequired": password_required,
        "authenticated": authenticated
    }))
}

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

async fn auth_login(State(state): State<ApiState>, Json(body): Json<LoginBody>) -> Response {
    let Some(expected) = &state.owner_password else {
        return Json(serde_json::json!({ "ok": true })).into_response();
    };
    let ok = expected.len() == body.password.len()
        && expected
            .bytes()
            .zip(body.password.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0;
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid password" })),
        )
            .into_response();
    }
    let mut raw = [0u8; 24];
    rand::thread_rng().fill(&mut raw);
    let sid = hex::encode(raw);
    state
        .owner_sessions
        .write()
        .await
        .insert(sid.clone(), now_unix_secs() + 86_400 * 7);
    let cookie = format!("rackdeck_session={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"ok":true}"#))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn auth_logout(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(sid) = extract_session_cookie(&headers) {
        state.owner_sessions.write().await.remove(&sid);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::SET_COOKIE,
            "rackdeck_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"ok":true}"#))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn err_res(err: CoreError) -> Response {
    let code = match err {
        CoreError::NotFound(_) => StatusCode::NOT_FOUND,
        CoreError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
        CoreError::Forbidden(_) => StatusCode::FORBIDDEN,
        CoreError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        CoreError::AgentUpgradeRequired => StatusCode::CONFLICT,
        CoreError::Storage(_) | CoreError::Runtime(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(serde_json::json!({ "error": err.to_string() }))).into_response()
}

async fn health(State(state): State<ApiState>) -> impl IntoResponse {
    let guard = state.connect_handle.lock().await;
    let enabled = guard.is_some();
    let connected = guard.as_ref().is_some_and(|h| h.is_connected());
    Json(serde_json::json!({
        "ok": true,
        "service": "rackdeck",
        "version": env!("CARGO_PKG_VERSION"),
        "nodeId": state.local_node_id,
        "passwordSet": state.owner_password.is_some(),
        // The built-in default points at a relay on this machine, which normal users don't run.
        "relayConfigured": !state.relay_ws_url.contains("127.0.0.1:7430"),
        "connectEnabled": enabled,
        "connectActive": connected
    }))
}

async fn list_nodes(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state.fleet_svc.list_nodes(&principal).await {
        Ok(nodes) => Json(serde_json::json!({ "nodes": nodes })).into_response(),
        Err(e) => err_res(e),
    }
}

/// A machine's apps: this machine's from the local scan, others' from their last check-in.
async fn all_apps_for(state: &ApiState, principal: &Principal, node_id: &str) -> rackdeck_core::CoreResult<Vec<ManagedApp>> {
    let local = state.fleet_svc.list_apps(principal, node_id).await?; // also checks access
    if node_id == state.local_node_id {
        return Ok(local);
    }
    Ok(state.remote_apps.read().await.get(node_id).cloned().unwrap_or_default())
}

async fn list_node_apps(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match all_apps_for(&state, &principal, &node_id).await {
        Ok(apps) => Json(serde_json::json!({ "apps": apps })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn deploy_node_app(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    Json(spec): Json<DeploySpec>,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state.fleet_svc.deploy_app(&principal, &node_id, spec).await {
        Ok(app) => {
            refresh_local_apps(&state).await;
            Json(serde_json::json!({ "app": app })).into_response()
        }
        Err(e) => err_res(e),
    }
}

async fn refresh_local_apps(state: &ApiState) {
    if let Ok(mut apps) = state.local_node.list_apps().await {
        *state.latest_apps.write().await = apps.clone();
        for list in state.remote_apps.read().await.values() {
            apps.extend(list.clone());
        }
        let _ = state.ws_tx.send(ServerWsEvent::Apps {
            node_id: state.local_node_id.clone(),
            apps,
        });
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppActionOptions {
    #[serde(default)]
    delete_data: bool,
}

fn app_action_message(result: AppActionResult) -> Option<&'static str> {
    match result {
        AppActionResult::Done => None,
        AppActionResult::Updated => Some("App updated."),
        AppActionResult::AlreadyUpToDate => Some("Already up to date."),
    }
}

async fn run_app_change(
    state: ApiState,
    principal: Principal,
    node_id: String,
    app_id: String,
    action: AppAction,
) -> rackdeck_core::CoreResult<AppActionResult> {
    // Finish the Docker change and its audit entry even if the caller disconnects.
    tokio::spawn(async move {
        let result = state.fleet_svc.execute_app_action(&principal, &node_id, &app_id, action).await;
        if node_id == state.local_node_id
            && (matches!(&result, Ok(AppActionResult::Updated))
                || matches!(action, AppAction::Remove { .. }) && result.is_ok())
        {
            refresh_local_apps(&state).await;
        }
        result
    })
    .await
    .map_err(|_| CoreError::Runtime("The app operation was interrupted.".into()))?
}

async fn run_app_action(
    State(state): State<ApiState>,
    Path((node_id, app_id, action)): Path<(String, String, String)>,
    Query(options): Query<AppActionOptions>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let parsed = match action.as_str() {
        "start" => AppAction::Start,
        "stop" => AppAction::Stop,
        "restart" => AppAction::Restart,
        "remove" => AppAction::Remove { delete_data: options.delete_data },
        "update" => AppAction::Update,
        _ => return err_res(CoreError::InvalidInput("action must be start|stop|restart|remove|update".into())),
    };
    let result = if matches!(parsed, AppAction::Remove { .. } | AppAction::Update) {
        run_app_change(state, principal, node_id, app_id, parsed).await
    } else {
        state.fleet_svc.execute_app_action(&principal, &node_id, &app_id, parsed).await
    };
    match result {
        Ok(result) => Json(serde_json::json!({ "ok": true, "message": app_action_message(result) })).into_response(),
        Err(e) => err_res(e),
    }
}

/// Update Rackdeck on one machine. Owner only: it replaces the binary and restarts the process.
async fn require_owner_only(state: &ApiState, headers: &HeaderMap) -> Result<(), Response> {
    match resolve_principal(headers, state).await {
        Ok(Principal::Owner { .. }) => Ok(()),
        Ok(_) => Err(err_res(CoreError::Forbidden("only the owner can do this".into()))),
        Err(r) => Err(r),
    }
}

/// Names, machines and dates only. Values never leave the dashboard except sealed to a machine.
async fn list_secrets(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_owner_only(&state, &headers).await {
        return r;
    }
    match state.fleet_repo.list_secrets().await {
        Ok(list) => Json(
            list.into_iter()
                .map(|s| serde_json::json!({ "name": s.name, "nodeIds": s.node_ids, "updatedAt": s.updated_at }))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => err_res(e),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutSecretBody {
    /// Leave out to keep the current value and only change which machines get it.
    value: Option<String>,
    node_ids: Vec<String>,
}

async fn put_secret(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PutSecretBody>,
) -> Response {
    if let Err(r) = require_owner_only(&state, &headers).await {
        return r;
    }
    if !seal::valid_secret_name(&name) {
        return err_res(CoreError::InvalidInput(
            "use capital letters, digits and _ (like CLAUDE_CODE_OAUTH_TOKEN). PATH, HOME, LD_* and DYLD_* aren't allowed".into(),
        ));
    }
    let _admission = state.agent_admission.lock().await;
    for node_id in &body.node_ids {
        match state.fleet_repo.get_node(node_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return err_res(CoreError::NotFound(format!("No machine called {node_id}.")))
            }
            Err(e) => return err_res(e),
        }
    }
    let sk = state.signing_key.to_bytes();
    let existing = match state.fleet_repo.list_secrets().await {
        Ok(list) => list.into_iter().find(|s| s.name == name),
        Err(e) => return err_res(e),
    };
    let sealed = match (body.value, existing) {
        (Some(v), _) if !v.is_empty() => seal::encrypt_at_rest(&sk, &v),
        (_, Some(old)) => old.sealed,
        _ => return err_res(CoreError::InvalidInput("a new secret needs a value".into())),
    };
    let secret = rackdeck_core::Secret { name: name.clone(), sealed, node_ids: body.node_ids, updated_at: now_unix_secs() };
    if let Err(e) = state.fleet_repo.upsert_secret(secret).await {
        return err_res(e);
    }
    secret_changed(&state, "set secret", name).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_secret(State(state): State<ApiState>, Path(name): Path<String>, headers: HeaderMap) -> Response {
    if let Err(r) = require_owner_only(&state, &headers).await {
        return r;
    }
    match state.fleet_repo.delete_secret(&name).await {
        Ok(_) => {
            secret_changed(&state, "delete secret", name).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => err_res(e),
    }
}

/// Audit (name only) and refresh this machine's own secrets file. Joined machines pick up changes on their next check-in.
async fn secret_changed(state: &ApiState, action: &str, name: String) {
    let ev = AuditEvent {
        id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
        ts: now_unix_secs(),
        actor: "you (web)".into(),
        action: action.into(),
        target: name,
        ok: true,
        reason: None,
    };
    let _ = state.audit_repo.append_audit(ev.clone()).await;
    let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });
    if let Ok(vars) = secrets_for(state, &state.local_node_id).await {
        if !vars.is_empty() || seal::secrets_file_path().exists() {
            if let Err(e) = seal::write_secrets_file(&vars) {
                eprintln!("rackdeck: couldn't write this machine's secrets file: {e}");
            }
        }
    }
}

async fn remove_node(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match resolve_principal(&headers, &state).await {
        Ok(Principal::Owner { .. }) => {}
        Ok(_) => return err_res(CoreError::Forbidden("only the owner can remove machines".into())),
        Err(r) => return r,
    }
    if node_id == state.local_node_id {
        return err_res(CoreError::InvalidInput("can't remove the machine running the dashboard".into()));
    }
    let _admission = state.agent_admission.lock().await;
    if let Err(e) = state.fleet_repo.delete_node(&node_id).await {
        return err_res(e);
    }
    state.remote_apps.write().await.remove(&node_id);
    state.agent_bus.forget(&node_id).await;
    let _ = state.ws_tx.send(fleet_snapshot(&state).await);
    let ev = AuditEvent {
        id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
        ts: now_unix_secs(),
        actor: "you (web)".into(),
        action: "remove machine".into(),
        target: node_id,
        ok: true,
        reason: None,
    };
    let _ = state.audit_repo.append_audit(ev.clone()).await;
    let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });
    StatusCode::NO_CONTENT.into_response()
}

async fn update_node(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    match resolve_principal(&headers, &state).await {
        Ok(Principal::Owner { .. }) => {}
        Ok(_) => return err_res(CoreError::Forbidden("only the owner can update machines".into())),
        Err(r) => return r,
    }
    let result = if node_id == state.local_node_id {
        match update::self_update().await {
            Ok(Some(v)) => {
                // Answer first, then swap this process for the new binary.
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let err = update::restart_self();
                    eprintln!("rackdeck: updated on disk but couldn't restart ({err}); restart it manually");
                });
                Ok(Some(v))
            }
            other => other.map_err(CoreError::Runtime),
        }
    } else {
        state.agent_bus.update(&node_id).await
    };
    let ok = result.is_ok();
    let ev = AuditEvent {
        id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
        ts: now_unix_secs(),
        actor: "you (web)".into(),
        action: "update".into(),
        target: node_id.clone(),
        ok,
        reason: result.as_ref().err().map(|e| e.to_string()),
    };
    let _ = state.audit_repo.append_audit(ev.clone()).await;
    let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });
    match result {
        Ok(v) => Json(serde_json::json!({ "ok": true, "updatedTo": v })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn get_app_logs(
    State(state): State<ApiState>,
    Path((node_id, app_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state.fleet_svc.tail_logs(&principal, &node_id, &app_id, 150).await {
        Ok(lines) => Json(serde_json::json!({ "lines": lines })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn scan_network(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageNetwork, None) {
        return err_res(e);
    }
    let known: Vec<String> = state
        .fleet_repo
        .list_nodes()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| n.tailscale_ip)
        .collect();
    match state.discovery.scan_peers(state.listen_port, &known).await {
        Ok(peers) => {
            for p in &peers {
                let _ = state.ws_tx.send(ServerWsEvent::Disc { peer: p.clone() });
            }
            Json(serde_json::json!({ "peers": peers })).into_response()
        }
        Err(e) => err_res(e),
    }
}

/// Lets the installer tell "expired join command" apart from "can't reach the dashboard". Doesn't use up the token.
/// Takes the token's sha256 (X-Join-Check), so the token itself never crosses the network in the clear.
async fn join_check(State(state): State<ApiState>, headers: HeaderMap) -> StatusCode {
    let want = headers
        .get("x-join-check")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let now = now_unix_secs();
    let valid = state
        .join_tokens
        .read()
        .await
        .iter()
        .any(|(t, &exp)| now <= exp && hex::encode(Sha256::digest(t.as_bytes())) == want);
    if valid { StatusCode::NO_CONTENT } else { StatusCode::UNAUTHORIZED }
}

async fn issue_join_token(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageNetwork, None) {
        return err_res(e);
    }
    let mut raw = [0u8; 18];
    rand::thread_rng().fill(&mut raw);
    let token = format!("rd_join_{}", hex::encode(raw));
    let expires_at = now_unix_secs() + 900; // 15 minutes
    state
        .join_tokens
        .write()
        .await
        .insert(token.clone(), expires_at);

    let node = state.fleet_repo.get_node(&state.local_node_id).await.ok().flatten();
    // List every address we have; the installer keeps the first one the new machine can reach
    // (e.g. WSL often can't reach the Tailscale IP but can reach the LAN IP).
    let mut hosts: Vec<String> = node
        .map(|n| [n.tailscale_ip, n.lan_ip].into_iter().flatten().collect())
        .unwrap_or_default();
    hosts.dedup();
    if hosts.is_empty() {
        hosts.push("127.0.0.1".into());
    }
    let controller_url = hosts
        .iter()
        .map(|h| format!("http://{h}:{}", state.listen_port))
        .collect::<Vec<_>>()
        .join(",");
    // The key pins this dashboard, so the new machine's check-ins can't be read or faked on the network.
    let key = hex::encode(seal::public(&controller_channel_secret(&state)));
    let command = format!(
        "curl -fsSL https://get.rackdeck.dev | sh -s -- --controller {controller_url} --join {token} --key {key}"
    );
    Json(serde_json::json!({
        "token": token,
        "expiresAt": expires_at,
        "controllerUrl": controller_url,
        "command": command
    }))
    .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentCheckinBody {
    node: Node,
    sample: Option<TelemetrySample>,
    apps: Vec<ManagedApp>,
    #[serde(default)]
    results: Vec<AgentCommandResult>,
    #[serde(default)]
    app_management: bool,
    // Only inside sealed check-ins:
    #[serde(default)]
    join_token: Option<String>,
    /// Pre-0.2.4 bearer key, sent once so an updated agent can move to the sealed channel.
    #[serde(default)]
    agent_key: Option<String>,
    #[serde(default)]
    secrets_version: Option<String>,
    #[serde(default)]
    timestamp: Option<u64>,
    #[serde(default)]
    join_request_only: bool,
}

fn machine_already_joined(name: &str) -> CoreError {
    CoreError::Forbidden(format!(
        "A machine called {name} is already joined. Remove it on its page first, then try again."
    ))
}

fn check_node_available(
    name: &str,
    has_node: bool,
    stored: Option<&str>,
    key: &str,
) -> rackdeck_core::CoreResult<()> {
    match stored {
        Some(stored) if stored == key => Ok(()),
        None if !has_node => Ok(()),
        _ => Err(machine_already_joined(name)),
    }
}

async fn list_join_requests(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_owner_only(&state, &headers).await {
        return r;
    }
    let now = now_unix_secs();
    let mut reqs = state.join_requests.write().await;
    reqs.retain(|_, r| now.saturating_sub(r.at) < 900);
    let mut list: Vec<JoinRequest> = reqs.values().cloned().collect();
    list.sort_by_key(|r| r.at);
    Json(serde_json::json!({ "requests": list })).into_response()
}

/// Allow: record the machine's key, so its next check-in is accepted like any joined machine.
async fn allow_join_request(State(state): State<ApiState>, headers: HeaderMap, Path(key): Path<String>) -> Response {
    if let Err(r) = require_owner_only(&state, &headers).await {
        return r;
    }
    let _admission = state.agent_admission.lock().await;
    let Some(req) = state
        .join_requests
        .write()
        .await
        .remove(&key)
        .filter(|r| now_unix_secs().saturating_sub(r.at) < 900)
    else {
        return err_res(CoreError::NotFound("that request expired; run the install command on the machine again".into()));
    };
    let result = async {
        let node = state.fleet_repo.get_node(&req.node_id).await?;
        let stored = state.fleet_repo.agent_key_hash(&req.node_id).await?;
        let want = format!("x25519:{}", req.key);
        check_node_available(
            node.as_ref().map_or(&req.name, |n| &n.name),
            node.is_some(),
            stored.as_deref(),
            &want,
        )?;
        state
            .fleet_repo
            .set_agent_key_hash(&req.node_id, &want)
            .await
    }
    .await;
    if let Err(e) = result {
        return err_res(e);
    }
    let ev = AuditEvent {
        id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
        ts: now_unix_secs(),
        actor: "you (web)".into(),
        action: "allow machine".into(),
        target: req.node_id.clone(),
        ok: true,
        reason: None,
    };
    let _ = state.audit_repo.append_audit(ev.clone()).await;
    let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn ignore_join_request(State(state): State<ApiState>, headers: HeaderMap, Path(key): Path<String>) -> Response {
    if let Err(r) = require_owner_only(&state, &headers).await {
        return r;
    }
    let _admission = state.agent_admission.lock().await;
    if state.join_requests.write().await.remove(&key).is_some() {
        state
            .ignored_join_keys
            .lock()
            .await
            .insert(key, now_unix_secs());
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

/// One-time use. Expired tokens are dropped either way.
async fn take_join_token(state: &ApiState, token: &str) -> bool {
    match state.join_tokens.write().await.remove(token) {
        Some(exp) => now_unix_secs() <= exp,
        None => false,
    }
}

fn controller_channel_secret(state: &ApiState) -> [u8; 32] {
    seal::controller_secret(&state.signing_key.to_bytes())
}

/// Decrypted values of the secrets assigned to a machine.
async fn secrets_for(state: &ApiState, node_id: &str) -> rackdeck_core::CoreResult<std::collections::BTreeMap<String, String>> {
    let sk = state.signing_key.to_bytes();
    Ok(state
        .fleet_repo
        .list_secrets()
        .await?
        .into_iter()
        .filter(|s| s.node_ids.iter().any(|n| n == node_id))
        .filter_map(|s| seal::decrypt_at_rest(&sk, &s.sealed).map(|v| (s.name, v)))
        .collect())
}

/// Check-ins come two ways. Sealed (X-Rackdeck-Seal header): encrypted both ways and tied to the
/// agent's own key; the only way secrets are delivered. Legacy bearer: pre-0.2.4 agents.
async fn agent_checkin(State(state): State<ApiState>, headers: HeaderMap, raw: axum::body::Bytes) -> Response {
    let opened = if let Some(header) = headers.get("x-rackdeck-seal") {
        let Some(opened) = header.to_str().ok().and_then(|h| {
            seal::open_request(
                &controller_channel_secret(&state),
                h,
                &hex::decode(raw.trim_ascii()).ok()?,
            )
        }) else {
            return err_res(CoreError::Unauthorized(
                "couldn't open sealed check-in".into(),
            ));
        };
        Some(opened)
    } else {
        None
    };
    let mut body: AgentCheckinBody =
        match serde_json::from_slice(opened.as_ref().map_or(raw.as_ref(), |r| &r.plain)) {
            Ok(b) => b,
            Err(e) => return err_res(CoreError::InvalidInput(format!("bad check-in: {e}"))),
        };
    let now = now_unix_secs();
    if let Some(request) = &opened {
        if body.timestamp.is_some_and(|ts| now.abs_diff(ts) > 300) {
            return err_res(CoreError::Unauthorized(
                "Check the clock on this machine and the dashboard.".into(),
            ));
        }
        if !state
            .agent_bus
            .record_seal(request.agent, request.ephemeral)
            .await
        {
            return err_res(CoreError::Unauthorized(
                "Repeated check-in or too many recent check-ins.".into(),
            ));
        }
    }

    let _admission = state.agent_admission.lock().await;
    if body.node.id == state.local_node_id {
        return err_res(CoreError::Forbidden(
            "that machine id belongs to the controller itself".into(),
        ));
    }
    let node = match state.fleet_repo.get_node(&body.node.id).await {
        Ok(node) => node,
        Err(e) => return err_res(e),
    };
    let stored = match state.fleet_repo.agent_key_hash(&body.node.id).await {
        Ok(h) => h,
        Err(e) => return err_res(e),
    };
    let name = node.as_ref().map_or(&body.node.name, |n| &n.name);
    let sha = |k: &str| hex::encode(Sha256::digest(k.as_bytes()));
    let mut issued_agent_key: Option<String> = None;
    let mut joined = false;

    if let Some(request) = &opened {
        let key = hex::encode(request.agent);
        let want = format!("x25519:{key}");
        if stored.as_deref() != Some(&want) {
            match state.fleet_repo.agent_key_removed(&want).await {
                Ok(false) => {}
                Ok(true) => {
                    return err_res(CoreError::Forbidden(
                        "This machine was removed from the dashboard.".into(),
                    ))
                }
                Err(e) => return err_res(e),
            }
            let mut ignored = state.ignored_join_keys.lock().await;
            ignored.retain(|_, at| now.saturating_sub(*at) < 1800);
            if ignored.contains_key(&key) {
                return err_res(CoreError::Forbidden(
                    "This join request was ignored on the dashboard.".into(),
                ));
            }
            drop(ignored);

            let upgrading = matches!((&body.agent_key, &stored), (Some(k), Some(h)) if !h.starts_with("x25519:") && &sha(k) == h);
            if !upgrading {
                if let Err(e) = check_node_available(name, node.is_some(), stored.as_deref(), &want)
                {
                    return err_res(e);
                }
                let mut reqs = state.join_requests.write().await;
                reqs.retain(|_, r| now.saturating_sub(r.at) < 900);
                if reqs.get(&key).is_some_and(|r| r.node_id != body.node.id) {
                    return err_res(CoreError::Forbidden(
                        "This key already has a join request for a different machine ID.".into(),
                    ));
                }
                if body.join_request_only || body.join_token.is_none() {
                    if reqs.len() >= 20 && !reqs.contains_key(&key) {
                        return err_res(CoreError::Forbidden("Too many machines waiting. Try again after reviewing requests on the dashboard.".into()));
                    }
                    reqs.entry(key.clone()).or_insert_with(|| JoinRequest {
                        key: key.clone(),
                        node_id: body.node.id.clone(),
                        name: body.node.name.clone(),
                        os: body.node.os.clone(),
                        ip: body.node.lan_ip.clone().or(body.node.tailscale_ip.clone()),
                        code: seal::pair_code(
                            &seal::public(&controller_channel_secret(&state)),
                            &request.agent,
                        ),
                        at: now,
                    });
                    return (
                        StatusCode::FORBIDDEN,
                        Json(
                            serde_json::json!({ "error": "waiting for approval", "pending": true }),
                        ),
                    )
                        .into_response();
                }
                if !take_join_token(&state, body.join_token.as_deref().unwrap_or_default()).await {
                    return err_res(CoreError::Unauthorized(
                        "invalid or expired join token".into(),
                    ));
                }
                reqs.remove(&key);
                joined = true;
            }
            if let Err(e) = state.fleet_repo.set_agent_key_hash(&body.node.id, &want).await {
                return err_res(e);
            }
        }
        if body.join_request_only {
            return hex::encode(seal::seal_response(&request.reply_key, br#"{"ok":true}"#))
                .into_response();
        }
    } else {
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if bearer.is_empty() || body.join_request_only {
            return err_res(CoreError::Unauthorized("missing agent bearer token".into()));
        }
        let hash = sha(bearer);
        if stored.as_deref() != Some(&hash) {
            match state.fleet_repo.agent_key_removed(&hash).await {
                Ok(false) => {}
                Ok(true) => {
                    return err_res(CoreError::Forbidden(
                        "This machine was removed from the dashboard.".into(),
                    ))
                }
                Err(e) => return err_res(e),
            }
            if stored.is_some() && !bearer.starts_with("rd_join_") {
                return err_res(CoreError::Unauthorized("invalid agent bearer key".into()));
            }
            if let Err(e) = check_node_available(name, node.is_some(), stored.as_deref(), &hash) {
                return err_res(e);
            }
            if !take_join_token(&state, bearer).await {
                return err_res(CoreError::Unauthorized("invalid or expired join token".into()));
            }
            let mut raw = [0u8; 24];
            rand::thread_rng().fill(&mut raw);
            let agent_key = format!("rd_agent_{}", hex::encode(raw));
            if let Err(e) = state.fleet_repo.set_agent_key_hash(&body.node.id, &sha(&agent_key)).await {
                return err_res(e);
            }
            issued_agent_key = Some(agent_key);
            joined = true;
        }
    }

    body.node.connect_enabled = node.as_ref().is_some_and(|n| n.connect_enabled);
    body.node.connect_slug = node.and_then(|n| n.connect_slug);
    for app in &mut body.apps {
        app.node_id.clone_from(&body.node.id);
    }
    for result in &mut body.results {
        if let Ok(AgentOutput::App { app }) = &mut result.result {
            app.node_id.clone_from(&body.node.id);
        }
    }

    if joined {
        let ev = AuditEvent {
            id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
            ts: now_unix_secs(),
            actor: body.node.name.clone(),
            action: "node joined".into(),
            target: body.node.id.clone(),
            ok: true,
            reason: None,
        };
        let _ = state.audit_repo.append_audit(ev.clone()).await;
        let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });
    }

    if let Err(e) = state.fleet_repo.upsert_node(body.node.clone()).await {
        return err_res(e);
    }
    state
        .remote_apps
        .write()
        .await
        .insert(body.node.id.clone(), body.apps.clone());

    let _ = state.ws_tx.send(ServerWsEvent::Node {
        node: body.node.clone(),
    });
    if let Some(sample) = body.sample {
        let _ = state.ws_tx.send(ServerWsEvent::Tm {
            node_id: body.node.id.clone(),
            s: sample,
        });
    }

    let mut all_apps = state.latest_apps.read().await.clone();
    for list in state.remote_apps.read().await.values() {
        all_apps.extend(list.clone());
    }
    let _ = state.ws_tx.send(ServerWsEvent::Apps {
        node_id: body.node.id.clone(),
        apps: all_apps,
    });

    let commands = state
        .agent_bus
        .checkin(
            &body.node.id,
            body.results,
            body.app_management && opened.is_some(),
        )
        .await;

    let mut res = serde_json::json!({
        "ok": true,
        "agentKey": issued_agent_key,
        "commands": commands,
        "controllerKey": hex::encode(seal::public(&controller_channel_secret(&state))),
    });
    let Some(key) = opened.map(|r| r.reply_key) else {
        return Json(res).into_response();
    };
    // Secrets only ever travel sealed, and only when the machine's copy is out of date.
    if let Ok(vars) = secrets_for(&state, &body.node.id).await {
        let version = seal::secrets_version(&vars);
        if body.secrets_version.as_deref() != Some(version.as_str()) {
            res["secrets"] = serde_json::json!({ "version": version, "vars": vars });
        }
    }
    let sealed = seal::seal_response(&key, res.to_string().as_bytes());
    ([(header::CONTENT_TYPE, "text/plain")], hex::encode(sealed)).into_response()
}

async fn start_pairing(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageNetwork, None) {
        return err_res(e);
    }
    let node = state.fleet_repo.get_node(&state.local_node_id).await.ok().flatten();
    let host = node
        .and_then(|n| n.tailscale_ip.or(n.lan_ip))
        .unwrap_or_else(|| "127.0.0.1".into());
    let endpoint = format!("http://{host}:{}", state.listen_port);
    let invite = create_pairing_invitation(&state.local_node_id, &endpoint, &state.signing_key);
    Json(invite).into_response()
}

#[derive(Deserialize)]
struct ToggleConnectBody {
    enabled: bool,
    slug: Option<String>,
}

async fn toggle_connect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<ToggleConnectBody>,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageNetwork, None) {
        return err_res(e);
    }
    // The tunnel arrives from localhost, so without a password anyone with the public URL would be the owner.
    if body.enabled && state.owner_password.is_none() {
        return err_res(CoreError::Forbidden(
            "set RACKDECK_PASSWORD before turning on Connect".into(),
        ));
    }

    let slug = match body.slug {
        Some(slug) => Some(slug),
        None if body.enabled => match state.fleet_repo.get_node(&state.local_node_id).await {
            Ok(Some(node)) => Some(
                node.connect_slug
                    .unwrap_or_else(|| node.name.to_ascii_lowercase()),
            ),
            Ok(None) => return err_res(CoreError::NotFound(state.local_node_id)),
            Err(e) => return err_res(e),
        },
        None => None,
    };
    if slug.as_deref().is_some_and(|s| {
        s.is_empty()
            || !s
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }) {
        return err_res(CoreError::InvalidInput(
            "Use only lowercase letters, numbers, and hyphens in the Connect name.".into(),
        ));
    }
    let updated: Node = match state
        .fleet_repo
        .set_connect_state(&state.local_node_id, body.enabled, slug)
        .await
    {
        Ok(n) => n,
        Err(e) => return err_res(e),
    };

    let mut guard = state.connect_handle.lock().await;
    if let Some(prev) = guard.take() {
        prev.stop();
    }
    if updated.connect_enabled {
        let slug = updated
            .connect_slug
            .clone()
            .unwrap_or_else(|| updated.name.to_lowercase());
        let handle = spawn_connect_client(ConnectClientConfig {
            relay_ws_url: state.relay_ws_url.clone(),
            slug,
            node_id: updated.id.clone(),
            signing_key: (*state.signing_key).clone(),
            local_upstream_addr: format!("127.0.0.1:{}", state.listen_port),
        });
        *guard = Some(handle);
    }
    drop(guard);

    let _ = state.ws_tx.send(ServerWsEvent::Node { node: updated.clone() });
    let ev = AuditEvent {
        id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
        ts: now_unix_secs(),
        actor: principal.actor_name().to_string(),
        action: if updated.connect_enabled {
            "enable connect".into()
        } else {
            "disable connect".into()
        },
        target: updated.name.clone(),
        ok: true,
        reason: None,
    };
    let _ = state.audit_repo.append_audit(ev.clone()).await;
    let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });

    Json(serde_json::json!({ "node": updated })).into_response()
}

/// The relay's HTTP base, from its tunnel URL (wss://relay/_rackdeck/tunnel -> https://relay).
fn relay_http_base(state: &ApiState) -> String {
    let http = state
        .relay_ws_url
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
    http.strip_suffix("/_rackdeck/tunnel").unwrap_or(&http).to_string()
}

/// Call the Connect relay's account API and pass its JSON answer through.
async fn relay_call(state: &ApiState, path: &str, body: Option<serde_json::Value>) -> Response {
    let url = format!("{}{path}", relay_http_base(state));
    let mut cmd = tokio::process::Command::new("curl");
    cmd.args(["-sS", "-m", "10", "-w", "\n%{http_code}"]);
    if let Some(b) = &body {
        cmd.args(["-X", "POST", "-H", "Content-Type: application/json", "--data-binary", &b.to_string()]);
    }
    let out = match cmd.arg(&url).kill_on_drop(true).output().await {
        Ok(o) if o.status.success() => o,
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("couldn't reach the Connect relay at {}", relay_http_base(state)) })),
            )
                .into_response()
        }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let (resp, code) = text.rsplit_once('\n').unwrap_or((&text, "502"));
    let code = code
        .trim()
        .parse::<u16>()
        .ok()
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let val: serde_json::Value = serde_json::from_str(resp)
        .unwrap_or_else(|_| serde_json::json!({ "error": "the relay sent an unexpected reply" }));
    (code, Json(val)).into_response()
}

async fn require_owner(headers: &HeaderMap, state: &ApiState) -> Result<(), Response> {
    match resolve_principal(headers, state).await? {
        Principal::Owner { .. } => Ok(()),
        _ => Err(err_res(CoreError::Forbidden("owner only".into()))),
    }
}

fn controller_pk(state: &ApiState) -> String {
    hex::encode(state.signing_key.verifying_key().to_bytes())
}

/// Is this dashboard linked to a Rackdeck account, and is Connect paid for?
async fn account_status(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_owner(&headers, &state).await {
        return r;
    }
    relay_call(&state, &format!("/account/controller?pk={}", controller_pk(&state)), None).await
}

#[derive(Deserialize)]
struct LinkBody {
    slug: String,
}

/// Start linking: returns a code and URL for the owner to approve while logged in on the relay.
async fn account_link(State(state): State<ApiState>, headers: HeaderMap, Json(body): Json<LinkBody>) -> Response {
    if let Err(r) = require_owner(&headers, &state).await {
        return r;
    }
    let payload = serde_json::json!({ "slug": body.slug.trim().to_ascii_lowercase(), "publicKeyHex": controller_pk(&state) });
    relay_call(&state, "/account/link/start", Some(payload)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkPollBody {
    poll_token: String,
}

async fn account_link_poll(State(state): State<ApiState>, headers: HeaderMap, Json(body): Json<LinkPollBody>) -> Response {
    if let Err(r) = require_owner(&headers, &state).await {
        return r;
    }
    relay_call(&state, "/account/link/poll", Some(serde_json::json!({ "pollToken": body.poll_token }))).await
}

async fn list_routes(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = resolve_principal(&headers, &state).await {
        return r;
    }
    match state.route_repo.list_routes().await {
        Ok(routes) => Json(serde_json::json!({ "routes": routes })).into_response(),
        Err(e) => err_res(e),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddRouteBody {
    host: String,
    node_id: String,
    target_app: String,
    target_port: u16,
    require_auth: Option<bool>,
}

async fn add_route(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<AddRouteBody>,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageNetwork, None) {
        return err_res(e);
    }
    let _admission = state.agent_admission.lock().await;
    match state.fleet_repo.get_node(&body.node_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return err_res(CoreError::NotFound(format!(
                "No machine called {}.",
                body.node_id
            )))
        }
        Err(e) => return err_res(e),
    }
    let route = ConnectRoute {
        id: format!("rt-{}", uuid::Uuid::new_v4().simple()),
        host: body.host.trim().to_ascii_lowercase(),
        node_id: body.node_id,
        target_app: body.target_app,
        target_port: body.target_port,
        tls: if body.host.ends_with(".rackdev.app") {
            TlsState::Valid
        } else {
            TlsState::Issuing
        },
        require_auth: body.require_auth.unwrap_or(false),
        bytes_24h: 0,
    };
    match state.route_repo.upsert_route(route.clone()).await {
        Ok(()) => Json(serde_json::json!({ "route": route })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn remove_route(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageNetwork, None) {
        return err_res(e);
    }
    match state.route_repo.delete_route(&id).await {
        Ok(deleted) => Json(serde_json::json!({ "deleted": deleted })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn list_tokens(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageTokens, None) {
        return err_res(e);
    }
    match state.token_repo.list_tokens().await {
        Ok(tokens) => Json(serde_json::json!({ "tokens": tokens })).into_response(),
        Err(e) => err_res(e),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateTokenBody {
    name: String,
    client: String,
    scope: TokenScope,
    node_ids: Option<Vec<String>>,
    expires_in_days: Option<u64>,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    record: rackdeck_core::AccessTokenRecord,
    token: String,
    snippet: String,
}

async fn create_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateTokenBody>,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageTokens, None) {
        return err_res(e);
    }
    let mut raw_bytes = [0u8; 24];
    rand::thread_rng().fill(&mut raw_bytes);
    let raw_token = format!("rd_tok_{}", hex::encode(raw_bytes));
    let hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
    let expires_at = body
        .expires_in_days
        .map(|d| now_unix_secs() + d.saturating_mul(86_400));

    match state
        .token_repo
        .create_token(
            body.name.clone(),
            body.client.clone(),
            body.scope,
            body.node_ids.unwrap_or_default(),
            hash,
            expires_at,
        )
        .await
    {
        Ok(record) => {
            let mcp_url = format!("http://127.0.0.1:{}/mcp", state.listen_port);
            let snippet = match body.client.to_ascii_lowercase().as_str() {
                "claude code" => format!(
                    "claude mcp add rackdeck --transport http {mcp_url} --header \"Authorization: Bearer {raw_token}\""
                ),
                "codex" => format!(
                    "codex mcp add rackdeck --url {mcp_url} --bearer-token {raw_token}"
                ),
                _ => format!(
                    "{{\n  \"mcpServers\": {{\n    \"rackdeck\": {{\n      \"url\": \"{mcp_url}\",\n      \"headers\": {{ \"Authorization\": \"Bearer {raw_token}\" }}\n    }}\n  }}\n}}"
                ),
            };
            let ev = AuditEvent {
                id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
                ts: now_unix_secs(),
                actor: principal.actor_name().to_string(),
                action: "create token".into(),
                target: body.name,
                ok: true,
                reason: None,
            };
            let _ = state.audit_repo.append_audit(ev.clone()).await;
            let _ = state.ws_tx.send(ServerWsEvent::Audit { ev });
            Json(CreateTokenResponse {
                record,
                token: raw_token,
                snippet,
            })
            .into_response()
        }
        Err(e) => err_res(e),
    }
}

async fn revoke_token(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = principal.authorize(Capability::ManageTokens, None) {
        return err_res(e);
    }
    match state.token_repo.revoke_token(&id).await {
        Ok(revoked) => Json(serde_json::json!({ "revoked": revoked })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn list_audit(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if !is_valid_owner_session(&headers, &state).await {
        return err_res(CoreError::Unauthorized("authentication required".into()));
    }
    match state.audit_repo.list_audit(100).await {
        Ok(events) => Json(serde_json::json!({ "events": events })).into_response(),
        Err(e) => err_res(e),
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Response {
    if !is_valid_owner_session(&headers, &state).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let sid = extract_session_cookie(&headers);
    ws.on_upgrade(move |socket| handle_ui_ws(socket, state, sid))
}

/// Live logs for an app on a remote agent: poll its tail every 3s and forward only new lines.
async fn follow_remote_logs(
    fleet: Arc<FleetService>,
    principal: Principal,
    node_id: String,
    app_id: String,
    sub: String,
    tx: tokio::sync::mpsc::Sender<String>,
) {
    let mut last: Option<String> = None;
    loop {
        let lines = match fleet.tail_logs(&principal, &node_id, &app_id, 200).await {
            Ok(lines) => lines,
            Err(e) => vec![format!("[rackdeck] couldn't read logs from {node_id}: {e}")],
        };
        // ponytail: resumes after the last line we sent; if that exact line repeats in the window
        // a few lines may be skipped. Switch to `docker logs --since` cursors if that bites.
        let start = last
            .as_ref()
            .and_then(|l| lines.iter().rposition(|x| x == l).map(|i| i + 1))
            .unwrap_or(if last.is_some() { 0 } else { lines.len().saturating_sub(80) });
        let fresh = &lines[start.min(lines.len())..];
        if !fresh.is_empty() {
            last = fresh.last().cloned();
            let now = now_unix_secs();
            let ev = ServerWsEvent::Log {
                sub: sub.clone(),
                lines: fresh.iter().map(|l| (now, "stdout".to_string(), l.clone())).collect(),
            };
            if let Ok(out) = serde_json::to_string(&ev) {
                if tx.send(out).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn fleet_snapshot(state: &ApiState) -> ServerWsEvent {
    let nodes = state.fleet_repo.list_nodes().await.unwrap_or_default();
    let mut apps = state.latest_apps.read().await.clone();
    for list in state.remote_apps.read().await.values() {
        apps.extend(list.clone());
    }
    ServerWsEvent::Snapshot { nodes, apps }
}

async fn handle_ui_ws(socket: WebSocket, state: ApiState, sid: Option<String>) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let (mut ws_tx, mut ws_rx) = socket.split();

    let mut rx = state.ws_tx.subscribe();
    // Send initial snapshot immediately
    if let Ok(text) = serde_json::to_string(&fleet_snapshot(&state).await) {
        let _ = ws_tx.send(Message::Text(text.into())).await;
    }
    if let Some(sample) = state.latest_sample.read().await.clone() {
        if let Ok(text) = serde_json::to_string(&ServerWsEvent::Tm {
            node_id: state.local_node_id.clone(),
            s: sample,
        }) {
            let _ = ws_tx.send(Message::Text(text.into())).await;
        }
    }

    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<String>(128);
    let mut log_tasks: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();

    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Ok(ev) = rx.recv() => {
                    if let Ok(text) = serde_json::to_string(&ev) {
                        if ws_tx.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Some(direct) = reply_rx.recv() => {
                    if ws_tx.send(Message::Text(direct.into())).await.is_err() {
                        break;
                    }
                }
                else => break,
            }
        }
    });

    // Logging out or an expired session closes the socket, which also stops live logs and stats.
    let mut session_check = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        let msg = tokio::select! {
            m = ws_rx.next() => match m {
                Some(Ok(m)) => m,
                _ => break,
            },
            _ = session_check.tick() => {
                if session_still_valid(&state, sid.as_deref()).await { continue } else { break }
            }
        };
        if !session_still_valid(&state, sid.as_deref()).await {
            break;
        }
        if let Message::Text(txt) = msg {
            if let Ok(cmd) = serde_json::from_str::<ClientWsCommand>(&txt) {
                match cmd {
                    ClientWsCommand::Ping { id } => {
                        if let Ok(out) = serde_json::to_string(&ServerWsEvent::Pong { id }) {
                            let _ = reply_tx.send(out).await;
                        }
                    }
                    ClientWsCommand::Sub {
                        ch,
                        sub,
                        node_id,
                        app_id,
                    } if ch == "logs" => {
                        if let Some(prev) = log_tasks.remove(&sub) {
                            prev.abort();
                        }
                        let target = app_id.unwrap_or_else(|| "system:rackdeck".into());
                        let tx = reply_tx.clone();
                        let sub_key = sub.clone();
                        if node_id != state.local_node_id {
                            let fleet = state.fleet_svc.clone();
                            // WS upgrades are owner-session only (see ws_handler).
                            let principal = Principal::Owner { label: "you (web)".into() };
                            let handle = tokio::spawn(async move {
                                follow_remote_logs(fleet, principal, node_id, target, sub_key, tx).await
                            });
                            log_tasks.insert(sub, handle);
                            continue;
                        }
                        let local_node = state.local_node.clone();
                        let handle = tokio::spawn(async move {
                            if let Some(cid) = target.strip_prefix("docker:") {
                                if let Ok(mut child) = Command::new("docker")
                                    .args(["logs", "-f", "--tail", "50", "--", cid])
                                    .stdout(std::process::Stdio::piped())
                                    .stderr(std::process::Stdio::piped())
                                    .kill_on_drop(true)
                                    .spawn()
                                {
                                    if let Some(stdout) = child.stdout.take() {
                                        let mut reader = BufReader::new(stdout).lines();
                                        while let Ok(Some(line)) = reader.next_line().await {
                                            let ev = ServerWsEvent::Log {
                                                sub: sub_key.clone(),
                                                lines: vec![(now_unix_secs(), "stdout".into(), line)],
                                            };
                                            if let Ok(out) = serde_json::to_string(&ev) {
                                                if tx.send(out).await.is_err() {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    return;
                                }
                            }
                            if let Ok(lines) = local_node.tail_logs(&target, 80).await {
                                let now = now_unix_secs();
                                let formatted = lines
                                    .into_iter()
                                    .map(|l| (now, "stdout".to_string(), l))
                                    .collect();
                                if let Ok(out) = serde_json::to_string(&ServerWsEvent::Log {
                                    sub: sub_key.clone(),
                                    lines: formatted,
                                }) {
                                    let _ = tx.send(out).await;
                                }
                            }
                            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3));
                            ticker.tick().await;
                            loop {
                                ticker.tick().await;
                                let ev = ServerWsEvent::Log {
                                    sub: sub_key.clone(),
                                    lines: vec![(
                                        now_unix_secs(),
                                        "stdout".into(),
                                        format!("[{target}] heartbeat ok"),
                                    )],
                                };
                                if let Ok(out) = serde_json::to_string(&ev) {
                                    if tx.send(out).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        });
                        log_tasks.insert(sub, handle);
                    }
                    ClientWsCommand::Unsub { sub } => {
                        if let Some(h) = log_tasks.remove(&sub) {
                            h.abort();
                        }
                    }
                    ClientWsCommand::TermExec { sub, cmd } => {
                        let tx = reply_tx.clone();
                        if !session_still_valid(&state, sid.as_deref()).await {
                            if let Ok(out) = serde_json::to_string(&ServerWsEvent::TermOut {
                                sub,
                                text: "error: your session ended, reload and log in again\n".into(),
                            }) {
                                let _ = tx.send(out).await;
                            }
                            continue;
                        }
                        let audit = state.audit_repo.clone();
                        let ws_bcast = state.ws_tx.clone();
                        let node_id = state.local_node_id.clone();
                        tokio::spawn(async move {
                            let res = tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                Command::new("/bin/sh")
                                    .args(["-lc", &cmd])
                                    .stdout(std::process::Stdio::piped())
                                    .stderr(std::process::Stdio::piped())
                                    .kill_on_drop(true)
                                    .output(),
                            )
                            .await;
                            let text = match res {
                                Ok(Ok(out)) => {
                                    let mut combined =
                                        String::from_utf8_lossy(&out.stdout).to_string();
                                    let err = String::from_utf8_lossy(&out.stderr);
                                    if !err.is_empty() {
                                        combined.push_str(&err);
                                    }
                                    if combined.is_empty() {
                                        format!("(exit {})\n", out.status.code().unwrap_or(0))
                                    } else {
                                        combined
                                    }
                                }
                                Ok(Err(e)) => format!("error: {e}\n"),
                                Err(_) => "error: command timed out after 15s\n".to_string(),
                            };
                            if let Ok(out) = serde_json::to_string(&ServerWsEvent::TermOut {
                                sub,
                                text,
                            }) {
                                let _ = tx.send(out).await;
                            }
                            let ev = AuditEvent {
                                id: format!("aud-{}", uuid::Uuid::new_v4().simple()),
                                ts: now_unix_secs(),
                                actor: "you (web)".into(),
                                action: "terminal exec".into(),
                                target: node_id,
                                ok: true,
                                reason: None,
                            };
                            let _ = audit.append_audit(ev.clone()).await;
                            let _ = ws_bcast.send(ServerWsEvent::Audit { ev });
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    for (_, h) in log_tasks {
        h.abort();
    }
    send_task.abort();
}

#[derive(Deserialize)]
struct McpRpcRequest {
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

/// The one-click apps, shared with the dashboard's catalog page.
fn catalog() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!("../../../ui/src/catalog.json")).unwrap_or_default()
}

fn mcp_tools() -> serde_json::Value {
    let node = serde_json::json!({ "type": "string", "description": "Machine id from node_health. Defaults to the dashboard's own machine." });
    let manage = "Needs an assistant allowed to manage apps.";
    serde_json::json!([
        { "name": "node_health", "description": "List the machines with status, hardware and latest CPU, memory, disk and GPU use.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "container_logs_tail", "description": "Read the last lines of an app's logs.",
          "inputSchema": { "type": "object", "properties": {
              "nodeId": node, "appId": { "type": "string", "description": "App id from the machine's app list, e.g. docker:jellyfin" },
              "lines": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } }, "required": ["appId"] } },
        { "name": "app_action", "description": format!("Start, stop or restart an app. {manage}"),
          "inputSchema": { "type": "object", "properties": {
              "nodeId": node, "appId": { "type": "string" }, "action": { "type": "string", "enum": ["start", "stop", "restart"] } },
              "required": ["appId", "action"] } },
        { "name": "remove_app", "description": format!("Remove a Docker app and keep its saved data. {manage}"),
          "inputSchema": { "type": "object", "properties": {
              "nodeId": node, "appId": { "type": "string", "description": "App id from list_apps." } },
              "required": ["appId"], "additionalProperties": false } },
        { "name": "update_app", "description": format!("Update a Docker app using its saved Rackdeck install settings. {manage}"),
          "inputSchema": { "type": "object", "properties": {
              "nodeId": node, "appId": { "type": "string", "description": "App id from list_apps." } },
              "required": ["appId"], "additionalProperties": false } },
        { "name": "list_apps", "description": "List the apps on every machine: containers and local model servers (ninfer, Ollama, vLLM, MLX), with ids, ports and state.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "list_catalog_apps", "description": "List the apps Rackdeck can install in one step (Jellyfin, AdGuard Home, Open WebUI and others), with what each does and its port. Prefer these over deploy_app.",
          "inputSchema": { "type": "object", "properties": {} } },
        { "name": "install_app", "description": format!("Install an app from list_catalog_apps on a machine, with tested ports and saved data. Uses the GPU when the machine has an NVIDIA one. Returns the address to open. {manage} Media folders can't be attached this way; the owner adds those in the dashboard."),
          "inputSchema": { "type": "object", "properties": {
              "nodeId": node, "app": { "type": "string", "description": "App id from list_catalog_apps, e.g. jellyfin" },
              "modelServer": { "type": "string", "description": "For apps with modelServer (Open WebUI): use a model server already running on the network instead of downloading models, e.g. http://192.168.1.78:8080 (find them with list_apps)" },
              "modelServerType": { "type": "string", "enum": ["openai", "ollama"], "default": "openai", "description": "ollama for Ollama; openai for ninfer, vLLM, MLX and other OpenAI-style servers" },
              "modelServerKey": { "type": "string", "description": "API key, if the model server needs one" } },
              "required": ["nodeId", "app"] } },
        { "name": "deploy_app", "description": format!("Run any Docker image as an app. Use install_app instead when the app is in the catalog. {manage}"),
          "inputSchema": { "type": "object", "properties": {
              "nodeId": node,
              "name": { "type": "string", "description": "Container name: letters, digits, - and _" },
              "image": { "type": "string" },
              "hostPort": { "type": "integer" }, "containerPort": { "type": "integer" },
              "ports": { "type": "array", "items": { "type": "string" }, "description": "Extra port maps like 53:53/udp" },
              "volumes": { "type": "array", "items": { "type": "string" }, "description": "Named volumes like app-data:/data" },
              "env": { "type": "object", "additionalProperties": { "type": "string" } },
              "gpu": { "type": "boolean" } },
              "required": ["name", "image"] } }
    ])
}

/// Open WebUI settings for a model server elsewhere on the network.
fn open_webui_model_env(url: &str, kind: &str, key: Option<&str>) -> std::collections::BTreeMap<String, String> {
    let url = url.trim_end_matches('/');
    let mut env = std::collections::BTreeMap::new();
    if kind == "ollama" {
        env.insert("OLLAMA_BASE_URL".into(), url.to_string());
    } else {
        let base = if url.ends_with("/v1") { url.to_string() } else { format!("{url}/v1") };
        env.insert("OPENAI_API_BASE_URL".into(), base);
        env.insert("OPENAI_API_KEY".into(), key.filter(|k| !k.is_empty()).unwrap_or("none").to_string());
        env.insert("ENABLE_OLLAMA_API".into(), "false".into());
    }
    env
}

async fn install_catalog_app(state: &ApiState, principal: &Principal, args: &serde_json::Value) -> rackdeck_core::CoreResult<String> {
    let node_id = args.get("nodeId").and_then(|v| v.as_str()).unwrap_or(&state.local_node_id).to_string();
    let want = args.get("app").and_then(|v| v.as_str()).unwrap_or_default();
    let Some(app) = catalog().into_iter().find(|a| a["id"] == want) else {
        return Err(CoreError::NotFound(format!("no catalog app `{want}`; call list_catalog_apps")));
    };
    let node = state.fleet_repo.get_node(&node_id).await?.ok_or_else(|| CoreError::NotFound(format!("no machine `{node_id}`")))?;
    let nvidia = matches!(node.hw.accel, rackdeck_core::Accelerator::Nvidia { driver_loaded: true, .. });
    let strs = |k: &str| -> Vec<String> {
        app[k].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    let mut spec = DeploySpec {
        name: app["id"].as_str().unwrap_or_default().to_string(),
        image: app["image"].as_str().unwrap_or_default().to_string(),
        host_port: app["hostPort"].as_u64().map(|p| p as u16),
        container_port: app["containerPort"].as_u64().map(|p| p as u16),
        env: Default::default(),
        ports: strs("ports"),
        volumes: strs("volumes"),
        gpu: app["gpu"].as_bool().unwrap_or(false) && nvidia,
    };
    let model_server = args
        .get("modelServer")
        .and_then(|v| v.as_str())
        .filter(|u| !u.is_empty());
    if let Some(url) = model_server {
        let alt = &app["modelServer"];
        if !alt.is_object() {
            return Err(CoreError::InvalidInput(format!("{want} doesn't connect to a model server")));
        }
        spec.image = alt["image"].as_str().unwrap_or_default().to_string();
        spec.volumes = alt["volumes"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
        spec.gpu = false;
        spec.env = open_webui_model_env(
            url,
            args.get("modelServerType").and_then(|v| v.as_str()).unwrap_or("openai"),
            args.get("modelServerKey").and_then(|v| v.as_str()),
        );
    }
    state.fleet_svc.deploy_app(principal, &node_id, spec).await?;
    let host = node.lan_ip.or(node.tailscale_ip).unwrap_or_else(|| node.name.clone());
    let next = if model_server.is_some() {
        "Create the admin account, then choose a model from your server."
    } else if app["folder"].is_object() {
        "Finish setup. Ask the dashboard owner to link your media folder when installing from the catalog."
    } else {
        app["next"].as_str().unwrap_or_default()
    };
    Ok(format!(
        "{} is running on {}. Open http://{host}:{}\nNext: {next}",
        app["name"].as_str().unwrap_or_default(),
        node.name,
        app["hostPort"],
    ))
}

async fn mcp_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(rpc): Json<McpRpcRequest>,
) -> Response {
    let principal = match resolve_principal(&headers, &state).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let id = rpc.id.unwrap_or(serde_json::Value::Null);

    // Notifications (like notifications/initialized) get no reply.
    if rpc.method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }
    match rpc.method.as_str() {
        "ping" => Json(serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} })).into_response(),
        "initialize" => Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-11-25",
                "serverInfo": { "name": "rackdeck", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "tools": {} }
            }
        }))
        .into_response(),
        "tools/list" => Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": mcp_tools()
            }
        }))
        .into_response(),
        "tools/call" => {
            let params = rpc.params.unwrap_or_default();
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_default();

            let result_text = match name {
                "node_health" => match state.fleet_svc.list_nodes(&principal).await {
                    Ok(nodes) => Ok(serde_json::to_string_pretty(&nodes).unwrap_or_default()),
                    Err(e) => Err(e),
                },
                "container_logs_tail" => {
                    let node_id = args
                        .get("nodeId")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&state.local_node_id);
                    let app_id = args
                        .get("appId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("system:rackdeck");
                    let lines = args
                        .get("lines")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(50) as usize;
                    state
                        .fleet_svc
                        .tail_logs(&principal, node_id, app_id, lines)
                        .await
                        .map(|l| l.join("\n"))
                }
                "app_action" => {
                    async {
                        let node_id = args
                            .get("nodeId")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&state.local_node_id);
                        let app_id = args.get("appId").and_then(|v| v.as_str()).unwrap_or("");
                        let action = match args.get("action").and_then(|v| v.as_str()).unwrap_or("")
                        {
                            "start" => AppAction::Start,
                            "stop" => AppAction::Stop,
                            "restart" => AppAction::Restart,
                            _ => {
                                return Err(CoreError::InvalidInput(
                                    "action must be start|stop|restart".into(),
                                ))
                            }
                        };
                        state
                            .fleet_svc
                            .execute_app_action(&principal, node_id, app_id, action)
                            .await
                            .map(|_| "ok".to_string())
                    }
                    .await
                }
                "remove_app" | "update_app" => async {
                    let node_id = args.get("nodeId").and_then(|v| v.as_str()).unwrap_or(&state.local_node_id);
                    let app_id = args.get("appId").and_then(|v| v.as_str())
                        .filter(|id| !id.is_empty())
                        .ok_or_else(|| CoreError::InvalidInput("Choose an app from list_apps.".into()))?;
                    let action = if name == "remove_app" {
                        if args.get("deleteData").is_some_and(|v| v.as_bool() != Some(false)) {
                            return Err(CoreError::Forbidden("Only the owner can delete app data in the dashboard.".into()));
                        }
                        AppAction::Remove { delete_data: false }
                    } else {
                        AppAction::Update
                    };
                    let node_id = node_id.to_string();
                    let result = run_app_change(state, principal, node_id, app_id.to_string(), action).await?;
                    Ok(app_action_message(result).unwrap_or("App removed.").to_string())
                }.await,
                "deploy_app" => {
                    let node_id = args
                        .get("nodeId")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&state.local_node_id)
                        .to_string();
                    match serde_json::from_value::<DeploySpec>(args) {
                        Ok(spec) => state
                            .fleet_svc
                            .deploy_app(&principal, &node_id, spec)
                            .await
                            .map(|a| serde_json::to_string_pretty(&a).unwrap_or_default()),
                        Err(e) => Err(CoreError::InvalidInput(format!("invalid deploy spec: {e}"))),
                    }
                }
                "list_apps" => async {
                    let mut out = Vec::new();
                    for n in state.fleet_svc.list_nodes(&principal).await? {
                        if let Ok(apps) = all_apps_for(&state, &principal, &n.id).await {
                            out.extend(apps);
                        }
                    }
                    Ok(serde_json::to_string_pretty(&out).unwrap_or_default())
                }
                .await,
                "list_catalog_apps" => Ok(serde_json::to_string_pretty(&catalog()).unwrap_or_default()),
                "install_app" => install_catalog_app(&state, &principal, &args).await,
                _ => Err(CoreError::NotFound(format!("unknown tool {name}"))),
            };

            match result_text {
                Ok(text) => Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": text }] }
                }))
                .into_response(),
                // Tool failures go back as a result the assistant can read and act on.
                Err(e) => Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": e.to_string() }], "isError": true }
                }))
                .into_response(),
            }
        }
        _ => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            })),
        )
            .into_response(),
    }
}

async fn serve_embedded_ui(State(state): State<ApiState>, uri: Uri) -> Response {
    let Some(assets) = &state.assets else {
        return Json(serde_json::json!({ "service": "rackdeck", "ui": "not embedded" })).into_response();
    };
    let req_path = uri.path().trim_start_matches('/');
    let lookup = if req_path.is_empty() {
        "index.html"
    } else {
        req_path
    };
    if let Some((bytes, mime)) = assets.get_asset(lookup).or_else(|| assets.get_asset("index.html")) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    StatusCode::NOT_FOUND.into_response()
}
