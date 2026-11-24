use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use rackdeck_core::{ConnectTenant, TenantRepository, UsageRepository};
use rackdeck_protocol::{
    AuthPayload, ChallengePayload, Frame, FrameType, HelloPayload, HttpRequestHead,
    HttpResponseHead, DEFAULT_DATA_CHUNK,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::verify_challenge;

mod account;
pub use account::AccountConfig;

struct TunnelSession {
    slug: String,
    node_id: String,
    generation: u64,
    tx: mpsc::Sender<Bytes>,
    requests: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

type PendingMap = HashMap<u32, oneshot::Sender<Result<(HttpResponseHead, Vec<u8>), StatusCode>>>;

#[derive(Clone)]
pub struct BillingConfig {
    pub require_subscription: bool,
    pub stripe_webhook_secret: Option<String>,
    pub stripe_secret_key: Option<String>,
    pub stripe_price_id: Option<String>,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Clone)]
pub struct RelayState {
    audience: String,
    sessions: Arc<RwLock<HashMap<String, Arc<TunnelSession>>>>,
    pending: Arc<RwLock<PendingMap>>,
    next_stream_id: Arc<AtomicU32>,
    usage_repo: Option<Arc<dyn UsageRepository>>,
    tenant_repo: Option<Arc<dyn TenantRepository>>,
    billing: BillingConfig,
    accounts: AccountConfig,
    account_mem: account::SharedAccountMem,
}

#[derive(Serialize)]
struct RelayStats {
    ok: bool,
    active_tunnels: usize,
    tunnels: Vec<TunnelStat>,
}

#[derive(Serialize)]
struct TunnelStat {
    slug: String,
    node_id: String,
    generation: u64,
    requests: u64,
    bytes_in: u64,
    bytes_out: u64,
}

impl RelayState {
    pub fn new(audience: impl Into<String>, usage_repo: Option<Arc<dyn UsageRepository>>) -> Self {
        Self {
            audience: audience.into(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
            next_stream_id: Arc::new(AtomicU32::new(2)), // relay uses even stream IDs
            usage_repo,
            tenant_repo: None,
            billing: BillingConfig {
                require_subscription: false,
                stripe_webhook_secret: None,
                stripe_secret_key: None,
                stripe_price_id: None,
                success_url: "https://rackdeck.dev/connect/success".into(),
                cancel_url: "https://rackdeck.dev/connect/cancel".into(),
            },
            accounts: AccountConfig::default(),
            account_mem: Default::default(),
        }
    }

    pub fn with_accounts(mut self, accounts: AccountConfig) -> Self {
        self.accounts = accounts;
        self
    }

    /// Close a slug's tunnel with a GOAWAY reason (e.g. subscription ended).
    async fn drop_tunnel(&self, slug: &str, reason: &'static [u8]) {
        if let Some(sess) = self.sessions.write().await.remove(slug) {
            if let Ok(goaway) = Frame::new(FrameType::GoAway, 0, Bytes::from_static(reason)).encode() {
                let _ = sess.tx.send(goaway).await;
            }
        }
    }

    pub fn with_billing(
        mut self,
        tenant_repo: Arc<dyn TenantRepository>,
        billing: BillingConfig,
    ) -> Self {
        self.tenant_repo = Some(tenant_repo);
        self.billing = billing;
        self
    }

    pub async fn has_tunnel(&self, slug: &str) -> bool {
        self.sessions.read().await.contains_key(slug)
    }
}

/// Pure-Rust RFC 2104 HMAC-SHA256 for Stripe webhook verification (zero extra crates).
fn hmac_sha256_hex(secret: &[u8], data: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut key = [0u8; BLOCK];
    if secret.len() > BLOCK {
        let h = Sha256::digest(secret);
        key[..32].copy_from_slice(&h);
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

fn verify_stripe_signature(secret: &str, sig_header: &str, payload: &[u8]) -> bool {
    let mut ts = None;
    let mut v1 = None;
    for part in sig_header.split(',') {
        if let Some(t) = part.trim().strip_prefix("t=") {
            ts = Some(t);
        } else if let Some(s) = part.trim().strip_prefix("v1=") {
            v1 = Some(s);
        }
    }
    let (Some(ts), Some(v1)) = (ts, v1) else {
        return false;
    };
    // Stripe's default tolerance: reject replays of old events.
    let fresh = ts
        .parse::<u64>()
        .is_ok_and(|t| rackdeck_core::now_unix_secs().abs_diff(t) <= 300);
    if !fresh {
        return false;
    }
    let mut signed = Vec::with_capacity(ts.len() + 1 + payload.len());
    signed.extend_from_slice(ts.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(payload);
    let expected = hmac_sha256_hex(secret.as_bytes(), &signed);
    // Constant-time length & byte check
    expected.len() == v1.len()
        && expected
            .bytes()
            .zip(v1.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

pub fn relay_router(state: RelayState) -> Router {
    Router::new()
        .route("/_rackdeck/tunnel", get(ws_tunnel_upgrade))
        .route("/_rackdeck/stats", get(stats_handler))
        .route("/_rackdeck/stripe/webhook", post(stripe_webhook_handler))
        .route("/connect/{slug}", any(proxy_path_root))
        .route("/connect/{slug}/{*rest}", any(proxy_path_rest))
        .merge(account::account_routes())
        .fallback(any(proxy_host_fallback))
        .with_state(state)
}

fn is_valid_slug(slug: &str) -> bool {
    let b = slug.as_bytes();
    b.len() >= 3
        && b.len() <= 32
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

#[derive(Deserialize)]
struct StripeEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData {
    object: serde_json::Value,
}

async fn stripe_webhook_handler(
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(repo) = state.tenant_repo.clone() else {
        return Json(serde_json::json!({ "received": true, "billing": "disabled" })).into_response();
    };
    // Billing changes who can use a slug, so unsigned events are never trusted.
    let Some(secret) = &state.billing.stripe_webhook_secret else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "set RACKDECK_STRIPE_WEBHOOK_SECRET to accept Stripe events" })),
        )
            .into_response();
    };
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !verify_stripe_signature(secret, sig, &body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid or stale stripe signature" })),
        )
            .into_response();
    }
    let Ok(ev) = serde_json::from_slice::<StripeEvent>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    account::handle_billing_event(&state, &repo, &ev.event_type, &ev.data.object).await;
    Json(serde_json::json!({ "received": true })).into_response()
}

async fn stats_handler(State(state): State<RelayState>) -> Json<RelayStats> {
    let map = state.sessions.read().await;
    let tunnels = map
        .values()
        .map(|s| TunnelStat {
            slug: s.slug.clone(),
            node_id: s.node_id.clone(),
            generation: s.generation,
            requests: s.requests.load(Ordering::Relaxed),
            bytes_in: s.bytes_in.load(Ordering::Relaxed),
            bytes_out: s.bytes_out.load(Ordering::Relaxed),
        })
        .collect::<Vec<_>>();
    Json(RelayStats {
        ok: true,
        active_tunnels: tunnels.len(),
        tunnels,
    })
}

async fn ws_tunnel_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_tunnel_socket(socket, state))
}

async fn handle_tunnel_socket(socket: WebSocket, state: RelayState) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // 1. Expect HELLO
    let Some(Ok(Message::Binary(raw_hello))) = ws_rx.next().await else {
        return;
    };
    let Ok(hello_frame) = Frame::decode(&raw_hello) else {
        return;
    };
    if hello_frame.frame_type != FrameType::Hello {
        return;
    }
    let Ok(hello) = serde_json::from_slice::<HelloPayload>(&hello_frame.payload) else {
        return;
    };

    // 2. Send cryptographic CHALLENGE
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let challenge = ChallengePayload {
        audience: state.audience.clone(),
        nonce_hex: nonce_hex.clone(),
    };
    let Ok(chal_bytes) = Frame::json(FrameType::Challenge, 0, &challenge).and_then(|f| f.encode())
    else {
        return;
    };
    if ws_tx.send(Message::Binary(chal_bytes)).await.is_err() {
        return;
    }

    // 3. Verify Ed25519 AUTH signature
    let Some(Ok(Message::Binary(raw_auth))) = ws_rx.next().await else {
        return;
    };
    let Ok(auth_frame) = Frame::decode(&raw_auth) else {
        return;
    };
    if auth_frame.frame_type != FrameType::Auth {
        return;
    }
    let Ok(auth) = serde_json::from_slice::<AuthPayload>(&auth_frame.payload) else {
        return;
    };
    if !verify_challenge(
        &hello.public_key_hex,
        &state.audience,
        &nonce_hex,
        &hello.node_id,
        &auth.signature_hex,
    ) {
        return;
    }

    // 4. A slug belongs to the first key that used it (or the dashboard linked to it);
    //    hosted relays also need an active subscription.
    let slug = hello.slug.to_ascii_lowercase();
    let pk = hello.public_key_hex.to_ascii_lowercase();
    let tenant = match &state.tenant_repo {
        Some(repo) => repo.get_tenant(&slug).await.ok().flatten(),
        None => None,
    };
    let refuse: Option<&'static [u8]> = match &tenant {
        Some(t) if t.public_key_hex.as_deref().is_some_and(|k| k != pk) => Some(b"slug_taken"),
        Some(t) if state.billing.require_subscription && !t.active => Some(b"subscription_required"),
        None if state.billing.require_subscription => Some(b"subscription_required"),
        _ => None,
    };
    if let Some(reason) = refuse {
        let _ = ws_tx
            .send(Message::Binary(
                Frame::new(FrameType::GoAway, 0, Bytes::from_static(reason))
                    .encode()
                    .unwrap_or_default(),
            ))
            .await;
        return;
    }
    if let Some(repo) = &state.tenant_repo {
        let pin = match tenant {
            Some(t) if t.public_key_hex.is_none() => Some(ConnectTenant { public_key_hex: Some(pk.clone()), ..t }),
            None => Some(ConnectTenant {
                slug: slug.clone(),
                public_key_hex: Some(pk.clone()),
                plan: "self-hosted".into(),
                active: false,
                stripe_customer_id: None,
                account_id: None,
            }),
            Some(_) => None,
        };
        if let Some(t) = pin {
            let _ = repo.upsert_tenant(t).await;
        }
    }

    // 5. Register session with generation fencing
    let (tx, mut rx) = mpsc::channel::<Bytes>(128);
    let session = Arc::new(TunnelSession {
        slug: slug.clone(),
        node_id: hello.node_id.clone(),
        generation: hello.generation,
        tx,
        requests: AtomicU64::new(0),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
    });

    {
        let mut sessions = state.sessions.write().await;
        if let Some(existing) = sessions.get(&slug) {
            if hello.generation < existing.generation {
                return;
            }
        }
        sessions.insert(slug.clone(), Arc::clone(&session));
    }

    let writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if ws_tx.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    let mut assembling: HashMap<u32, (HttpResponseHead, Vec<u8>)> = HashMap::new();
    while let Some(Ok(msg)) = ws_rx.next().await {
        let Message::Binary(bin) = msg else { continue };
        let Ok(frame) = Frame::decode(&bin) else { continue };
        match frame.frame_type {
            FrameType::Headers => {
                if let Ok(head) = serde_json::from_slice::<HttpResponseHead>(&frame.payload) {
                    assembling.insert(frame.stream_id, (head, Vec::new()));
                }
            }
            FrameType::Data => {
                if let Some((_, body)) = assembling.get_mut(&frame.stream_id) {
                    body.extend_from_slice(&frame.payload);
                }
            }
            FrameType::Fin => {
                if let Some((head, body)) = assembling.remove(&frame.stream_id) {
                    if let Some(tx) = state.pending.write().await.remove(&frame.stream_id) {
                        let _ = tx.send(Ok((head, body)));
                    }
                }
            }
            FrameType::Rst => {
                assembling.remove(&frame.stream_id);
                if let Some(tx) = state.pending.write().await.remove(&frame.stream_id) {
                    let _ = tx.send(Err(StatusCode::BAD_GATEWAY));
                }
            }
            _ => {}
        }
    }

    writer.abort();
    let mut sessions = state.sessions.write().await;
    if let Some(curr) = sessions.get(&slug) {
        if Arc::ptr_eq(curr, &session) {
            sessions.remove(&slug);
        }
    }
}

async fn proxy_path_root(
    Path(slug): Path<String>,
    State(state): State<RelayState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let q = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    forward_to_slug(&state, &slug, method, format!("/{q}"), headers, body).await
}

async fn proxy_path_rest(
    Path((slug, rest)): Path<(String, String)>,
    State(state): State<RelayState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let q = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    forward_to_slug(&state, &slug, method, format!("/{rest}{q}"), headers, body).await
}

async fn proxy_host_fallback(
    State(state): State<RelayState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Some(slug) = host.strip_suffix(".rackdev.app") {
        let path_q = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        return forward_to_slug(&state, slug, method, path_q, headers, body).await;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "service": "rackdeck-relay", "status": "ready" })),
    )
        .into_response()
}

async fn forward_to_slug(
    state: &RelayState,
    slug: &str,
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let session = {
        let map = state.sessions.read().await;
        map.get(&slug.to_ascii_lowercase()).cloned()
    };
    let Some(session) = session else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("no active tunnel for {slug}") })),
        )
            .into_response();
    };

    let stream_id = state.next_stream_id.fetch_add(2, Ordering::Relaxed);
    let (res_tx, res_rx) = oneshot::channel();
    state.pending.write().await.insert(stream_id, res_tx);

    let mut hdrs = BTreeMap::new();
    for (k, v) in &headers {
        if let Ok(val) = v.to_str() {
            hdrs.insert(k.as_str().to_string(), val.to_string());
        }
    }
    let req_head = HttpRequestHead {
        method: method.as_str().to_string(),
        path,
        headers: hdrs,
    };

    let Ok(head_bytes) = Frame::json(FrameType::Headers, stream_id, &req_head)
        .and_then(|f| f.encode())
    else {
        state.pending.write().await.remove(&stream_id);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    if session.tx.send(head_bytes).await.is_err() {
        state.pending.write().await.remove(&stream_id);
        return StatusCode::BAD_GATEWAY.into_response();
    }
    for chunk in body.chunks(DEFAULT_DATA_CHUNK) {
        if let Ok(data_bytes) =
            Frame::new(FrameType::Data, stream_id, Bytes::copy_from_slice(chunk)).encode()
        {
            let _ = session.tx.send(data_bytes).await;
        }
    }
    if let Ok(fin_bytes) = Frame::new(FrameType::Fin, stream_id, Bytes::new()).encode() {
        let _ = session.tx.send(fin_bytes).await;
    }

    match tokio::time::timeout(std::time::Duration::from_secs(15), res_rx).await {
        Ok(Ok(Ok((res_head, res_body)))) => {
            let b_in = body.len() as u64;
            let b_out = res_body.len() as u64;
            session.requests.fetch_add(1, Ordering::Relaxed);
            session.bytes_in.fetch_add(b_in, Ordering::Relaxed);
            session.bytes_out.fetch_add(b_out, Ordering::Relaxed);
            if let Some(repo) = &state.usage_repo {
                let _ = repo.add_usage_delta(&session.slug, b_in, b_out).await;
            }
            let status =
                StatusCode::from_u16(res_head.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            for (k, v) in res_head.headers {
                if let (Ok(hn), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(&v),
                ) {
                    builder = builder.header(hn, hv);
                }
            }
            builder
                .body(Body::from(res_body))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Ok(Ok(Err(code))) => code.into_response(),
        _ => {
            state.pending.write().await.remove(&stream_id);
            StatusCode::GATEWAY_TIMEOUT.into_response()
        }
    }
}
