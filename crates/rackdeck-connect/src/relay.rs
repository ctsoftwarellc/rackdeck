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
        .route("/_rackdeck/checkout", post(create_checkout_session))
        .route("/_rackdeck/stripe/webhook", post(stripe_webhook_handler))
        .route("/connect/{slug}", any(proxy_path_root))
        .route("/connect/{slug}/{*rest}", any(proxy_path_rest))
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
#[serde(rename_all = "camelCase")]
struct CheckoutBody {
    slug: String,
    public_key_hex: String,
}

async fn create_checkout_session(
    State(state): State<RelayState>,
    Json(body): Json<CheckoutBody>,
) -> Response {
    let slug = body.slug.trim().to_ascii_lowercase();
    if !is_valid_slug(&slug) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "slug must be 3-32 lowercase alphanumeric/hyphen chars" })),
        )
            .into_response();
    }
    let pk = body.public_key_hex.trim().to_ascii_lowercase();
    if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid publicKeyHex" })),
        )
            .into_response();
    }

    // 1. Check slug availability BEFORE creating a Stripe Checkout Session
    if let Some(repo) = &state.tenant_repo {
        if let Ok(Some(existing)) = repo.get_tenant(&slug).await {
            if existing.active
                && existing.public_key_hex.as_deref().is_some_and(|k| k != pk)
            {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({ "error": format!("slug '{slug}' is already taken") })),
                )
                    .into_response();
            }
        }
    }

    let (Some(secret_key), Some(price_id)) = (
        &state.billing.stripe_secret_key,
        &state.billing.stripe_price_id,
    ) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Stripe checkout not configured on this relay (set STRIPE_SECRET_KEY and RACKDECK_STRIPE_PRICE_ID)" })),
        )
            .into_response();
    };

    // 2. Call Stripe Checkout Sessions API via curl -K - (secret passed via stdin, never in argv)
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let mut child = match Command::new("curl")
        .args([
            "-sS",
            "-K",
            "-",
            "-X",
            "POST",
            "https://api.stripe.com/v1/checkout/sessions",
            "--data-urlencode",
            "mode=subscription",
            "--data-urlencode",
            &format!("line_items[0][price]={price_id}"),
            "--data-urlencode",
            "line_items[0][quantity]=1",
            "--data-urlencode",
            &format!("client_reference_id={slug}"),
            "--data-urlencode",
            &format!("metadata[slug]={slug}"),
            "--data-urlencode",
            &format!("metadata[public_key_hex]={pk}"),
            "--data-urlencode",
            "metadata[plan]=connect",
            "--data-urlencode",
            &format!("success_url={}", state.billing.success_url),
            "--data-urlencode",
            &format!("cancel_url={}", state.billing.cancel_url),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("failed to invoke curl: {e}") })),
            )
                .into_response();
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let cfg = format!("header = \"Authorization: Bearer {secret_key}\"\n");
        let _ = stdin.write_all(cfg.as_bytes()).await;
    }

    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(12),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(o)) => o,
        _ => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({ "error": "Stripe API timed out" })),
            )
                .into_response();
        }
    };

    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_default();
    if let Some(url) = parsed.get("url").and_then(|v| v.as_str()) {
        return Json(serde_json::json!({ "url": url, "slug": slug })).into_response();
    }
    let stripe_err = parsed
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or("Stripe checkout session creation failed");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": stripe_err })),
    )
        .into_response()
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
    if let Some(secret) = &state.billing.stripe_webhook_secret {
        let sig = headers
            .get("stripe-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !verify_stripe_signature(secret, sig, &body) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid stripe signature" })),
            )
                .into_response();
        }
    }
    let Ok(ev) = serde_json::from_slice::<StripeEvent>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(repo) = &state.tenant_repo else {
        return Json(serde_json::json!({ "received": true, "billing": "disabled" })).into_response();
    };

    let obj = &ev.data.object;
    match ev.event_type.as_str() {
        "checkout.session.completed" => {
            let slug = obj
                .pointer("/metadata/slug")
                .or_else(|| obj.pointer("/client_reference_id"))
                .or_else(|| obj.pointer("/custom_fields/0/text/value"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let public_key_hex = obj
                .pointer("/metadata/public_key_hex")
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_lowercase());
            let customer_id = obj
                .get("customer")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let plan = obj
                .pointer("/metadata/plan")
                .and_then(|v| v.as_str())
                .unwrap_or("connect")
                .to_string();
            if is_valid_slug(&slug.to_ascii_lowercase()) {
                let _ = repo
                    .upsert_tenant(ConnectTenant {
                        slug: slug.to_ascii_lowercase(),
                        public_key_hex,
                        plan,
                        active: true,
                        stripe_customer_id: customer_id,
                    })
                    .await;
            }
        }
        "customer.subscription.deleted" | "invoice.payment_failed" => {
            if let Some(customer_id) = obj.get("customer").and_then(|v| v.as_str()) {
                let _ = repo.set_tenant_active_by_customer(customer_id, false).await;
            }
            if let Some(slug) = obj.pointer("/metadata/slug").and_then(|v| v.as_str()) {
                if let Some(sess) = state.sessions.write().await.remove(&slug.to_ascii_lowercase()) {
                    if let Ok(goaway) = Frame::new(
                        FrameType::GoAway,
                        0,
                        Bytes::from_static(b"subscription_cancelled"),
                    )
                    .encode()
                    {
                        let _ = sess.tx.send(goaway).await;
                    }
                }
            }
        }
        _ => {}
    }

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

    // 4. Enforce paid Connect subscription + pin Ed25519 key (TOFU if unbound)
    let slug = hello.slug.to_ascii_lowercase();
    if state.billing.require_subscription {
        let allowed = match &state.tenant_repo {
            Some(repo) => match repo.get_tenant(&slug).await {
                Ok(Some(mut t)) if t.active => match t.public_key_hex.as_deref() {
                    Some(pk) => pk == hello.public_key_hex,
                    None => {
                        t.public_key_hex = Some(hello.public_key_hex.clone());
                        let _ = repo.upsert_tenant(t).await;
                        true
                    }
                },
                _ => false,
            },
            None => false,
        };
        if !allowed {
            let _ = ws_tx
                .send(Message::Binary(
                    Frame::new(FrameType::GoAway, 0, Bytes::from_static(b"subscription_required"))
                        .encode()
                        .unwrap_or_default(),
                ))
                .await;
            return;
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
