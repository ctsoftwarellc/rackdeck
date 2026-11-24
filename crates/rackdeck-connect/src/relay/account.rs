//! Hosted accounts: email magic-link login, Stripe subscription, and linking a dashboard
//! (controller public key + slug) to an account with a short code, GitHub-CLI style.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rackdeck_core::{now_unix_secs, Account, AccountKey, ConnectTenant, TenantRepository};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use super::{hmac_sha256_hex, is_valid_slug, RelayState};

const LOGIN_TTL: u64 = 15 * 60;
const LINK_TTL: u64 = 10 * 60;
const SESSION_TTL: u64 = 30 * 86_400;
const EMAIL_COOLDOWN: u64 = 60;
const COOKIE: &str = "rd_acct";

#[derive(Clone)]
pub struct AccountConfig {
    /// Where people reach this relay in a browser, e.g. https://rackdev.app (used in emailed links).
    pub public_url: String,
    pub resend_api_key: Option<String>,
    pub mail_from: String,
    pub session_secret: Vec<u8>,
}

impl Default for AccountConfig {
    fn default() -> Self {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill(&mut secret[..]);
        Self {
            public_url: "http://127.0.0.1:7430".into(),
            resend_api_key: None,
            mail_from: "Rackdeck <login@rackdev.app>".into(),
            session_secret: secret,
        }
    }
}

struct LinkRequest {
    public_key_hex: String,
    slug: String,
    poll_hash: String,
    expires: u64,
    linked: Option<Account>,
}

/// Short-lived login and link codes. ponytail: in memory, so a relay restart voids pending ones (users just retry).
#[derive(Default)]
pub struct AccountMem {
    login_tokens: HashMap<String, (String, u64, String)>, // token hash -> (email, expires, next)
    last_email: HashMap<String, u64>,
    links: HashMap<String, LinkRequest>, // user code -> request
}

pub type SharedAccountMem = Arc<Mutex<AccountMem>>;

pub fn account_routes() -> Router<RelayState> {
    Router::new()
        .route("/account", get(account_page))
        .route("/account/login", post(login))
        .route("/account/verify", get(verify))
        .route("/account/logout", post(logout))
        .route("/account/checkout", post(checkout))
        .route("/account/link", get(link_page))
        .route("/account/link/approve", post(link_approve))
        .route("/account/link/start", post(link_start))
        .route("/account/link/poll", post(link_poll))
        .route("/account/controller", get(controller_status))
}

fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill(&mut b[..]);
    hex::encode(b)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Only same-site relative paths, so `next` can't bounce people to another site.
fn safe_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") {
        next.to_string()
    } else {
        "/account".into()
    }
}

fn session_cookie(state: &RelayState, account_id: &str) -> String {
    let exp = now_unix_secs() + SESSION_TTL;
    let payload = format!("{account_id}.{exp}");
    let sig = hmac_sha256_hex(&state.accounts.session_secret, payload.as_bytes());
    let secure = if state.accounts.public_url.starts_with("https://") { "; Secure" } else { "" };
    format!("{COOKIE}={payload}.{sig}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{secure}")
}

async fn current_account(state: &RelayState, headers: &HeaderMap) -> Option<Account> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let val = raw
        .split(';')
        .find_map(|p| p.trim().strip_prefix(&format!("{COOKIE}=")))?;
    let (payload, sig) = val.rsplit_once('.')?;
    let expected = hmac_sha256_hex(&state.accounts.session_secret, payload.as_bytes());
    let same = expected.len() == sig.len()
        && expected.bytes().zip(sig.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
    let (id, exp) = payload.split_once('.')?;
    if !same || exp.parse::<u64>().ok()? < now_unix_secs() {
        return None;
    }
    let repo = state.tenant_repo.as_ref()?;
    repo.find_account(AccountKey::Id, id).await.ok().flatten()
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Rackdeck</title><style>
:root{{color-scheme:light dark;--bg:#fafaf9;--fg:#1c1917;--mut:#78716c;--card:#fff;--line:#e7e5e4;--acc:#1c1917;--accfg:#fff}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0c0a09;--fg:#f5f5f4;--mut:#a8a29e;--card:#1c1917;--line:#292524;--acc:#f5f5f4;--accfg:#0c0a09}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px;box-sizing:border-box}}
main{{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}}
h1{{font-size:20px;margin:0 0 6px}}p{{color:var(--mut);margin:0 0 16px}}
input{{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit;margin-bottom:12px}}
button{{width:100%;padding:10px 12px;border:0;border-radius:8px;background:var(--acc);color:var(--accfg);font:inherit;font-weight:600;cursor:pointer}}
button.ghost{{background:transparent;color:var(--mut);border:1px solid var(--line);margin-top:10px}}
.code{{font:600 28px ui-monospace,monospace;letter-spacing:4px;text-align:center;padding:12px;border:1px dashed var(--line);border-radius:8px;margin-bottom:16px}}
ul{{padding-left:18px;color:var(--mut)}}.ok{{color:#16a34a}}.warn{{color:#d97706}}
</style></head><body><main>{body}</main></body></html>"#
    ))
}

fn login_form(next: &str, note: &str) -> Html<String> {
    page(
        "Log in",
        &format!(
            r#"<h1>Log in to Rackdeck</h1><p>{note}We'll email you a link. No password.</p>
<form method="post" action="/account/login"><input type="hidden" name="next" value="{}">
<label for="email" style="font-size:13px;color:var(--mut)">Email</label>
<input id="email" name="email" type="email" autocomplete="email" required autofocus>
<button type="submit">Email me a link</button></form>"#,
            esc(next)
        ),
    )
}

async fn account_page(State(state): State<RelayState>, headers: HeaderMap) -> Response {
    let Some(acct) = current_account(&state, &headers).await else {
        return login_form("/account", "").into_response();
    };
    let tenants = match &state.tenant_repo {
        Some(repo) => repo.list_tenants().await.unwrap_or_default(),
        None => vec![],
    };
    // ponytail: scans every tenant; index connect_tenants by account_id once there are thousands.
    let mine: Vec<String> = tenants
        .into_iter()
        .filter(|t| t.account_id.as_deref() == Some(acct.id.as_str()))
        .map(|t| format!("<li>{}</li>", esc(&t.slug)))
        .collect();
    let plan = if acct.active {
        r#"<p class="ok">Connect subscription active.</p>"#.to_string()
    } else {
        r#"<p class="warn">No active subscription.</p><form method="post" action="/account/checkout"><button type="submit">Subscribe to Connect</button></form>"#.to_string()
    };
    let linked = if mine.is_empty() {
        "<p>No dashboards linked yet. In your Rackdeck dashboard, open Network and click Sign in.</p>".to_string()
    } else {
        format!("<p style=\"margin:16px 0 4px\">Linked dashboards</p><ul>{}</ul>", mine.join(""))
    };
    page(
        "Account",
        &format!(
            r#"<h1>Your account</h1><p>{}</p>{plan}{linked}
<form method="post" action="/account/logout"><button class="ghost" type="submit">Log out</button></form>"#,
            esc(&acct.email)
        ),
    )
    .into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    #[serde(default)]
    next: String,
}

async fn login(State(state): State<RelayState>, Form(form): Form<LoginForm>) -> Response {
    let email = form.email.trim().to_ascii_lowercase();
    let next = safe_next(&form.next);
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(u, d)| !u.is_empty() && d.contains('.'))
        && !email.contains(char::is_whitespace);
    if !valid {
        return login_form(&next, "That doesn't look like an email. ").into_response();
    }
    let token = random_hex(24);
    {
        let mut mem = state.account_mem.lock().await;
        let now = now_unix_secs();
        if mem.last_email.get(&email).is_some_and(|&t| now - t < EMAIL_COOLDOWN) {
            return page("Check your email", "<h1>Check your email</h1><p>We just sent you a link. Give it a minute before asking for another.</p>").into_response();
        }
        mem.last_email.insert(email.clone(), now);
        mem.login_tokens.retain(|_, (_, exp, _)| *exp > now);
        mem.login_tokens.insert(sha_hex(&token), (email.clone(), now + LOGIN_TTL, next));
    }
    let link = format!("{}/account/verify?token={token}", state.accounts.public_url.trim_end_matches('/'));
    if let Err(e) = send_login_email(&state, &email, &link).await {
        tracing::warn!("login email to {email} failed: {e}");
        return page("Couldn't send", "<h1>Couldn't send the email</h1><p>Try again in a minute.</p>").into_response();
    }
    page(
        "Check your email",
        &format!(
            "<h1>Check your email</h1><p>We sent a login link to <b>{}</b>. It works once and expires in 15 minutes.</p>",
            esc(&email)
        ),
    )
    .into_response()
}

async fn send_login_email(state: &RelayState, to: &str, link: &str) -> Result<(), String> {
    let Some(key) = &state.accounts.resend_api_key else {
        // Dev/self-hosted relay without email: print the link so you can still log in.
        tracing::info!("login link for {to}: {link}");
        return Ok(());
    };
    let body = serde_json::json!({
        "from": state.accounts.mail_from,
        "to": [to],
        "subject": "Your Rackdeck login link",
        "text": format!("Click to log in to Rackdeck:\n\n{link}\n\nThe link works once and expires in 15 minutes. If you didn't ask for it, ignore this email."),
    })
    .to_string();
    curl_json(key, "https://api.resend.com/emails", &["-H", "Content-Type: application/json", "--data-binary", &body])
        .await
        .map(|_| ())
}

/// POST with a bearer secret passed via stdin config (never in argv). Returns the JSON body.
async fn curl_json(secret: &str, url: &str, extra: &[&str]) -> Result<serde_json::Value, String> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("curl")
        .args(["-sS", "-m", "15", "-K", "-", "-X", "POST", url])
        .args(extra)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("couldn't run curl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let cfg = format!("header = \"Authorization: Bearer {secret}\"\n");
        let _ = stdin.write_all(cfg.as_bytes()).await;
    }
    let out = child.wait_with_output().await.map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    if let Some(msg) = v.pointer("/error/message").or_else(|| v.get("message")).and_then(|m| m.as_str()) {
        if v.get("error").is_some() || v.get("statusCode").is_some() {
            return Err(msg.to_string());
        }
    }
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(v)
}

#[derive(Deserialize)]
struct VerifyQuery {
    token: String,
}

async fn verify(State(state): State<RelayState>, Query(q): Query<VerifyQuery>) -> Response {
    let found = {
        let mut mem = state.account_mem.lock().await;
        mem.login_tokens.remove(&sha_hex(&q.token))
    };
    let Some((email, _, next)) = found.filter(|(_, exp, _)| *exp >= now_unix_secs()) else {
        return login_form("/account", "That link expired or was already used. ").into_response();
    };
    let Some(repo) = &state.tenant_repo else {
        return (StatusCode::SERVICE_UNAVAILABLE, "accounts need a database").into_response();
    };
    let acct = match repo.find_account(AccountKey::Email, &email).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            let a = Account {
                id: format!("acct_{}", random_hex(10)),
                email: email.clone(),
                stripe_customer_id: None,
                active: false,
                created_at: now_unix_secs(),
            };
            if let Err(e) = repo.upsert_account(a.clone()).await {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
            tracing::info!("new account {} ({email})", a.id);
            a
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    (
        [(header::SET_COOKIE, session_cookie(&state, &acct.id))],
        Redirect::to(&next),
    )
        .into_response()
}

async fn logout() -> Response {
    (
        [(header::SET_COOKIE, format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"))],
        Redirect::to("/account"),
    )
        .into_response()
}

async fn checkout(State(state): State<RelayState>, headers: HeaderMap) -> Response {
    let Some(acct) = current_account(&state, &headers).await else {
        return Redirect::to("/account").into_response();
    };
    let (Some(key), Some(price)) = (&state.billing.stripe_secret_key, &state.billing.stripe_price_id) else {
        return page("Not available", "<h1>Subscriptions aren't open yet</h1><p>This relay isn't set up for billing.</p>").into_response();
    };
    let base = state.accounts.public_url.trim_end_matches('/');
    let mut form: Vec<String> = vec![
        "mode=subscription".into(),
        format!("line_items[0][price]={price}"),
        "line_items[0][quantity]=1".into(),
        format!("client_reference_id={}", acct.id),
        format!("metadata[account_id]={}", acct.id),
        format!("subscription_data[metadata][account_id]={}", acct.id),
        format!("success_url={base}/account"),
        format!("cancel_url={base}/account"),
    ];
    match &acct.stripe_customer_id {
        Some(c) => form.push(format!("customer={c}")),
        None => form.push(format!("customer_email={}", acct.email)),
    }
    let args: Vec<String> = form.into_iter().flat_map(|f| ["--data-urlencode".to_string(), f]).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match curl_json(key, "https://api.stripe.com/v1/checkout/sessions", &args).await {
        Ok(v) => match v.get("url").and_then(|u| u.as_str()) {
            Some(url) => Redirect::to(url).into_response(),
            None => page("Checkout failed", "<h1>Checkout failed</h1><p>Stripe didn't return a checkout page. Try again.</p>").into_response(),
        },
        Err(e) => {
            tracing::warn!("stripe checkout for {} failed: {e}", acct.id);
            page("Checkout failed", "<h1>Checkout failed</h1><p>Try again in a minute.</p>").into_response()
        }
    }
}

/// Stripe webhook events for account subscriptions.
pub(super) async fn handle_billing_event(state: &RelayState, repo: &Arc<dyn TenantRepository>, kind: &str, obj: &serde_json::Value) {
    let customer = obj.get("customer").and_then(|v| v.as_str()).map(str::to_string);
    let acct = match obj.pointer("/metadata/account_id").and_then(|v| v.as_str()) {
        Some(id) => repo.find_account(AccountKey::Id, id).await.ok().flatten(),
        None => match &customer {
            Some(c) => repo.find_account(AccountKey::StripeCustomer, c).await.ok().flatten(),
            None => None,
        },
    };
    let Some(mut acct) = acct else { return };
    let active = match kind {
        "checkout.session.completed" | "invoice.paid" => true,
        "customer.subscription.deleted" | "invoice.payment_failed" => false,
        _ => return,
    };
    acct.active = active;
    if customer.is_some() {
        acct.stripe_customer_id = customer.clone();
    }
    let _ = repo.upsert_account(acct.clone()).await;
    for mut t in repo.list_tenants().await.unwrap_or_default() {
        if t.account_id.as_deref() != Some(acct.id.as_str()) {
            continue;
        }
        t.active = active;
        t.stripe_customer_id = acct.stripe_customer_id.clone();
        let slug = t.slug.clone();
        let _ = repo.upsert_tenant(t).await;
        if !active {
            state.drop_tunnel(&slug, b"subscription_cancelled").await;
        }
    }
    tracing::info!("account {} subscription active={active} ({kind})", acct.id);
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkStartBody {
    public_key_hex: String,
    slug: String,
}

/// Called by a dashboard: returns a code for the person to approve while logged in.
async fn link_start(State(state): State<RelayState>, Json(body): Json<LinkStartBody>) -> Response {
    let slug = body.slug.trim().to_ascii_lowercase();
    let pk = body.public_key_hex.trim().to_ascii_lowercase();
    if !is_valid_slug(&slug) || pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "need a valid slug and publicKeyHex" }))).into_response();
    }
    // Unambiguous characters only, shown as XXXX-XXXX.
    const ALPHA: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";
    let raw: String = {
        let mut rng = rand::thread_rng(); // not Send: keep it out of the awaits below
        (0..8).map(|_| ALPHA[rng.gen_range(0..ALPHA.len())] as char).collect()
    };
    let user_code = format!("{}-{}", &raw[..4], &raw[4..]);
    let poll_token = random_hex(24);
    let now = now_unix_secs();
    {
        let mut mem = state.account_mem.lock().await;
        mem.links.retain(|_, l| l.expires > now);
        mem.links.insert(
            user_code.clone(),
            LinkRequest { public_key_hex: pk, slug, poll_hash: sha_hex(&poll_token), expires: now + LINK_TTL, linked: None },
        );
    }
    let url = format!("{}/account/link?code={user_code}", state.accounts.public_url.trim_end_matches('/'));
    Json(serde_json::json!({ "userCode": user_code, "pollToken": poll_token, "url": url, "expiresIn": LINK_TTL })).into_response()
}

#[derive(Deserialize)]
struct CodeQuery {
    #[serde(default)]
    code: String,
}

async fn link_page(State(state): State<RelayState>, headers: HeaderMap, Query(q): Query<CodeQuery>) -> Response {
    let code = q.code.trim().to_ascii_uppercase();
    let Some(acct) = current_account(&state, &headers).await else {
        let next = format!("/account/link?code={}", esc(&code));
        return login_form(&next, "Log in to link your dashboard. ").into_response();
    };
    let slug = {
        let mem = state.account_mem.lock().await;
        mem.links.get(&code).filter(|l| l.expires > now_unix_secs() && l.linked.is_none()).map(|l| l.slug.clone())
    };
    let Some(slug) = slug else {
        return page("Link expired", "<h1>That code expired</h1><p>Click Sign in again in your dashboard to get a new one.</p>").into_response();
    };
    page(
        "Link dashboard",
        &format!(
            r#"<h1>Link this dashboard?</h1><p>Check the code matches the one in your dashboard. It'll use <b>{}</b> under your account ({}).</p>
<div class="code">{}</div>
<form method="post" action="/account/link/approve"><input type="hidden" name="code" value="{}"><button type="submit">Link dashboard</button></form>"#,
            esc(&slug),
            esc(&acct.email),
            esc(&code),
            esc(&code)
        ),
    )
    .into_response()
}

async fn link_approve(State(state): State<RelayState>, headers: HeaderMap, Form(q): Form<CodeQuery>) -> Response {
    let Some(acct) = current_account(&state, &headers).await else {
        return Redirect::to("/account").into_response();
    };
    let Some(repo) = state.tenant_repo.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "accounts need a database").into_response();
    };
    let code = q.code.trim().to_ascii_uppercase();
    let req = {
        let mem = state.account_mem.lock().await;
        mem.links
            .get(&code)
            .filter(|l| l.expires > now_unix_secs() && l.linked.is_none())
            .map(|l| (l.slug.clone(), l.public_key_hex.clone()))
    };
    let Some((slug, pk)) = req else {
        return page("Link expired", "<h1>That code expired</h1><p>Click Sign in again in your dashboard.</p>").into_response();
    };
    // A slug belongs to whoever claimed it first: same key, or same account.
    if let Ok(Some(t)) = repo.get_tenant(&slug).await {
        let other_account = t.account_id.as_deref().is_some_and(|a| a != acct.id);
        let other_key = t.public_key_hex.as_deref().is_some_and(|k| k != pk);
        if other_account || (other_key && t.account_id.as_deref() != Some(acct.id.as_str())) {
            return page("Name taken", &format!("<h1>{} is taken</h1><p>Pick a different name in your dashboard and sign in again.</p>", esc(&slug))).into_response();
        }
    }
    let tenant = ConnectTenant {
        slug: slug.clone(),
        public_key_hex: Some(pk),
        plan: "connect".into(),
        active: acct.active,
        stripe_customer_id: acct.stripe_customer_id.clone(),
        account_id: Some(acct.id.clone()),
    };
    if let Err(e) = repo.upsert_tenant(tenant).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Some(l) = state.account_mem.lock().await.links.get_mut(&code) {
        l.linked = Some(acct.clone());
    }
    tracing::info!("account {} linked {slug}", acct.id);
    page("Linked", "<h1>Dashboard linked</h1><p>You can close this tab and go back to your dashboard.</p>").into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PollBody {
    poll_token: String,
}

async fn link_poll(State(state): State<RelayState>, Json(body): Json<PollBody>) -> Response {
    let hash = sha_hex(&body.poll_token);
    let mut mem = state.account_mem.lock().await;
    let Some((code, req)) = mem.links.iter().find(|(_, l)| l.poll_hash == hash) else {
        return Json(serde_json::json!({ "status": "expired" })).into_response();
    };
    if req.expires <= now_unix_secs() {
        let code = code.clone();
        mem.links.remove(&code);
        return Json(serde_json::json!({ "status": "expired" })).into_response();
    }
    match &req.linked {
        None => Json(serde_json::json!({ "status": "pending" })).into_response(),
        Some(acct) => {
            let out = serde_json::json!({ "status": "linked", "email": acct.email, "active": acct.active, "slug": req.slug });
            let code = code.clone();
            mem.links.remove(&code);
            Json(out).into_response()
        }
    }
}

#[derive(Deserialize)]
struct PkQuery {
    pk: String,
}

/// Lets a dashboard show whether it's linked and paid for, without exposing who owns it.
async fn controller_status(State(state): State<RelayState>, Query(q): Query<PkQuery>) -> Response {
    let pk = q.pk.trim().to_ascii_lowercase();
    let tenants = match &state.tenant_repo {
        Some(repo) => repo.list_tenants().await.unwrap_or_default(),
        None => vec![],
    };
    let mine: Vec<_> = tenants
        .iter()
        .filter(|t| t.account_id.is_some() && t.public_key_hex.as_deref() == Some(pk.as_str()))
        .collect();
    Json(serde_json::json!({
        "linked": !mine.is_empty(),
        "active": mine.iter().any(|t| t.active),
        "slugs": mine.iter().map(|t| t.slug.clone()).collect::<Vec<_>>(),
        "accountUrl": format!("{}/account", state.accounts.public_url.trim_end_matches('/')),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_stays_on_site() {
        assert_eq!(safe_next("/account/link?code=AB"), "/account/link?code=AB");
        assert_eq!(safe_next("//evil.com"), "/account");
        assert_eq!(safe_next("https://evil.com"), "/account");
    }
}
