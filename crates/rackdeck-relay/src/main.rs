use std::net::SocketAddr;

use rackdeck_connect::relay::{relay_router, AccountConfig, BillingConfig, RelayState};
use rackdeck_store::SqliteStore;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let port: u16 = std::env::var("RACKDECK_RELAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7430);
    let audience =
        std::env::var("RACKDECK_RELAY_AUDIENCE").unwrap_or_else(|_| "connect.rackdeck.dev".into());
    let db_path = std::env::var("RACKDECK_RELAY_DB").unwrap_or_else(|_| "rackdeck-relay.db".into());
    let require_sub = std::env::var("RACKDECK_RELAY_REQUIRE_SUBSCRIPTION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let billing = BillingConfig {
        require_subscription: require_sub,
        stripe_webhook_secret: std::env::var("RACKDECK_STRIPE_WEBHOOK_SECRET").ok(),
        stripe_secret_key: std::env::var("STRIPE_SECRET_KEY").ok(),
        stripe_price_id: std::env::var("RACKDECK_STRIPE_PRICE_ID").ok(),
        success_url: std::env::var("RACKDECK_CHECKOUT_SUCCESS_URL")
            .unwrap_or_else(|_| "https://rackdeck.dev/connect/success".into()),
        cancel_url: std::env::var("RACKDECK_CHECKOUT_CANCEL_URL")
            .unwrap_or_else(|_| "https://rackdeck.dev/connect/cancel".into()),
    };

    let store = SqliteStore::open(&db_path)?;
    let mut accounts = AccountConfig {
        public_url: std::env::var("RACKDECK_PUBLIC_URL").unwrap_or_else(|_| format!("http://127.0.0.1:{port}")),
        resend_api_key: std::env::var("RESEND_API_KEY").ok().filter(|s| !s.is_empty()),
        mail_from: std::env::var("RACKDECK_MAIL_FROM").unwrap_or_else(|_| "Rackdeck <login@rackdev.app>".into()),
        ..AccountConfig::default()
    };
    match std::env::var("RACKDECK_SESSION_SECRET") {
        Ok(s) if s.len() >= 32 => accounts.session_secret = s.into_bytes(),
        _ => tracing::warn!("RACKDECK_SESSION_SECRET unset (or under 32 chars): logins reset when the relay restarts"),
    }
    if accounts.resend_api_key.is_none() {
        tracing::warn!("RESEND_API_KEY unset: login links are printed to this log instead of emailed");
    }

    let state = RelayState::new(audience, Some(store.clone()))
        .with_billing(store, billing)
        .with_accounts(accounts);
    let app = relay_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("rackdeck-relay listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}
