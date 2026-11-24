use std::net::SocketAddr;

use rackdeck_connect::relay::{relay_router, BillingConfig, RelayState};
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
    let state = RelayState::new(audience, Some(store.clone())).with_billing(store, billing);
    let app = relay_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("rackdeck-relay listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}
