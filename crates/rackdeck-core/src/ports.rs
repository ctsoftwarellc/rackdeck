use async_trait::async_trait;

use crate::{
    AccessTokenRecord, AppAction, AuditEvent, ConnectRoute, ConnectTenant, CoreResult, DeploySpec,
    DiscoveredPeer, ManagedApp, Node, TelemetrySample, TokenScope,
};

#[async_trait]
pub trait NodeOps: Send + Sync {
    async fn sample(&self) -> CoreResult<TelemetrySample>;
    async fn inspect_node(&self) -> CoreResult<Node>;
    async fn list_apps(&self) -> CoreResult<Vec<ManagedApp>>;
    async fn app_action(&self, app_id: &str, action: AppAction) -> CoreResult<()>;
    async fn deploy_app(&self, spec: DeploySpec) -> CoreResult<ManagedApp>;
    async fn tail_logs(&self, app_id: &str, lines: usize) -> CoreResult<Vec<String>>;
}

#[async_trait]
pub trait FleetRepository: Send + Sync {
    async fn upsert_node(&self, node: Node) -> CoreResult<()>;
    async fn list_nodes(&self) -> CoreResult<Vec<Node>>;
    async fn get_node(&self, id: &str) -> CoreResult<Option<Node>>;
    async fn set_connect_state(
        &self,
        node_id: &str,
        enabled: bool,
        slug: Option<String>,
    ) -> CoreResult<Node>;
}

#[async_trait]
pub trait RouteRepository: Send + Sync {
    async fn list_routes(&self) -> CoreResult<Vec<ConnectRoute>>;
    async fn upsert_route(&self, route: ConnectRoute) -> CoreResult<()>;
    async fn delete_route(&self, id: &str) -> CoreResult<bool>;
}

#[async_trait]
pub trait TokenRepository: Send + Sync {
    async fn create_token(
        &self,
        name: String,
        client: String,
        scope: TokenScope,
        node_ids: Vec<String>,
        token_hash: String,
        expires_at: Option<u64>,
    ) -> CoreResult<AccessTokenRecord>;
    async fn list_tokens(&self) -> CoreResult<Vec<AccessTokenRecord>>;
    async fn find_by_hash(&self, token_hash: &str) -> CoreResult<Option<AccessTokenRecord>>;
    async fn revoke_token(&self, id: &str) -> CoreResult<bool>;
    async fn touch_token(&self, id: &str, ts: u64) -> CoreResult<()>;
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn append_audit(&self, event: AuditEvent) -> CoreResult<()>;
    async fn list_audit(&self, limit: usize) -> CoreResult<Vec<AuditEvent>>;
}

#[async_trait]
pub trait UsageRepository: Send + Sync {
    async fn add_usage_delta(&self, tenant: &str, bytes_in: u64, bytes_out: u64) -> CoreResult<()>;
    async fn get_usage(&self, tenant: &str) -> CoreResult<(u64, u64)>;
}

#[async_trait]
pub trait TenantRepository: Send + Sync {
    async fn upsert_tenant(&self, tenant: ConnectTenant) -> CoreResult<()>;
    async fn get_tenant(&self, slug: &str) -> CoreResult<Option<ConnectTenant>>;
    async fn set_tenant_active_by_customer(&self, customer_id: &str, active: bool) -> CoreResult<()>;
}

#[async_trait]
pub trait DiscoveryPort: Send + Sync {
    async fn scan_peers(&self, rackdeck_port: u16, known_ips: &[String])
        -> CoreResult<Vec<DiscoveredPeer>>;
}
