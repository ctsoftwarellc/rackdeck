use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Vps,
    Gpu,
    Mac,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Online,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DockerState {
    Running,
    Stopped,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvidiaGpuInfo {
    pub idx: u32,
    pub name: String,
    pub vram_total_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Accelerator {
    None,
    #[serde(rename_all = "camelCase")]
    Nvidia {
        gpus: Vec<NvidiaGpuInfo>,
        driver: Option<String>,
        driver_loaded: bool,
    },
    #[serde(rename_all = "camelCase")]
    Apple {
        chip: String,
        unified_total_mb: u64,
        ane: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardwareSpec {
    pub cpu_cores: u32,
    pub ram_total_mb: u64,
    pub disk_total_gb: u64,
    pub accel: Accelerator,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetrySample {
    pub t: u64,
    pub cpu: f32,
    pub mem_mb: u64,
    pub disk_gb: u64,
    pub net_rx_bps: u64,
    pub net_tx_bps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vram_mb: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temp_c: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    pub id: String,
    pub name: String,
    pub kind: NodeKind,
    pub os: String,
    pub kernel: Option<String>,
    pub status: NodeStatus,
    pub last_seen: u64,
    pub uptime_secs: u64,
    pub hw: HardwareSpec,
    pub docker: DockerState,
    pub version: String,
    pub lan_ip: Option<String>,
    pub tailscale_ip: Option<String>,
    pub connect_slug: Option<String>,
    pub connect_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppType {
    Docker,
    Compose,
    Ai,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppState {
    Running,
    Stopped,
    Starting,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppAction {
    Start,
    Stop,
    Restart,
    Remove { delete_data: bool },
    Update,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppActionResult {
    Done,
    Updated,
    AlreadyUpToDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsState {
    Valid,
    Issuing,
    DnsMismatch,
    Failed,
    TargetOffline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDomain {
    pub host: String,
    pub tls: TlsState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUsage {
    pub cpu: f32,
    pub mem_mb: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vram_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tps: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedApp {
    pub id: String,
    pub node_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub app_type: AppType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub state: AppState,
    /// Absent on older agents and on services other than containers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can_update: Option<bool>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub update_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<AppStorage>,
    pub ports: Vec<u16>,
    pub domains: Vec<AppDomain>,
    pub usage: AppUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStorage {
    pub named_volumes: Vec<String>,
    pub has_anonymous_volumes: bool,
    pub has_folders: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredPeer {
    pub id: String,
    pub hostname: String,
    pub ip: String,
    pub source: String, // "mdns" | "tailnet"
    pub os: String,
    pub online: bool,
    pub rackdeck_version: Option<String>,
    pub in_fleet: bool,
}

/// An environment variable pushed to chosen machines. `sealed` is the value encrypted at rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    pub name: String,
    pub sealed: String,
    pub node_ids: Vec<String>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRoute {
    pub id: String,
    pub host: String,
    pub node_id: String,
    pub target_app: String,
    pub target_port: u16,
    pub tls: TlsState,
    pub require_auth: bool,
    pub bytes_24h: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    Read,
    Deploy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenRecord {
    pub id: String,
    pub name: String,
    pub client: String,
    pub scope: TokenScope,
    pub node_ids: Vec<String>, // empty = all machines
    pub created_at: u64,
    pub last_used_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub ts: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingInvitation {
    pub id: String,
    pub node_id: String,
    pub code_6: String,
    pub fingerprint: String,
    pub qr_uri: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploySpec {
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub host_port: Option<u16>,
    #[serde(default)]
    pub container_port: Option<u16>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// More port maps, "host:container" or "host:container/udp".
    #[serde(default)]
    pub ports: Vec<String>,
    /// "volume-name:/path/in/container", or "/host/folder:/path" (owner only).
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Give the container the machine's NVIDIA GPUs.
    #[serde(default)]
    pub gpu: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectTenant {
    pub slug: String,
    pub public_key_hex: Option<String>,
    pub plan: String,
    pub active: bool,
    pub stripe_customer_id: Option<String>,
    /// Rackdeck account that linked this controller (hosted Connect).
    #[serde(default)]
    pub account_id: Option<String>,
}

/// A person on the hosted service, identified by email (magic-link login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub email: String,
    pub stripe_customer_id: Option<String>,
    /// Paid Connect subscription is current.
    pub active: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKey {
    Id,
    Email,
    StripeCustomer,
}
