use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    AppAction, AuditEvent, AuditRepository, Capability, CoreResult, DeploySpec, FleetRepository,
    ManagedApp, Node, NodeOps, Principal,
};

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct FleetService {
    pub fleet: Arc<dyn FleetRepository>,
    pub audit: Arc<dyn AuditRepository>,
    pub local_node: Arc<dyn NodeOps>,
}

impl FleetService {
    pub async fn list_nodes(&self, principal: &Principal) -> CoreResult<Vec<Node>> {
        principal.authorize(Capability::ReadTelemetry, None)?;
        self.fleet.list_nodes().await
    }

    pub async fn list_apps(
        &self,
        principal: &Principal,
        node_id: &str,
    ) -> CoreResult<Vec<ManagedApp>> {
        principal.authorize(Capability::ReadTelemetry, Some(node_id))?;
        self.local_node.list_apps().await
    }

    pub async fn execute_app_action(
        &self,
        principal: &Principal,
        node_id: &str,
        app_id: &str,
        action: AppAction,
    ) -> CoreResult<()> {
        let action_label = format!("{action:?}").to_lowercase();
        let target = format!("{node_id}/{app_id}");
        if let Err(err) = principal.authorize(Capability::ControlApp, Some(node_id)) {
            let _ = self
                .audit
                .append_audit(AuditEvent {
                    id: format!("aud-{}", now_unix_secs()),
                    ts: now_unix_secs(),
                    actor: principal.actor_name().to_string(),
                    action: action_label,
                    target,
                    ok: false,
                    reason: Some(err.to_string()),
                })
                .await;
            return Err(err);
        }

        let res = self.local_node.app_action(app_id, action).await;
        let _ = self
            .audit
            .append_audit(AuditEvent {
                id: format!("aud-{}", now_unix_secs()),
                ts: now_unix_secs(),
                actor: principal.actor_name().to_string(),
                action: action_label,
                target,
                ok: res.is_ok(),
                reason: res.as_ref().err().map(|e| e.to_string()),
            })
            .await;
        res
    }

    pub async fn deploy_app(
        &self,
        principal: &Principal,
        node_id: &str,
        spec: DeploySpec,
    ) -> CoreResult<ManagedApp> {
        let target = format!("{node_id}/{}", spec.name);
        if let Err(err) = principal.authorize(Capability::ControlApp, Some(node_id)) {
            let _ = self
                .audit
                .append_audit(AuditEvent {
                    id: format!("aud-{}", now_unix_secs()),
                    ts: now_unix_secs(),
                    actor: principal.actor_name().to_string(),
                    action: "deploy app".into(),
                    target,
                    ok: false,
                    reason: Some(err.to_string()),
                })
                .await;
            return Err(err);
        }

        let res = self.local_node.deploy_app(spec).await;
        let _ = self
            .audit
            .append_audit(AuditEvent {
                id: format!("aud-{}", now_unix_secs()),
                ts: now_unix_secs(),
                actor: principal.actor_name().to_string(),
                action: "deploy app".into(),
                target,
                ok: res.is_ok(),
                reason: res.as_ref().err().map(|e| e.to_string()),
            })
            .await;
        res
    }

    pub async fn tail_logs(
        &self,
        principal: &Principal,
        node_id: &str,
        app_id: &str,
        lines: usize,
    ) -> CoreResult<Vec<String>> {
        principal.authorize(Capability::ReadLogs, Some(node_id))?;
        self.local_node.tail_logs(app_id, lines.min(500)).await
    }
}
