use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    AppAction, AuditEvent, AuditRepository, Capability, CoreResult, DeploySpec, FleetRepository,
    ManagedApp, Node, NodeOps, Principal, RemoteDispatch,
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
    /// Id of the machine this controller runs on; every other node id is routed to `remote`.
    pub local_node_id: String,
    pub remote: Arc<dyn RemoteDispatch>,
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

        let res = if node_id == self.local_node_id {
            self.local_node.app_action(app_id, action).await
        } else {
            self.remote.app_action(node_id, app_id, action).await
        };
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

        // A host folder mount reaches the machine's files, so only the owner may use one, not a token.
        if !matches!(principal, Principal::Owner { .. }) {
            if let Err(e) = assistant_volumes_ok(&spec) {
                return Err(crate::CoreError::Forbidden(e));
            }
        }
        let res = if node_id == self.local_node_id {
            self.local_node.deploy_app(spec).await
        } else {
            self.remote.deploy_app(node_id, spec).await
        };
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
        let lines = lines.min(500);
        if node_id == self.local_node_id {
            self.local_node.tail_logs(app_id, lines).await
        } else {
            self.remote.tail_logs(node_id, app_id, lines).await
        }
    }
}

/// Assistants (tokens) only get storage named after the app they install, so they can't attach
/// another app's data (say, the password vault's). Host folders are the owner's call.
fn assistant_volumes_ok(spec: &DeploySpec) -> Result<(), String> {
    for v in &spec.volumes {
        let src = v.split(':').next().unwrap_or_default();
        if src.starts_with('/') {
            return Err("only the owner can give an app a folder from the machine".into());
        }
        if src != spec.name && !src.starts_with(&format!("{}-", spec.name)) {
            return Err(format!(
                "storage `{src}` must be named after the app: `{0}` or `{0}-something`",
                spec.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod assistant_rules_tests {
    use super::*;

    #[test]
    fn volumes_must_belong_to_the_app() {
        let mut spec = DeploySpec {
            name: "open-webui".into(),
            image: "x".into(),
            host_port: None,
            container_port: None,
            env: Default::default(),
            ports: vec![],
            volumes: vec![],
            gpu: false,
        };
        spec.volumes = vec!["open-webui:/data".into(), "open-webui-ollama:/root/.ollama".into()];
        assert!(assistant_volumes_ok(&spec).is_ok());
        for bad in ["vaultwarden-data:/data", "/etc:/x", "open-webuix:/data"] {
            spec.volumes = vec![bad.into()];
            assert!(assistant_volumes_ok(&spec).is_err(), "{bad}");
        }
    }
}
