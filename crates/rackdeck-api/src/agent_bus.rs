use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use rackdeck_core::{
    now_unix_secs, AppAction, AppActionResult, CoreError, CoreResult, DeploySpec, ManagedApp,
    RemoteDispatch,
};
use rackdeck_protocol::{AgentCommand, AgentCommandResult, AgentOp, AgentOutput};
use tokio::sync::{oneshot, Mutex};

/// Agents poll every 2s; anything quieter than this is treated as offline.
const OFFLINE_AFTER_SECS: u64 = 15;
const IMAGE_OPERATION_TIMEOUT: Duration = Duration::from_secs(990);

#[derive(Clone, Copy)]
struct Checkin {
    at: u64,
    app_management: bool,
}

/// Queues commands for remote agents and hands them out on check-in.
/// ponytail: in-memory only, so commands in flight are lost on controller restart (callers just get a timeout).
#[derive(Default)]
pub struct AgentBus {
    queued: Mutex<HashMap<String, Vec<AgentCommand>>>,
    waiting: Mutex<HashMap<String, oneshot::Sender<Result<AgentOutput, String>>>>,
    last_seen: Mutex<HashMap<String, Checkin>>,
}

impl AgentBus {
    /// Called on every authenticated check-in: deliver finished results, return queued work.
    pub async fn checkin(
        &self,
        node_id: &str,
        results: Vec<AgentCommandResult>,
        app_management: bool,
    ) -> Vec<AgentCommand> {
        self.last_seen
            .lock()
            .await
            .insert(node_id.to_string(), Checkin { at: now_unix_secs(), app_management });
        {
            let mut waiting = self.waiting.lock().await;
            for r in results {
                if let Some(tx) = waiting.remove(&r.id) {
                    let _ = tx.send(r.result);
                }
            }
        }
        self.queued.lock().await.remove(node_id).unwrap_or_default()
    }

    /// Nodes that stopped checking in. Each is returned once, then forgotten until it checks in again.
    pub async fn take_stale(&self) -> Vec<String> {
        let now = now_unix_secs();
        let mut seen = self.last_seen.lock().await;
        let stale: Vec<String> = seen
            .iter()
            .filter(|(_, checkin)| now.saturating_sub(checkin.at) > OFFLINE_AFTER_SECS)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            seen.remove(id);
        }
        stale
    }

    async fn run(&self, node_id: &str, op: AgentOp, timeout: Duration) -> CoreResult<AgentOutput> {
        match self.last_seen.lock().await.get(node_id).copied() {
            None => {
                return Err(CoreError::NotFound(format!(
                    "{node_id} isn't connected to this controller"
                )))
            }
            Some(checkin) if now_unix_secs().saturating_sub(checkin.at) > OFFLINE_AFTER_SECS => {
                return Err(CoreError::Runtime(format!(
                    "{node_id} is offline (last check-in {}s ago)",
                    now_unix_secs().saturating_sub(checkin.at)
                )))
            }
            Some(checkin) => {
                if matches!(&op, AgentOp::AppAction { action: AppAction::Remove { .. } | AppAction::Update, .. })
                    && !checkin.app_management
                {
                    return Err(CoreError::AgentUpgradeRequired);
                }
            }
        }

        let id = format!("cmd-{}", uuid::Uuid::new_v4().simple());
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().await.insert(id.clone(), tx);
        self.queued
            .lock()
            .await
            .entry(node_id.to_string())
            .or_default()
            .push(AgentCommand { id: id.clone(), op });

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(out))) => Ok(out),
            Ok(Ok(Err(e))) => Err(CoreError::Runtime(e)),
            _ => {
                self.waiting.lock().await.remove(&id);
                if let Some(q) = self.queued.lock().await.get_mut(node_id) {
                    q.retain(|c| c.id != id);
                }
                Err(CoreError::Runtime(format!(
                    "{node_id} didn't answer within {}s",
                    timeout.as_secs()
                )))
            }
        }
    }
}

impl AgentBus {
    /// Ask an agent to update itself. Allows for a slow download plus a check-in round trip.
    /// Agents older than this feature drop the unknown command, so they time out instead.
    pub async fn update(&self, node_id: &str) -> CoreResult<Option<String>> {
        match self.run(node_id, AgentOp::Update, Duration::from_secs(330)).await {
            Ok(AgentOutput::Updated { version }) => Ok(version),
            Ok(_) => Err(unexpected()),
            Err(CoreError::Runtime(m)) if m.contains("didn't answer") => Err(CoreError::Runtime(format!(
                "{m}. If this machine runs an older agent, rerun its install command once"
            ))),
            Err(e) => Err(e),
        }
    }
}

fn unexpected() -> CoreError {
    CoreError::Runtime("agent sent an unexpected reply".into())
}

#[async_trait]
impl RemoteDispatch for AgentBus {
    async fn app_action(&self, node_id: &str, app_id: &str, action: AppAction) -> CoreResult<AppActionResult> {
        let op = AgentOp::AppAction {
            app_id: app_id.to_string(),
            action,
        };
        let timeout = match action {
            AppAction::Update => IMAGE_OPERATION_TIMEOUT,
            AppAction::Remove { .. } => Duration::from_secs(45),
            _ => Duration::from_secs(30),
        };
        match self.run(node_id, op, timeout).await? {
            AgentOutput::Done => Ok(AppActionResult::Done),
            AgentOutput::AppUpdated { changed: true } => Ok(AppActionResult::Updated),
            AgentOutput::AppUpdated { changed: false } => Ok(AppActionResult::AlreadyUpToDate),
            _ => Err(unexpected()),
        }
    }

    async fn deploy_app(&self, node_id: &str, spec: DeploySpec) -> CoreResult<ManagedApp> {
        // Agent pulls for up to 15 min, runs for up to 60s, plus a check-in round trip.
        match self
            .run(node_id, AgentOp::Deploy { spec }, IMAGE_OPERATION_TIMEOUT)
            .await?
        {
            AgentOutput::App { app } => Ok(app),
            _ => Err(unexpected()),
        }
    }

    async fn tail_logs(
        &self,
        node_id: &str,
        app_id: &str,
        lines: usize,
    ) -> CoreResult<Vec<String>> {
        let op = AgentOp::Logs {
            app_id: app_id.to_string(),
            lines,
        };
        match self.run(node_id, op, Duration::from_secs(15)).await? {
            AgentOutput::Lines { lines } => Ok(lines),
            _ => Err(unexpected()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn command_round_trips_through_checkin() {
        let bus = Arc::new(AgentBus::default());
        assert!(
            bus.tail_logs("node-pc", "docker:abc", 10).await.is_err(),
            "unknown node must fail fast"
        );

        bus.checkin("node-pc", vec![], false).await;
        let caller = {
            let bus = bus.clone();
            tokio::spawn(async move { bus.tail_logs("node-pc", "docker:abc", 10).await })
        };
        let mut cmds = Vec::new();
        while cmds.is_empty() {
            tokio::task::yield_now().await;
            cmds = bus.checkin("node-pc", vec![], false).await;
        }
        assert!(
            matches!(&cmds[0].op, AgentOp::Logs { app_id, lines: 10 } if app_id == "docker:abc")
        );

        let reply = AgentCommandResult {
            id: cmds[0].id.clone(),
            result: Ok(AgentOutput::Lines {
                lines: vec!["hello".into()],
            }),
        };
        assert!(bus.checkin("node-pc", vec![reply], false).await.is_empty());
        assert_eq!(caller.await.unwrap().unwrap(), vec!["hello".to_string()]);
    }

    #[tokio::test]
    async fn old_agents_are_not_sent_new_app_actions() {
        let bus = AgentBus::default();
        bus.checkin("node-pc", vec![], false).await;
        for action in [AppAction::Update, AppAction::Remove { delete_data: false }] {
            assert!(matches!(
                bus.app_action("node-pc", "docker:abc", action).await,
                Err(CoreError::AgentUpgradeRequired)
            ));
        }
        assert!(bus.checkin("node-pc", vec![], false).await.is_empty());
    }

    #[tokio::test]
    async fn new_app_actions_round_trip() {
        let bus = AgentBus::default();
        let node_id = "node-pc";
        for (action, reply, result) in [
            (AppAction::Remove { delete_data: true }, AgentOutput::Done, AppActionResult::Done),
            (AppAction::Update, AgentOutput::AppUpdated { changed: false }, AppActionResult::AlreadyUpToDate),
        ] {
            bus.checkin(node_id, vec![], true).await;
            let checkin = async {
                let cmd = loop {
                    if let Some(cmd) = bus.checkin(node_id, vec![], true).await.pop() {
                        break cmd;
                    }
                    tokio::task::yield_now().await;
                };
                let wire = serde_json::to_string(&cmd).unwrap();
                let cmd: AgentCommand = serde_json::from_str(&wire).unwrap();
                assert!(matches!(cmd.op, AgentOp::AppAction { app_id, action: sent }
                    if app_id == "docker:abc" && sent == action));
                bus.checkin(node_id, vec![AgentCommandResult { id: cmd.id, result: Ok(reply) }], true).await;
            };
            let (returned, ()) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(bus.app_action(node_id, "docker:abc", action), checkin)
            }).await.unwrap();
            assert_eq!(returned.unwrap(), result);
        }
    }
}
