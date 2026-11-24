use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use rackdeck_core::{
    now_unix_secs, AppAction, CoreError, CoreResult, DeploySpec, ManagedApp, RemoteDispatch,
};
use rackdeck_protocol::{AgentCommand, AgentCommandResult, AgentOp, AgentOutput};
use tokio::sync::{oneshot, Mutex};

/// Agents poll every 2s; anything quieter than this is treated as offline.
const OFFLINE_AFTER_SECS: u64 = 15;

/// Queues commands for remote agents and hands them out on check-in.
/// ponytail: in-memory only, so commands in flight are lost on controller restart (callers just get a timeout).
#[derive(Default)]
pub struct AgentBus {
    queued: Mutex<HashMap<String, Vec<AgentCommand>>>,
    waiting: Mutex<HashMap<String, oneshot::Sender<Result<AgentOutput, String>>>>,
    last_seen: Mutex<HashMap<String, u64>>,
}

impl AgentBus {
    /// Called on every authenticated check-in: deliver finished results, return queued work.
    pub async fn checkin(
        &self,
        node_id: &str,
        results: Vec<AgentCommandResult>,
    ) -> Vec<AgentCommand> {
        self.last_seen
            .lock()
            .await
            .insert(node_id.to_string(), now_unix_secs());
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

    async fn run(&self, node_id: &str, op: AgentOp, timeout: Duration) -> CoreResult<AgentOutput> {
        match self.last_seen.lock().await.get(node_id).copied() {
            None => {
                return Err(CoreError::NotFound(format!(
                    "{node_id} isn't connected to this controller"
                )))
            }
            Some(t) if now_unix_secs().saturating_sub(t) > OFFLINE_AFTER_SECS => {
                return Err(CoreError::Runtime(format!(
                    "{node_id} is offline (last check-in {}s ago)",
                    now_unix_secs().saturating_sub(t)
                )))
            }
            _ => {}
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

fn unexpected() -> CoreError {
    CoreError::Runtime("agent sent an unexpected reply".into())
}

#[async_trait]
impl RemoteDispatch for AgentBus {
    async fn app_action(&self, node_id: &str, app_id: &str, action: AppAction) -> CoreResult<()> {
        let op = AgentOp::AppAction {
            app_id: app_id.to_string(),
            action,
        };
        match self.run(node_id, op, Duration::from_secs(30)).await? {
            AgentOutput::Done => Ok(()),
            _ => Err(unexpected()),
        }
    }

    async fn deploy_app(&self, node_id: &str, spec: DeploySpec) -> CoreResult<ManagedApp> {
        // Agent's own `docker run` timeout is 60s (image pulls), plus a check-in round trip.
        match self
            .run(node_id, AgentOp::Deploy { spec }, Duration::from_secs(75))
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

        bus.checkin("node-pc", vec![]).await;
        let caller = {
            let bus = bus.clone();
            tokio::spawn(async move { bus.tail_logs("node-pc", "docker:abc", 10).await })
        };
        let mut cmds = Vec::new();
        while cmds.is_empty() {
            tokio::task::yield_now().await;
            cmds = bus.checkin("node-pc", vec![]).await;
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
        assert!(bus.checkin("node-pc", vec![reply]).await.is_empty());
        assert_eq!(caller.await.unwrap().unwrap(), vec!["hello".to_string()]);
    }
}
