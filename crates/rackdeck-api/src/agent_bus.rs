use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rackdeck_core::{
    now_unix_secs, AppAction, AppActionResult, CoreError, CoreResult, DeploySpec, ManagedApp,
    RemoteDispatch,
};
use rackdeck_protocol::{AgentCommand, AgentCommandResult, AgentOp, AgentOutput};
use tokio::sync::{oneshot, Mutex};

/// Agents poll every 2s; anything quieter than this is treated as offline.
const OFFLINE_AFTER_SECS: u64 = 15;
const IMAGE_OPERATION_TIMEOUT: Duration = Duration::from_secs(1050);
const REPLAY_TTL: Duration = Duration::from_secs(601);
const MAX_SEEN_CHECKINS: usize = 65_536;

type SealedCheckin = ([u8; 32], [u8; 32]);

#[derive(Default)]
struct SeenCheckins {
    keys: HashSet<SealedCheckin>,
    expiry: VecDeque<(Instant, SealedCheckin)>,
}

impl SeenCheckins {
    fn record(&mut self, key: SealedCheckin, now: Instant) -> bool {
        while self
            .expiry
            .front()
            .is_some_and(|&(expires, _)| expires <= now)
        {
            let (_, expired) = self.expiry.pop_front().unwrap();
            self.keys.remove(&expired);
        }
        // Fail closed at capacity so a burst cannot evict a still-valid check-in.
        if self.keys.len() >= MAX_SEEN_CHECKINS || !self.keys.insert(key) {
            return false;
        }
        self.expiry.push_back((now + REPLAY_TTL, key));
        true
    }
}

fn needs_app_management(op: &AgentOp) -> bool {
    match op {
        AgentOp::AppAction {
            action: AppAction::Remove { .. } | AppAction::Update,
            ..
        } => true,
        AgentOp::Deploy { spec, .. } => {
            spec.gpu || !spec.ports.is_empty() || !spec.volumes.is_empty()
        }
        _ => false,
    }
}

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
    waiting: Mutex<HashMap<String, oneshot::Sender<CoreResult<AgentOutput>>>>,
    last_seen: Mutex<HashMap<String, Checkin>>,
    seen_checkins: Mutex<SeenCheckins>,
}

impl AgentBus {
    pub(crate) async fn record_seal(&self, agent: [u8; 32], ephemeral: [u8; 32]) -> bool {
        self.seen_checkins
            .lock()
            .await
            .record((agent, ephemeral), Instant::now())
    }

    pub(crate) async fn forget(&self, node_id: &str) {
        self.last_seen.lock().await.remove(node_id);
        if let Some(commands) = self.queued.lock().await.remove(node_id) {
            let mut waiting = self.waiting.lock().await;
            for cmd in commands {
                if let Some(tx) = waiting.remove(&cmd.id) {
                    let _ = tx.send(Err(CoreError::NotFound(format!("{node_id} was removed."))));
                }
            }
        }
    }

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
        let mut commands = self.queued.lock().await.remove(node_id).unwrap_or_default();
        let mut waiting = self.waiting.lock().await;
        for r in results {
            if let Some(tx) = waiting.remove(&r.id) {
                let _ = tx.send(r.result.map_err(CoreError::Runtime));
            }
        }
        if !app_management {
            commands.retain(|cmd| {
                if !needs_app_management(&cmd.op) {
                    return true;
                }
                if let Some(tx) = waiting.remove(&cmd.id) {
                    let _ = tx.send(Err(CoreError::AgentUpgradeRequired));
                }
                false
            });
        }
        commands
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
        let seen = self.last_seen.lock().await;
        match seen.get(node_id).copied() {
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
            Some(checkin) if !checkin.app_management && needs_app_management(&op) => {
                return Err(CoreError::AgentUpgradeRequired);
            }
            Some(_) => {}
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
        drop(seen);

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
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

    async fn deploy_app(
        &self,
        node_id: &str,
        spec: DeploySpec,
        fresh_volumes: bool,
    ) -> CoreResult<ManagedApp> {
        // Agent pulls for up to 15 min, runs for up to 60s, plus a check-in round trip.
        match self
            .run(
                node_id,
                AgentOp::Deploy {
                    spec,
                    fresh_volumes,
                },
                IMAGE_OPERATION_TIMEOUT,
            )
            .await?
        {
            AgentOutput::App { app } => Ok(*app),
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
    async fn old_agents_are_not_sent_deploys_with_new_fields() {
        let bus = AgentBus::default();
        let node = "node-pc";
        bus.checkin(node, vec![], false).await;
        for extra in [
            serde_json::json!({ "ports": ["8080:80"] }),
            serde_json::json!({ "volumes": ["app:/data"] }),
            serde_json::json!({ "gpu": true }),
        ] {
            let mut spec = serde_json::json!({ "name": "app", "image": "app" });
            spec.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(matches!(
                bus.deploy_app(node, serde_json::from_value(spec).unwrap(), false)
                    .await,
                Err(CoreError::AgentUpgradeRequired)
            ));
        }

        let spec = serde_json::from_value(serde_json::json!({ "name": "app", "image": "app", "hostPort": 8080, "containerPort": 80 })).unwrap();
        let cmd = async {
            loop {
                if let Some(cmd) = bus.checkin(node, vec![], false).await.pop() {
                    break cmd;
                }
                tokio::task::yield_now().await;
            }
        };
        let deploy = bus.deploy_app(node, spec, false);
        tokio::select! {
            cmd = cmd => assert!(matches!(cmd.op, AgentOp::Deploy { spec, .. } if spec.host_port == Some(8080))),
            result = deploy => panic!("legacy deploy failed before dispatch: {result:?}"),
        }
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
