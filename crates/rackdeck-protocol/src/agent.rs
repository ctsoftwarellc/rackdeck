use rackdeck_core::{AppAction, DeploySpec, ManagedApp};
use serde::{Deserialize, Serialize};

/// Controller → agent work item, delivered in the `/api/v1/agent/checkin` response.
/// Agents only ever dial out, so commands ride the existing check-in loop (no inbound ports).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCommand {
    pub id: String,
    pub op: AgentOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentOp {
    #[serde(rename_all = "camelCase")]
    AppAction {
        app_id: String,
        action: AppAction,
    },
    Deploy {
        spec: DeploySpec,
    },
    #[serde(rename_all = "camelCase")]
    Logs {
        app_id: String,
        lines: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentOutput {
    Done,
    App { app: ManagedApp },
    Lines { lines: Vec<String> },
}

/// Agent → controller result, posted on the next check-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCommandResult {
    pub id: String,
    pub result: Result<AgentOutput, String>,
}
