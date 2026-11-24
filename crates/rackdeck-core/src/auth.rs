use crate::{CoreError, CoreResult, TokenScope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    Owner { label: String },
    ScopedToken {
        token_id: String,
        name: String,
        scope: TokenScope,
        node_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    ReadTelemetry,
    ReadLogs,
    ControlApp,
    OpenTerminal,
    ManageNetwork,
    ManageTokens,
}

impl Principal {
    pub fn actor_name(&self) -> &str {
        match self {
            Principal::Owner { label } => label,
            Principal::ScopedToken { name, .. } => name,
        }
    }

    pub fn authorize(&self, cap: Capability, node_id: Option<&str>) -> CoreResult<()> {
        match self {
            Principal::Owner { .. } => Ok(()),
            Principal::ScopedToken {
                scope, node_ids, ..
            } => {
                if let Some(target_node) = node_id {
                    if !node_ids.is_empty() && !node_ids.iter().any(|id| id == target_node) {
                        return Err(CoreError::Forbidden(format!(
                            "token not scoped for node {target_node}"
                        )));
                    }
                }
                match cap {
                    Capability::ReadTelemetry | Capability::ReadLogs => Ok(()),
                    Capability::ControlApp => match scope {
                        TokenScope::Deploy => Ok(()),
                        TokenScope::Read => {
                            Err(CoreError::Forbidden("requires deploy scope".into()))
                        }
                    },
                    // Terminal, network routes, and token management are never grantable to MCP tokens in v0.1
                    Capability::OpenTerminal => Err(CoreError::Forbidden(
                        "terminal access is never grantable to scoped tokens in v0.1".into(),
                    )),
                    Capability::ManageNetwork | Capability::ManageTokens => Err(
                        CoreError::Forbidden("owner session required".into()),
                    ),
                }
            }
        }
    }
}
