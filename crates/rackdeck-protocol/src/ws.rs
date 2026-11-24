use rackdeck_core::{AuditEvent, DiscoveredPeer, ManagedApp, Node, TelemetrySample};
use serde::{Deserialize, Serialize};

/// Single multiplexed `/api/ws` server → client events (Opus 5.5 spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerWsEvent {
    Snapshot {
        nodes: Vec<Node>,
        apps: Vec<ManagedApp>,
    },
    Node {
        node: Node,
    },
    Apps {
        #[serde(rename = "nodeId")]
        node_id: String,
        apps: Vec<ManagedApp>,
    },
    Tm {
        #[serde(rename = "nodeId")]
        node_id: String,
        s: TelemetrySample,
    },
    Log {
        sub: String,
        lines: Vec<(u64, String, String)>,
    },
    TermOut {
        sub: String,
        text: String,
    },
    Disc {
        peer: DiscoveredPeer,
    },
    Audit {
        ev: AuditEvent,
    },
    Pong {
        id: u64,
    },
}

/// Single multiplexed `/api/ws` client → server commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientWsCommand {
    Ping {
        id: u64,
    },
    Sub {
        ch: String,
        sub: String,
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "appId")]
        app_id: Option<String>,
    },
    Unsub {
        sub: String,
    },
    TermExec {
        sub: String,
        cmd: String,
    },
}
