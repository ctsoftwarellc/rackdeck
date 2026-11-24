use std::path::Path;
use std::sync::Arc;
use std::thread;

use async_trait::async_trait;
use rackdeck_core::{
    now_unix_secs, AccessTokenRecord, Account, AccountKey, AuditEvent, AuditRepository, ConnectRoute, ConnectTenant,
    CoreError, CoreResult, FleetRepository, Node, RouteRepository, Secret, TenantRepository,
    TokenRepository, TokenScope, UsageRepository,
};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::{mpsc, oneshot};

enum DbCmd {
    UpsertNode(Node, oneshot::Sender<CoreResult<()>>),
    ListNodes(oneshot::Sender<CoreResult<Vec<Node>>>),
    GetNode(String, oneshot::Sender<CoreResult<Option<Node>>>),
    SetConnectState {
        node_id: String,
        enabled: bool,
        slug: Option<String>,
        reply: oneshot::Sender<CoreResult<Node>>,
    },
    GetAgentKey(String, oneshot::Sender<CoreResult<Option<String>>>),
    SetAgentKey(String, String, oneshot::Sender<CoreResult<()>>),
    AgentKeyRemoved(String, oneshot::Sender<CoreResult<bool>>),
    DeleteNode(String, oneshot::Sender<CoreResult<()>>),
    ListSecrets(oneshot::Sender<CoreResult<Vec<Secret>>>),
    UpsertSecret(Secret, oneshot::Sender<CoreResult<()>>),
    DeleteSecret(String, oneshot::Sender<CoreResult<bool>>),
    ListRoutes(oneshot::Sender<CoreResult<Vec<ConnectRoute>>>),
    UpsertRoute(ConnectRoute, oneshot::Sender<CoreResult<()>>),
    DeleteRoute(String, oneshot::Sender<CoreResult<bool>>),
    CreateToken {
        name: String,
        client: String,
        scope: TokenScope,
        node_ids: Vec<String>,
        token_hash: String,
        expires_at: Option<u64>,
        reply: oneshot::Sender<CoreResult<AccessTokenRecord>>,
    },
    ListTokens(oneshot::Sender<CoreResult<Vec<AccessTokenRecord>>>),
    FindTokenByHash(String, oneshot::Sender<CoreResult<Option<AccessTokenRecord>>>),
    RevokeToken(String, oneshot::Sender<CoreResult<bool>>),
    TouchToken(String, u64, oneshot::Sender<CoreResult<()>>),
    AppendAudit(AuditEvent, oneshot::Sender<CoreResult<()>>),
    ListAudit(usize, oneshot::Sender<CoreResult<Vec<AuditEvent>>>),
    AddUsage(String, u64, u64, oneshot::Sender<CoreResult<()>>),
    GetUsage(String, oneshot::Sender<CoreResult<(u64, u64)>>),
    UpsertTenant(ConnectTenant, oneshot::Sender<CoreResult<()>>),
    GetTenant(String, oneshot::Sender<CoreResult<Option<ConnectTenant>>>),
    SetTenantActiveByCustomer(String, bool, oneshot::Sender<CoreResult<()>>),
    ListTenants(oneshot::Sender<CoreResult<Vec<ConnectTenant>>>),
    UpsertAccount(Account, oneshot::Sender<CoreResult<()>>),
    FindAccount(AccountKey, String, oneshot::Sender<CoreResult<Option<Account>>>),
}

/// Dedicated bounded-queue SQLite store (WAL, foreign_keys, busy_timeout).
#[derive(Clone)]
pub struct SqliteStore {
    tx: mpsc::Sender<DbCmd>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> CoreResult<Arc<Self>> {
        let path_buf = path.as_ref().to_path_buf();
        let conn = if path_buf.as_os_str() == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(&path_buf)
        }
        .map_err(|e| CoreError::Storage(e.to_string()))?;

        init_schema(&conn)?;

        let (tx, mut rx) = mpsc::channel::<DbCmd>(256);
        thread::Builder::new()
            .name("rackdeck-sqlite".into())
            .spawn(move || {
                while let Some(cmd) = rx.blocking_recv() {
                    handle_cmd(&conn, cmd);
                }
            })
            .map_err(|e| CoreError::Storage(e.to_string()))?;

        Ok(Arc::new(Self { tx }))
    }

    async fn call<T>(&self, make: impl FnOnce(oneshot::Sender<CoreResult<T>>) -> DbCmd) -> CoreResult<T> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(make(reply_tx))
            .await
            .map_err(|_| CoreError::Storage("sqlite worker closed".into()))?;
        reply_rx
            .await
            .map_err(|_| CoreError::Storage("sqlite worker dropped reply".into()))?
    }
}

fn init_schema(conn: &Connection) -> CoreResult<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;

        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_keys (
            node_id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS removed_agent_keys (
            key_hash TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS secrets (
            name TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS routes (
            id TEXT PRIMARY KEY,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tokens (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS usage_totals (
            tenant TEXT PRIMARY KEY,
            bytes_in INTEGER NOT NULL DEFAULT 0,
            bytes_out INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            stripe_customer_id TEXT,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connect_tenants (
            slug TEXT PRIMARY KEY,
            stripe_customer_id TEXT,
            payload_json TEXT NOT NULL
        );
        ",
    )
    .map_err(|e| CoreError::Storage(e.to_string()))
}

fn handle_cmd(conn: &Connection, cmd: DbCmd) {
    match cmd {
        DbCmd::UpsertNode(node, reply) => {
            let res = serde_json::to_string(&node)
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|json| {
                    conn.execute(
                        "INSERT INTO nodes (id, payload_json) VALUES (?1, ?2)
                         ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                        params![node.id, json],
                    )
                    .map(|_| ())
                    .map_err(|e| CoreError::Storage(e.to_string()))
                });
            let _ = reply.send(res);
        }
        DbCmd::ListNodes(reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT payload_json FROM nodes ORDER BY id ASC")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let mut out = Vec::new();
                for item in rows {
                    let s = item.map_err(|e| CoreError::Storage(e.to_string()))?;
                    out.push(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    );
                }
                Ok(out)
            })();
            let _ = reply.send(res);
        }
        DbCmd::GetAgentKey(node_id, reply) => {
            let res = conn
                .query_row(
                    "SELECT key_hash FROM agent_keys WHERE node_id = ?1",
                    params![node_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::AgentKeyRemoved(hash, reply) => {
            let res = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM removed_agent_keys WHERE key_hash = ?1)",
                    params![hash],
                    |r| r.get(0),
                )
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::DeleteNode(node_id, reply) => {
            let res = (|| {
                let tx = conn.unchecked_transaction()?;
                tx.execute(
                    "INSERT OR IGNORE INTO removed_agent_keys SELECT key_hash FROM agent_keys WHERE node_id = ?1",
                    params![node_id],
                )?;
                tx.execute("DELETE FROM nodes WHERE id = ?1", params![node_id])?;
                tx.execute("DELETE FROM agent_keys WHERE node_id = ?1", params![node_id])?;
                tx.execute("DELETE FROM routes WHERE json_extract(payload_json, '$.nodeId') = ?1", params![node_id])?;
                tx.execute(
                    "UPDATE secrets SET payload_json = json_set(payload_json, '$.nodeIds',
                        json((SELECT json_group_array(value) FROM json_each(payload_json, '$.nodeIds') WHERE value != ?1)))
                     WHERE EXISTS (SELECT 1 FROM json_each(payload_json, '$.nodeIds') WHERE value = ?1)",
                    params![node_id],
                )?;
                tx.commit()
            })().map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::SetAgentKey(node_id, hash, reply) => {
            let res = conn
                .execute(
                    "INSERT INTO agent_keys (node_id, key_hash) VALUES (?1, ?2)
                     ON CONFLICT(node_id) DO UPDATE SET key_hash = excluded.key_hash",
                    params![node_id, hash],
                )
                .map(|_| ())
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::GetNode(id, reply) => {
            let res = (|| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT payload_json FROM nodes WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                match raw {
                    Some(s) => Ok(Some(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    )),
                    None => Ok(None),
                }
            })();
            let _ = reply.send(res);
        }
        DbCmd::SetConnectState {
            node_id,
            enabled,
            slug,
            reply,
        } => {
            let res = (|| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT payload_json FROM nodes WHERE id = ?1",
                        params![node_id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let mut node: Node = match raw {
                    Some(s) => {
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?
                    }
                    None => return Err(CoreError::NotFound(node_id)),
                };
                node.connect_enabled = enabled;
                if let Some(s) = slug {
                    node.connect_slug = Some(s);
                }
                let json =
                    serde_json::to_string(&node).map_err(|e| CoreError::Storage(e.to_string()))?;
                conn.execute(
                    "UPDATE nodes SET payload_json = ?1 WHERE id = ?2",
                    params![json, node.id],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;
                Ok(node)
            })();
            let _ = reply.send(res);
        }
        DbCmd::ListSecrets(reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT payload_json FROM secrets ORDER BY name ASC")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let mut out = Vec::new();
                for item in rows {
                    let s = item.map_err(|e| CoreError::Storage(e.to_string()))?;
                    out.push(serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?);
                }
                Ok(out)
            })();
            let _ = reply.send(res);
        }
        DbCmd::UpsertSecret(secret, reply) => {
            let res = serde_json::to_string(&secret)
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|json| {
                    conn.execute(
                        "INSERT INTO secrets (name, payload_json) VALUES (?1, ?2)
                         ON CONFLICT(name) DO UPDATE SET payload_json = excluded.payload_json",
                        params![secret.name, json],
                    )
                    .map(|_| ())
                    .map_err(|e| CoreError::Storage(e.to_string()))
                });
            let _ = reply.send(res);
        }
        DbCmd::DeleteSecret(name, reply) => {
            let res = conn
                .execute("DELETE FROM secrets WHERE name = ?1", params![name])
                .map(|n| n > 0)
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::ListRoutes(reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT payload_json FROM routes ORDER BY id ASC")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let mut out = Vec::new();
                for item in rows {
                    let s = item.map_err(|e| CoreError::Storage(e.to_string()))?;
                    out.push(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    );
                }
                Ok(out)
            })();
            let _ = reply.send(res);
        }
        DbCmd::UpsertRoute(route, reply) => {
            let res = serde_json::to_string(&route)
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|json| {
                    conn.execute(
                        "INSERT INTO routes (id, payload_json) VALUES (?1, ?2)
                         ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                        params![route.id, json],
                    )
                    .map(|_| ())
                    .map_err(|e| CoreError::Storage(e.to_string()))
                });
            let _ = reply.send(res);
        }
        DbCmd::DeleteRoute(id, reply) => {
            let res = conn
                .execute("DELETE FROM routes WHERE id = ?1", params![id])
                .map(|n| n > 0)
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::CreateToken {
            name,
            client,
            scope,
            node_ids,
            token_hash,
            expires_at,
            reply,
        } => {
            let res = (|| {
                let rec = AccessTokenRecord {
                    id: format!("tok-{}", uuid::Uuid::new_v4().simple()),
                    name,
                    client,
                    scope,
                    node_ids,
                    created_at: now_unix_secs(),
                    last_used_at: None,
                    expires_at,
                    revoked: false,
                };
                let json =
                    serde_json::to_string(&rec).map_err(|e| CoreError::Storage(e.to_string()))?;
                conn.execute(
                    "INSERT INTO tokens (id, token_hash, payload_json) VALUES (?1, ?2, ?3)",
                    params![rec.id, token_hash, json],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;
                Ok(rec)
            })();
            let _ = reply.send(res);
        }
        DbCmd::ListTokens(reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT payload_json FROM tokens ORDER BY id DESC")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let mut out = Vec::new();
                for item in rows {
                    let s = item.map_err(|e| CoreError::Storage(e.to_string()))?;
                    out.push(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    );
                }
                Ok(out)
            })();
            let _ = reply.send(res);
        }
        DbCmd::FindTokenByHash(hash, reply) => {
            let res = (|| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT payload_json FROM tokens WHERE token_hash = ?1",
                        params![hash],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                match raw {
                    Some(s) => Ok(Some(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    )),
                    None => Ok(None),
                }
            })();
            let _ = reply.send(res);
        }
        DbCmd::RevokeToken(id, reply) => {
            let res = (|| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT payload_json FROM tokens WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let Some(s) = raw else { return Ok(false) };
                let mut rec: AccessTokenRecord =
                    serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?;
                rec.revoked = true;
                let json =
                    serde_json::to_string(&rec).map_err(|e| CoreError::Storage(e.to_string()))?;
                conn.execute(
                    "UPDATE tokens SET payload_json = ?1 WHERE id = ?2",
                    params![json, rec.id],
                )
                .map_err(|e| CoreError::Storage(e.to_string()))?;
                Ok(true)
            })();
            let _ = reply.send(res);
        }
        DbCmd::TouchToken(id, ts, reply) => {
            let res = (|| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT payload_json FROM tokens WHERE id = ?1",
                        params![id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                if let Some(s) = raw {
                    let mut rec: AccessTokenRecord =
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?;
                    rec.last_used_at = Some(ts);
                    let json = serde_json::to_string(&rec)
                        .map_err(|e| CoreError::Storage(e.to_string()))?;
                    conn.execute(
                        "UPDATE tokens SET payload_json = ?1 WHERE id = ?2",
                        params![json, rec.id],
                    )
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                }
                Ok(())
            })();
            let _ = reply.send(res);
        }
        DbCmd::AppendAudit(ev, reply) => {
            let res = serde_json::to_string(&ev)
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|json| {
                    conn.execute(
                        "INSERT INTO audit_events (payload_json) VALUES (?1)",
                        params![json],
                    )
                    .map(|_| ())
                    .map_err(|e| CoreError::Storage(e.to_string()))
                });
            let _ = reply.send(res);
        }
        DbCmd::ListAudit(limit, reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT payload_json FROM audit_events ORDER BY seq DESC LIMIT ?1")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows = stmt
                    .query_map(params![limit as i64], |r| r.get::<_, String>(0))
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let mut out = Vec::new();
                for item in rows {
                    let s = item.map_err(|e| CoreError::Storage(e.to_string()))?;
                    out.push(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    );
                }
                Ok(out)
            })();
            let _ = reply.send(res);
        }
        DbCmd::AddUsage(tenant, bytes_in, bytes_out, reply) => {
            let res = conn
                .execute(
                    "INSERT INTO usage_totals (tenant, bytes_in, bytes_out) VALUES (?1, ?2, ?3)
                     ON CONFLICT(tenant) DO UPDATE SET
                       bytes_in = usage_totals.bytes_in + excluded.bytes_in,
                       bytes_out = usage_totals.bytes_out + excluded.bytes_out",
                    params![tenant, bytes_in as i64, bytes_out as i64],
                )
                .map(|_| ())
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::GetUsage(tenant, reply) => {
            let res = conn
                .query_row(
                    "SELECT bytes_in, bytes_out FROM usage_totals WHERE tenant = ?1",
                    params![tenant],
                    |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
                )
                .optional()
                .map(|opt| opt.unwrap_or((0, 0)))
                .map_err(|e| CoreError::Storage(e.to_string()));
            let _ = reply.send(res);
        }
        DbCmd::UpsertTenant(tenant, reply) => {
            let res = serde_json::to_string(&tenant)
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|json| {
                    conn.execute(
                        "INSERT INTO connect_tenants (slug, stripe_customer_id, payload_json) VALUES (?1, ?2, ?3)
                         ON CONFLICT(slug) DO UPDATE SET stripe_customer_id = excluded.stripe_customer_id, payload_json = excluded.payload_json",
                        params![tenant.slug.to_ascii_lowercase(), tenant.stripe_customer_id, json],
                    )
                    .map(|_| ())
                    .map_err(|e| CoreError::Storage(e.to_string()))
                });
            let _ = reply.send(res);
        }
        DbCmd::GetTenant(slug, reply) => {
            let res = (|| {
                let raw: Option<String> = conn
                    .query_row(
                        "SELECT payload_json FROM connect_tenants WHERE slug = ?1",
                        params![slug.to_ascii_lowercase()],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                match raw {
                    Some(s) => Ok(Some(
                        serde_json::from_str(&s).map_err(|e| CoreError::Storage(e.to_string()))?,
                    )),
                    None => Ok(None),
                }
            })();
            let _ = reply.send(res);
        }
        DbCmd::ListTenants(reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT payload_json FROM connect_tenants ORDER BY slug")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                Ok(rows
                    .filter_map(Result::ok)
                    .filter_map(|s| serde_json::from_str(&s).ok())
                    .collect())
            })();
            let _ = reply.send(res);
        }
        DbCmd::UpsertAccount(acct, reply) => {
            let res = serde_json::to_string(&acct)
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|json| {
                    conn.execute(
                        "INSERT INTO accounts (id, email, stripe_customer_id, payload_json) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(id) DO UPDATE SET email = excluded.email,
                           stripe_customer_id = excluded.stripe_customer_id, payload_json = excluded.payload_json",
                        params![acct.id, acct.email.to_ascii_lowercase(), acct.stripe_customer_id, json],
                    )
                    .map(|_| ())
                    .map_err(|e| CoreError::Storage(e.to_string()))
                });
            let _ = reply.send(res);
        }
        DbCmd::FindAccount(by, value, reply) => {
            let col = match by {
                AccountKey::Id => "id",
                AccountKey::Email => "email",
                AccountKey::StripeCustomer => "stripe_customer_id",
            };
            let value = if by == AccountKey::Email { value.to_ascii_lowercase() } else { value };
            let res = conn
                .query_row(
                    &format!("SELECT payload_json FROM accounts WHERE {col} = ?1"),
                    params![value],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| CoreError::Storage(e.to_string()))
                .and_then(|raw| match raw {
                    Some(s) => serde_json::from_str(&s)
                        .map(Some)
                        .map_err(|e| CoreError::Storage(e.to_string())),
                    None => Ok(None),
                });
            let _ = reply.send(res);
        }
        DbCmd::SetTenantActiveByCustomer(customer_id, active, reply) => {
            let res = (|| {
                let mut stmt = conn
                    .prepare("SELECT slug, payload_json FROM connect_tenants WHERE stripe_customer_id = ?1")
                    .map_err(|e| CoreError::Storage(e.to_string()))?;
                let rows: Vec<(String, String)> = stmt
                    .query_map(params![customer_id], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map_err(|e| CoreError::Storage(e.to_string()))?
                    .filter_map(Result::ok)
                    .collect();
                for (slug, raw) in rows {
                    if let Ok(mut t) = serde_json::from_str::<ConnectTenant>(&raw) {
                        t.active = active;
                        if let Ok(json) = serde_json::to_string(&t) {
                            let _ = conn.execute(
                                "UPDATE connect_tenants SET payload_json = ?1 WHERE slug = ?2",
                                params![json, slug],
                            );
                        }
                    }
                }
                Ok(())
            })();
            let _ = reply.send(res);
        }
    }
}

#[async_trait]
impl FleetRepository for SqliteStore {
    async fn upsert_node(&self, node: Node) -> CoreResult<()> {
        self.call(|r| DbCmd::UpsertNode(node, r)).await
    }
    async fn list_nodes(&self) -> CoreResult<Vec<Node>> {
        self.call(DbCmd::ListNodes).await
    }
    async fn get_node(&self, id: &str) -> CoreResult<Option<Node>> {
        self.call(|r| DbCmd::GetNode(id.to_string(), r)).await
    }
    async fn agent_key_hash(&self, node_id: &str) -> CoreResult<Option<String>> {
        self.call(|r| DbCmd::GetAgentKey(node_id.to_string(), r)).await
    }
    async fn set_agent_key_hash(&self, node_id: &str, key_hash: &str) -> CoreResult<()> {
        self.call(|r| DbCmd::SetAgentKey(node_id.to_string(), key_hash.to_string(), r)).await
    }
    async fn agent_key_removed(&self, key_hash: &str) -> CoreResult<bool> {
        self.call(|tx| DbCmd::AgentKeyRemoved(key_hash.to_string(), tx))
            .await
    }

    async fn delete_node(&self, node_id: &str) -> CoreResult<()> {
        self.call(|r| DbCmd::DeleteNode(node_id.to_string(), r)).await
    }
    async fn list_secrets(&self) -> CoreResult<Vec<Secret>> {
        self.call(DbCmd::ListSecrets).await
    }
    async fn upsert_secret(&self, secret: Secret) -> CoreResult<()> {
        self.call(|r| DbCmd::UpsertSecret(secret, r)).await
    }
    async fn delete_secret(&self, name: &str) -> CoreResult<bool> {
        self.call(|r| DbCmd::DeleteSecret(name.to_string(), r)).await
    }
    async fn set_connect_state(
        &self,
        node_id: &str,
        enabled: bool,
        slug: Option<String>,
    ) -> CoreResult<Node> {
        self.call(|r| DbCmd::SetConnectState {
            node_id: node_id.to_string(),
            enabled,
            slug,
            reply: r,
        })
        .await
    }
}

#[async_trait]
impl RouteRepository for SqliteStore {
    async fn list_routes(&self) -> CoreResult<Vec<ConnectRoute>> {
        self.call(DbCmd::ListRoutes).await
    }
    async fn upsert_route(&self, route: ConnectRoute) -> CoreResult<()> {
        self.call(|r| DbCmd::UpsertRoute(route, r)).await
    }
    async fn delete_route(&self, id: &str) -> CoreResult<bool> {
        self.call(|r| DbCmd::DeleteRoute(id.to_string(), r)).await
    }
}

#[async_trait]
impl TokenRepository for SqliteStore {
    async fn create_token(
        &self,
        name: String,
        client: String,
        scope: TokenScope,
        node_ids: Vec<String>,
        token_hash: String,
        expires_at: Option<u64>,
    ) -> CoreResult<AccessTokenRecord> {
        self.call(|r| DbCmd::CreateToken {
            name,
            client,
            scope,
            node_ids,
            token_hash,
            expires_at,
            reply: r,
        })
        .await
    }
    async fn list_tokens(&self) -> CoreResult<Vec<AccessTokenRecord>> {
        self.call(DbCmd::ListTokens).await
    }
    async fn find_by_hash(&self, token_hash: &str) -> CoreResult<Option<AccessTokenRecord>> {
        self.call(|r| DbCmd::FindTokenByHash(token_hash.to_string(), r))
            .await
    }
    async fn revoke_token(&self, id: &str) -> CoreResult<bool> {
        self.call(|r| DbCmd::RevokeToken(id.to_string(), r)).await
    }
    async fn touch_token(&self, id: &str, ts: u64) -> CoreResult<()> {
        self.call(|r| DbCmd::TouchToken(id.to_string(), ts, r))
            .await
    }
}

#[async_trait]
impl AuditRepository for SqliteStore {
    async fn append_audit(&self, event: AuditEvent) -> CoreResult<()> {
        self.call(|r| DbCmd::AppendAudit(event, r)).await
    }
    async fn list_audit(&self, limit: usize) -> CoreResult<Vec<AuditEvent>> {
        self.call(|r| DbCmd::ListAudit(limit, r)).await
    }
}

#[async_trait]
impl UsageRepository for SqliteStore {
    async fn add_usage_delta(&self, tenant: &str, bytes_in: u64, bytes_out: u64) -> CoreResult<()> {
        self.call(|r| DbCmd::AddUsage(tenant.to_string(), bytes_in, bytes_out, r))
            .await
    }
    async fn get_usage(&self, tenant: &str) -> CoreResult<(u64, u64)> {
        self.call(|r| DbCmd::GetUsage(tenant.to_string(), r)).await
    }
}

#[async_trait]
impl TenantRepository for SqliteStore {
    async fn upsert_tenant(&self, tenant: ConnectTenant) -> CoreResult<()> {
        self.call(|r| DbCmd::UpsertTenant(tenant, r)).await
    }
    async fn get_tenant(&self, slug: &str) -> CoreResult<Option<ConnectTenant>> {
        self.call(|r| DbCmd::GetTenant(slug.to_string(), r)).await
    }
    async fn set_tenant_active_by_customer(&self, customer_id: &str, active: bool) -> CoreResult<()> {
        self.call(|r| DbCmd::SetTenantActiveByCustomer(customer_id.to_string(), active, r))
            .await
    }
    async fn list_tenants(&self) -> CoreResult<Vec<ConnectTenant>> {
        self.call(DbCmd::ListTenants).await
    }
    async fn upsert_account(&self, account: Account) -> CoreResult<()> {
        self.call(|r| DbCmd::UpsertAccount(account, r)).await
    }
    async fn find_account(&self, by: AccountKey, value: &str) -> CoreResult<Option<Account>> {
        self.call(|r| DbCmd::FindAccount(by, value.to_string(), r)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rackdeck_core::TlsState;

    #[tokio::test]
    async fn removing_a_machine_retires_its_key_and_prunes_its_assignments() {
        let store = SqliteStore::open(":memory:").unwrap();
        store
            .set_agent_key_hash("removed", "old-key")
            .await
            .unwrap();
        for (name, node_ids) in [
            ("shared", vec!["keep", "removed"]),
            ("private", vec!["removed"]),
        ] {
            store
                .upsert_secret(Secret {
                    name: name.into(),
                    sealed: "encrypted".into(),
                    node_ids: node_ids.into_iter().map(str::to_string).collect(),
                    updated_at: 0,
                })
                .await
                .unwrap();
        }
        for id in ["keep", "removed"] {
            store
                .upsert_route(ConnectRoute {
                    id: id.into(),
                    host: format!("{id}.example"),
                    node_id: id.into(),
                    target_app: "test".into(),
                    target_port: 8080,
                    tls: TlsState::Valid,
                    require_auth: true,
                    bytes_24h: 0,
                })
                .await
                .unwrap();
        }
        store.delete_node("removed").await.unwrap();

        assert!(store.agent_key_removed("old-key").await.unwrap());
        assert!(store.agent_key_hash("removed").await.unwrap().is_none());
        let routes = store.list_routes().await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].node_id, "keep");
        let secrets = store.list_secrets().await.unwrap();
        assert!(secrets[0].node_ids.is_empty());
        assert_eq!(secrets[1].node_ids, ["keep"]);
    }
}
