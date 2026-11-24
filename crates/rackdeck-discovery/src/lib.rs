use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rackdeck_core::{now_unix_secs, CoreResult, DiscoveredPeer, DiscoveryPort, PairingInvitation};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct RawTailscaleStatus {
    #[serde(rename = "Peer")]
    peer: Option<HashMap<String, RawPeer>>,
}

#[derive(Debug, Deserialize)]
struct RawPeer {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "HostName")]
    hostname: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "OS")]
    os: Option<String>,
    #[serde(rename = "Online")]
    online: Option<bool>,
}

pub struct NetworkDiscovery;

async fn probe_rackdeck_port(ip: &str, port: u16) -> Option<String> {
    let addr = format!("{ip}:{port}");
    let mut stream = tokio::time::timeout(Duration::from_millis(450), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let req = format!("GET /api/v1/health HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_millis(450), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let body = String::from_utf8_lossy(&buf[..n]);
    if body.contains("200 OK") && body.contains("rackdeck") {
        Some("0.1.0".into())
    } else {
        None
    }
}

#[async_trait]
impl DiscoveryPort for NetworkDiscovery {
    async fn scan_peers(
        &self,
        rackdeck_port: u16,
        known_ips: &[String],
    ) -> CoreResult<Vec<DiscoveredPeer>> {
        let output = tokio::time::timeout(
            Duration::from_secs(3),
            Command::new("tailscale")
                .args(["status", "--json"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output(),
        )
        .await;

        let Ok(Ok(out)) = output else {
            return Ok(vec![]);
        };
        if !out.status.success() {
            return Ok(vec![]);
        }

        let Ok(parsed) = serde_json::from_slice::<RawTailscaleStatus>(&out.stdout) else {
            return Ok(vec![]);
        };

        let mut peers = Vec::new();
        for p in parsed.peer.unwrap_or_default().into_values() {
            let ip = p
                .tailscale_ips
                .unwrap_or_default()
                .into_iter()
                .find(|x| x.contains('.'))
                .unwrap_or_default();
            if ip.is_empty() {
                continue;
            }
            let online = p.online.unwrap_or(false);
            let rackdeck_version = if online {
                probe_rackdeck_port(&ip, rackdeck_port).await
            } else {
                None
            };
            peers.push(DiscoveredPeer {
                id: p.id.unwrap_or_else(|| ip.clone()),
                hostname: p.hostname.unwrap_or_else(|| "unknown".into()),
                in_fleet: known_ips.iter().any(|k| k == &ip),
                ip,
                source: "tailnet".into(),
                os: p.os.unwrap_or_else(|| "unknown".into()),
                online,
                rackdeck_version,
            });
        }

        Ok(peers)
    }
}

/// Generate a 60-second one-use QR pairing invitation (Ed25519 fingerprint + 6-digit fallback code).
pub fn create_pairing_invitation(
    node_id: &str,
    endpoint_url: &str,
    signing_key: &SigningKey,
) -> PairingInvitation {
    let mut rng = rand::thread_rng();
    let code_num: u32 = rng.gen_range(100_000..999_999);
    let code_6 = format!("{}-{}", code_num / 1000, code_num % 1000);
    let mut secret_bytes = [0u8; 32];
    rng.fill(&mut secret_bytes);
    let secret_hex = hex::encode(secret_bytes);

    let pk = signing_key.verifying_key().to_bytes();
    let fp = hex::encode(&Sha256::digest(pk)[..8]);
    let qr_uri = format!(
        "rackdeck://pair?e={endpoint_url}&n={node_id}&s={secret_hex}&fp={fp}"
    );

    PairingInvitation {
        id: format!("pair-{}", uuid::Uuid::new_v4().simple()),
        node_id: node_id.to_string(),
        code_6,
        fingerprint: fp,
        qr_uri,
        expires_at: now_unix_secs() + 60,
    }
}
