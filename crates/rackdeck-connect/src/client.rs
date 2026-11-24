use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rackdeck_protocol::{
    AuthPayload, ChallengePayload, Frame, FrameType, HelloPayload, HttpRequestHead,
    HttpResponseHead, DEFAULT_DATA_CHUNK,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::sign_challenge;

pub struct ConnectClientConfig {
    pub relay_ws_url: String,
    pub slug: String,
    pub node_id: String,
    pub signing_key: SigningKey,
    pub local_upstream_addr: String, // e.g. "127.0.0.1:7420"
}

pub struct ConnectClientHandle {
    stop_tx: watch::Sender<bool>,
    connected: Arc<AtomicBool>,
}

impl ConnectClientHandle {
    pub fn stop(&self) {
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.stop_tx.send(true);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
}

pub fn spawn_connect_client(cfg: ConnectClientConfig) -> ConnectClientHandle {
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let connected = Arc::new(AtomicBool::new(false));
    let connected_bg = Arc::clone(&connected);
    let cfg = Arc::new(cfg);

    tokio::spawn(async move {
        let mut generation: u64 = 1;
        loop {
            if *stop_rx.borrow() {
                break;
            }
            let _ = run_session(Arc::clone(&cfg), generation, Arc::clone(&connected_bg), &mut stop_rx).await;
            connected_bg.store(false, Ordering::Relaxed);
            generation += 1;
            if *stop_rx.borrow() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                _ = stop_rx.changed() => break,
            }
        }
    });

    ConnectClientHandle { stop_tx, connected }
}

async fn run_session(
    cfg: Arc<ConnectClientConfig>,
    generation: u64,
    connected: Arc<AtomicBool>,
    stop_rx: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let (ws_stream, _) = connect_async(&cfg.relay_ws_url)
        .await
        .map_err(|e| e.to_string())?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let hello = HelloPayload {
        version: 1,
        slug: cfg.slug.clone(),
        node_id: cfg.node_id.clone(),
        public_key_hex: hex::encode(cfg.signing_key.verifying_key().to_bytes()),
        generation,
    };
    let hello_frame = Frame::json(FrameType::Hello, 0, &hello)
        .and_then(|f| f.encode())
        .map_err(|e| e.to_string())?;
    ws_tx
        .send(Message::Binary(hello_frame))
        .await
        .map_err(|e| e.to_string())?;

    // Wait for challenge
    let Some(Ok(Message::Binary(raw_challenge))) = ws_rx.next().await else {
        return Err("missing challenge".into());
    };
    let chal_frame = Frame::decode(&raw_challenge).map_err(|e| e.to_string())?;
    if chal_frame.frame_type != FrameType::Challenge {
        return Err("unexpected frame before challenge".into());
    }
    let challenge: ChallengePayload =
        serde_json::from_slice(&chal_frame.payload).map_err(|e| e.to_string())?;
    let sig = sign_challenge(
        &cfg.signing_key,
        &challenge.audience,
        &challenge.nonce_hex,
        &cfg.node_id,
    );
    let auth_frame = Frame::json(FrameType::Auth, 0, &AuthPayload { signature_hex: sig })
        .and_then(|f| f.encode())
        .map_err(|e| e.to_string())?;
    ws_tx
        .send(Message::Binary(auth_frame))
        .await
        .map_err(|e| e.to_string())?;
    connected.store(true, Ordering::Relaxed);

    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(128);
    let writer = tokio::spawn(async move {
        while let Some(bytes) = out_rx.recv().await {
            if ws_tx.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    let mut req_heads: HashMap<u32, (HttpRequestHead, Vec<u8>)> = HashMap::new();

    loop {
        tokio::select! {
            _ = stop_rx.changed() => break,
            msg = ws_rx.next() => {
                let Some(Ok(msg)) = msg else { break };
                let Message::Binary(bin) = msg else { continue };
                let Ok(frame) = Frame::decode(&bin) else { continue };
                match frame.frame_type {
                    FrameType::Headers => {
                        if let Ok(head) = serde_json::from_slice::<HttpRequestHead>(&frame.payload) {
                            req_heads.insert(frame.stream_id, (head, Vec::new()));
                        }
                    }
                    FrameType::Data => {
                        if let Some((_, body)) = req_heads.get_mut(&frame.stream_id) {
                            body.extend_from_slice(&frame.payload);
                        }
                    }
                    FrameType::Fin => {
                        if let Some((head, body)) = req_heads.remove(&frame.stream_id) {
                            let tx = out_tx.clone();
                            let upstream = cfg.local_upstream_addr.clone();
                            let sid = frame.stream_id;
                            tokio::spawn(async move {
                                forward_local_http(upstream, sid, head, body, tx).await;
                            });
                        }
                    }
                    FrameType::GoAway => break,
                    _ => {}
                }
            }
        }
    }

    writer.abort();
    Ok(())
}

async fn forward_local_http(
    upstream_addr: String,
    stream_id: u32,
    head: HttpRequestHead,
    body: Vec<u8>,
    out_tx: mpsc::Sender<Bytes>,
) {
    let result = proxy_raw_http(&upstream_addr, &head, &body).await;
    match result {
        Ok((res_head, res_body)) => {
            if let Ok(encoded) = Frame::json(FrameType::Headers, stream_id, &res_head)
                .and_then(|f| f.encode())
            {
                let _ = out_tx.send(encoded).await;
            }
            for chunk in res_body.chunks(DEFAULT_DATA_CHUNK) {
                if let Ok(encoded) =
                    Frame::new(FrameType::Data, stream_id, Bytes::copy_from_slice(chunk)).encode()
                {
                    let _ = out_tx.send(encoded).await;
                }
            }
            if let Ok(fin) = Frame::new(FrameType::Fin, stream_id, Bytes::new()).encode() {
                let _ = out_tx.send(fin).await;
            }
        }
        Err(_) => {
            if let Ok(rst) = Frame::new(FrameType::Rst, stream_id, Bytes::new()).encode() {
                let _ = out_tx.send(rst).await;
            }
        }
    }
}

async fn proxy_raw_http(
    upstream_addr: &str,
    head: &HttpRequestHead,
    body: &[u8],
) -> Result<(HttpResponseHead, Vec<u8>), String> {
    let mut stream = TcpStream::connect(upstream_addr)
        .await
        .map_err(|e| e.to_string())?;
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        head.method, head.path, upstream_addr
    );
    for (k, v) in &head.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "host" || lower == "connection" || lower == "content-length" {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if !body.is_empty() {
        stream.write_all(body).await.map_err(|e| e.to_string())?;
    }
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| e.to_string())?;

    let split_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "invalid upstream http response".to_string())?;
    let header_str = String::from_utf8_lossy(&raw[..split_pos]);
    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("HTTP/1.1 502 Bad Gateway");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let lk = k.trim().to_ascii_lowercase();
            if lk != "transfer-encoding" && lk != "connection" {
                headers.insert(lk, v.trim().to_string());
            }
        }
    }
    Ok((HttpResponseHead { status, headers }, raw[split_pos + 4..].to_vec()))
}
