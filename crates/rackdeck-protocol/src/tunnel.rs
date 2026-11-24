use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const SUBPROTOCOL: &str = "rackdeck.connect.v1";
pub const HEADER_LEN: usize = 10;
pub const MAX_FRAME_PAYLOAD: usize = 256 * 1024; // 256 KiB hard ceiling per frame
pub const DEFAULT_DATA_CHUNK: usize = 16 * 1024; // 16 KiB streaming chunks

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Hello = 1,
    Challenge = 2,
    Auth = 3,
    Open = 4,
    Headers = 5,
    Data = 6,
    WindowUpdate = 7,
    Fin = 8,
    Rst = 9,
    GoAway = 10,
}

impl TryFrom<u8> for FrameType {
    type Error = WireError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Challenge),
            3 => Ok(Self::Auth),
            4 => Ok(Self::Open),
            5 => Ok(Self::Headers),
            6 => Ok(Self::Data),
            7 => Ok(Self::WindowUpdate),
            8 => Ok(Self::Fin),
            9 => Ok(Self::Rst),
            10 => Ok(Self::GoAway),
            other => Err(WireError::UnknownFrameType(other)),
        }
    }
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("frame too short: {0} bytes")]
    TooShort(usize),
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u8),
    #[error("frame length mismatch: header={expected}, actual={actual}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("oversized frame payload: {0} bytes")]
    Oversized(usize),
    #[error("codec error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Binary wire envelope: `[type:u8, flags:u8, stream_id:u32, length:u32, payload]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(frame_type: FrameType, stream_id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            frame_type,
            flags: 0,
            stream_id,
            payload: payload.into(),
        }
    }

    pub fn json<T: Serialize>(
        frame_type: FrameType,
        stream_id: u32,
        value: &T,
    ) -> Result<Self, WireError> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_FRAME_PAYLOAD {
            return Err(WireError::Oversized(bytes.len()));
        }
        Ok(Self::new(frame_type, stream_id, Bytes::from(bytes)))
    }

    pub fn encode(&self) -> Result<Bytes, WireError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(WireError::Oversized(self.payload.len()));
        }
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u8(self.frame_type as u8);
        buf.put_u8(self.flags);
        buf.put_u32(self.stream_id);
        buf.put_u32(self.payload.len() as u32);
        buf.extend_from_slice(&self.payload);
        Ok(buf.freeze())
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        if raw.len() < HEADER_LEN {
            return Err(WireError::TooShort(raw.len()));
        }
        let frame_type = FrameType::try_from(raw[0])?;
        let flags = raw[1];
        let stream_id = u32::from_be_bytes([raw[2], raw[3], raw[4], raw[5]]);
        let len = u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]) as usize;
        if len > MAX_FRAME_PAYLOAD {
            return Err(WireError::Oversized(len));
        }
        let actual = raw.len() - HEADER_LEN;
        if actual != len {
            return Err(WireError::LengthMismatch {
                expected: len,
                actual,
            });
        }
        Ok(Self {
            frame_type,
            flags,
            stream_id,
            payload: Bytes::copy_from_slice(&raw[HEADER_LEN..]),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloPayload {
    pub version: u8,
    pub slug: String,
    pub node_id: String,
    pub public_key_hex: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePayload {
    pub audience: String,
    pub nonce_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestHead {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseHead {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_binary_frame() {
        let f = Frame::new(FrameType::Data, 42, Bytes::from_static(b"hello-rackdeck"));
        let encoded = f.encode().unwrap();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut raw = Frame::new(FrameType::Fin, 1, Bytes::new())
            .encode()
            .unwrap()
            .to_vec();
        raw.push(0xFF);
        assert!(matches!(
            Frame::decode(&raw),
            Err(WireError::LengthMismatch {
                expected: 0,
                actual: 1
            })
        ));
    }
}
