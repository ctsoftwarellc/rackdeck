#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "relay")]
pub mod relay;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub fn sign_challenge(
    key: &SigningKey,
    audience: &str,
    nonce_hex: &str,
    node_id: &str,
) -> String {
    let msg = format!("rackdeck.connect.v1|{audience}|{nonce_hex}|{node_id}");
    hex::encode(key.sign(msg.as_bytes()).to_bytes())
}

pub fn verify_challenge(
    public_key_hex: &str,
    audience: &str,
    nonce_hex: &str,
    node_id: &str,
    signature_hex: &str,
) -> bool {
    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    let msg = format!("rackdeck.connect.v1|{audience}|{nonce_hex}|{node_id}");
    vk.verify_strict(msg.as_bytes(), &sig).is_ok()
}
