//! Encrypted, mutually authenticated agent check-ins, plus secrets at rest.
//!
//! Each check-in: the agent makes a fresh X25519 key E and derives
//!   k = sha256(LABEL || DH(E, C) || DH(A, C) || A || E)
//! where C is the controller's static key (pinned from the join command) and A is the agent's
//! static key. Only the real controller can open the request and only the real agent can open
//! the reply, so plain-HTTP check-ins on a LAN leak nothing and can't be forged.

use curve25519_dalek::{montgomery::MontgomeryPoint, traits::IsIdentity};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use sha2::{Digest, Sha256};

const LABEL: &[u8] = b"rackdeck agent channel v1";
const REQ_NONCE: [u8; 12] = [0; 12];
const RES_NONCE: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub fn random32() -> [u8; 32] {
    rand::random()
}

pub fn public(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = MontgomeryPoint(*public).mul_clamped(*secret);
    (!shared.is_identity()).then(|| shared.to_bytes())
}

/// The controller's channel key, derived from its existing signing key so there's nothing new to store.
pub fn controller_secret(signing_key: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"rackdeck controller x25519")
        .chain_update(signing_key)
        .finalize()
        .into()
}

fn channel_key(eph_shared: [u8; 32], static_shared: [u8; 32], a: &[u8; 32], e: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(LABEL)
        .chain_update(eph_shared)
        .chain_update(static_shared)
        .chain_update(a)
        .chain_update(e)
        .finalize()
        .into()
}

fn aead(key: &[u8; 32]) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte key"))
}

fn seal_with(key: &[u8; 32], nonce: [u8; 12], plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    aead(key)
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
        .expect("seal");
    buf
}

fn open_with(key: &[u8; 32], nonce: [u8; 12], sealed: &[u8]) -> Option<Vec<u8>> {
    let mut buf = sealed.to_vec();
    let len = aead(key)
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
        .ok()?
        .len();
    buf.truncate(len);
    Some(buf)
}

/// Agent side. Returns (header value "A.E" in hex, sealed body, key for the reply).
pub fn seal_request(
    controller_pub: &[u8; 32],
    agent_secret: &[u8; 32],
    plain: &[u8],
) -> Option<(String, Vec<u8>, [u8; 32])> {
    let eph = random32();
    let (a, e) = (public(agent_secret), public(&eph));
    let key = channel_key(
        dh(&eph, controller_pub)?,
        dh(agent_secret, controller_pub)?,
        &a,
        &e,
    );
    Some((
        format!("{}.{}", hex::encode(a), hex::encode(e)),
        seal_with(&key, REQ_NONCE, plain),
        key,
    ))
}

pub fn open_response(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    open_with(key, RES_NONCE, sealed)
}

/// An authenticated check-in and the key used to seal its reply.
pub struct OpenRequest {
    pub agent: [u8; 32],
    pub ephemeral: [u8; 32],
    pub plain: Vec<u8>,
    pub reply_key: [u8; 32],
}

pub fn open_request(
    controller_secret: &[u8; 32],
    header: &str,
    sealed: &[u8],
) -> Option<OpenRequest> {
    let (a_hex, e_hex) = header.split_once('.')?;
    let agent = hex::decode(a_hex).ok()?.try_into().ok()?;
    let ephemeral = hex::decode(e_hex).ok()?.try_into().ok()?;
    let reply_key = channel_key(
        dh(controller_secret, &ephemeral)?,
        dh(controller_secret, &agent)?,
        &agent,
        &ephemeral,
    );
    let plain = open_with(&reply_key, REQ_NONCE, sealed)?;
    Some(OpenRequest {
        agent,
        ephemeral,
        plain,
        reply_key,
    })
}

pub fn seal_response(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    seal_with(key, RES_NONCE, plain)
}

/// Six digits both sides show while a machine asks to join on the home network. Covers both keys,
/// so a machine in the middle would make the codes differ.
pub fn pair_code(controller_pub: &[u8; 32], agent_pub: &[u8; 32]) -> String {
    let h = Sha256::new().chain_update(b"rackdeck pair code").chain_update(controller_pub).chain_update(agent_pub).finalize();
    let n = u32::from_be_bytes([0, h[0], h[1], h[2]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// Home-network discovery: a new machine broadcasts this on UDP and dashboards answer with their name and key.
pub const FIND_MSG: &[u8] = b"rackdeck-find v1";

/// Secrets at rest: random nonce, key derived from the controller's signing key. Output is hex.
pub fn encrypt_at_rest(signing_key: &[u8; 32], plain: &str) -> String {
    let key = Sha256::new().chain_update(b"rackdeck secrets at rest").chain_update(signing_key).finalize().into();
    let nonce: [u8; 12] = rand::random();
    let mut out = nonce.to_vec();
    out.extend(seal_with(&key, nonce, plain.as_bytes()));
    hex::encode(out)
}

pub fn decrypt_at_rest(signing_key: &[u8; 32], sealed_hex: &str) -> Option<String> {
    let key = Sha256::new().chain_update(b"rackdeck secrets at rest").chain_update(signing_key).finalize().into();
    let raw = hex::decode(sealed_hex).ok()?;
    if raw.len() < 12 {
        return None;
    }
    let nonce: [u8; 12] = raw[..12].try_into().ok()?;
    String::from_utf8(open_with(&key, nonce, &raw[12..])?).ok()
}

/// Names a secret may use. Blocks the variables that change which programs run.
pub fn valid_secret_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && name.len() <= 64
        && !matches!(name, "PATH" | "HOME" | "SHELL" | "USER" | "IFS" | "ENV" | "BASH_ENV" | "PROMPT_COMMAND")
        && !name.starts_with("LD_")
        && !name.starts_with("DYLD_")
}

/// Where a machine's secrets land. Shells pick them up via a line the installer adds to the rc files.
pub fn secrets_file_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("RACKDECK_SECRETS_FILE") {
        return p.into();
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    std::path::Path::new(&home).join(".config/rackdeck/secrets.env")
}

/// Write `export NAME='value'` lines, readable only by the owner. Owner comes from
/// RACKDECK_SECRETS_OWNER ("uid:gid") when the agent runs as root for another user.
pub fn write_secrets_file(vars: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    let mut body = String::from("# Managed by Rackdeck. Edit secrets in the dashboard; changes here are overwritten.\n");
    for (k, v) in vars {
        if valid_secret_name(k) {
            body.push_str(&format!("export {k}='{}'\n", v.replace('\'', "'\\''")));
        }
    }
    #[cfg(unix)]
    return write_secrets_unix(&secrets_file_path(), body.as_bytes()).map_err(|e| e.to_string());

    #[cfg(not(unix))]
    Err("Writing shell secrets requires Unix.".into())
}

#[cfg(unix)]
fn write_secrets_unix(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{Error, ErrorKind, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    use std::path::Component;

    let euid = unsafe { libc::geteuid() };
    let (uid, gid) = match std::env::var("RACKDECK_SECRETS_OWNER") {
        Ok(owner) => owner
            .split_once(':')
            .and_then(|(uid, gid)| Some((uid.parse().ok()?, gid.parse().ok()?)))
            .filter(|(uid, gid)| *uid != libc::uid_t::MAX && *gid != libc::gid_t::MAX)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Invalid secrets owner"))?,
        Err(std::env::VarError::NotPresent) => (euid, unsafe { libc::getegid() }),
        Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
    };

    let name = path
        .file_name()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Missing secrets filename"))?;
    let name = CString::new(name.as_bytes())?;
    let parent = path.parent().unwrap();
    let mut dir = File::open(if parent.is_absolute() { "/" } else { "." })?;
    let fd_file = |fd| {
        if fd < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    };
    let chown = |file: &File| {
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0 {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    };
    let wrong_owner = || {
        Error::new(
            ErrorKind::PermissionDenied,
            "Secrets directory has the wrong owner",
        )
    };
    for part in parent.components() {
        let part = match part {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(part) => CString::new(part.as_bytes())?,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid secrets directory",
                ))
            }
        };
        let fd = dir.as_raw_fd();
        let open_dir = || {
            fd_file(unsafe {
                libc::openat(
                    fd,
                    part.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })
        };
        dir = match open_dir() {
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if unsafe { libc::mkdirat(fd, part.as_ptr(), 0o700) } != 0 {
                    return Err(Error::last_os_error());
                }
                let new_dir = open_dir()?;
                if new_dir.metadata()?.uid() != euid {
                    return Err(wrong_owner());
                }
                if uid != euid || new_dir.metadata()?.gid() != gid {
                    chown(&new_dir)?;
                }
                new_dir
            }
            other => other?,
        };
    }
    if dir.metadata()?.uid() != uid {
        return Err(wrong_owner());
    }

    // Keep every operation relative to the verified directory, even if a parent is renamed.
    let fd = dir.as_raw_fd();
    let temp = CString::new(format!(".rackdeck-secrets-{:032x}", rand::random::<u128>()))?;
    let mut file = fd_file(unsafe {
        libc::openat(
            fd,
            temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    })?;
    let result = (|| {
        file.write_all(body)?;
        let metadata = file.metadata()?;
        if metadata.uid() != uid || metadata.gid() != gid {
            chown(&file)?;
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
            || unsafe { libc::renameat(fd, temp.as_ptr(), fd, name.as_ptr()) } != 0
        {
            return Err(Error::last_os_error());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(fd, temp.as_ptr(), 0) };
    }
    result
}

/// Short fingerprint of a machine's secrets, so the controller only resends when something changed.
pub fn secrets_version(vars: &std::collections::BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    for (k, v) in vars {
        h.update(k.as_bytes());
        h.update([0]);
        h.update(v.as_bytes());
        h.update([0]);
    }
    hex::encode(&h.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let c = controller_secret(&random32());
        let a = random32();
        let (hdr, sealed, k_agent) = seal_request(&public(&c), &a, b"hello").unwrap();
        let OpenRequest {
            agent: a_pub,
            plain,
            reply_key: k_ctrl,
            ..
        } = open_request(&c, &hdr, &sealed).unwrap();
        assert_eq!((a_pub, plain.as_slice()), (public(&a), &b"hello"[..]));
        assert_eq!(open_response(&k_agent, &seal_response(&k_ctrl, b"ok")).unwrap(), b"ok");

        // Wrong controller can't open; a flipped byte fails; a forged agent key changes the channel key.
        assert!(open_request(&random32(), &hdr, &sealed).is_none());
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open_request(&c, &hdr, &bad).is_none());
        let forged = format!("{}.{}", hex::encode(public(&random32())), hdr.split_once('.').unwrap().1);
        assert!(open_request(&c, &forged, &sealed).is_none());
    }

    #[test]
    fn rejects_zero_shared_secret_on_both_sides() {
        let c = random32();
        let a = public(&random32());
        let e = public(&random32());
        assert!(seal_request(&[0; 32], &c, b"hello").is_none());
        assert!(open_request(
            &c,
            &format!("{}.{}", hex::encode(a), hex::encode([0; 32])),
            &[]
        )
        .is_none());
        assert!(open_request(
            &c,
            &format!("{}.{}", hex::encode([0; 32]), hex::encode(e)),
            &[]
        )
        .is_none());
        assert!(dh(&c, &[0; 32]).is_none());
    }

    #[test]
    fn at_rest_and_names() {
        let k = random32();
        assert_eq!(decrypt_at_rest(&k, &encrypt_at_rest(&k, "s3cr'et")).unwrap(), "s3cr'et");
        assert!(decrypt_at_rest(&random32(), &encrypt_at_rest(&k, "x")).is_none());
        assert!(valid_secret_name("CLAUDE_CODE_OAUTH_TOKEN"));
        let (c, a) = (public(&random32()), public(&random32()));
        assert_eq!(pair_code(&c, &a), pair_code(&c, &a));
        assert_eq!(pair_code(&c, &a).len(), 7);
        assert_ne!(pair_code(&c, &a), pair_code(&a, &c));
        for bad in ["PATH", "LD_PRELOAD", "DYLD_X", "lower", "1ABC", "A-B", ""] {
            assert!(!valid_secret_name(bad), "{bad}");
        }
    }
}
