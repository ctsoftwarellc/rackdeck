//! Self-update from GitHub Releases. Shells out to curl and tar, which every supported host has.

use tokio::process::Command;

const REPO: &str = "ctsoftwarellc/rackdeck";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Release asset name for this build, matching release.yml (e.g. `rackdeck-aarch64-apple-darwin.tar.gz`).
fn asset_name() -> String {
    let os = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else {
        "unknown-linux-gnu"
    };
    format!("rackdeck-{}-{os}.tar.gz", std::env::consts::ARCH)
}

async fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("couldn't run {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Latest released version without the leading `v`, e.g. "0.2.1".
pub async fn latest_version() -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = run("curl", &["-fsSL", "-m", "15", "-H", "User-Agent: rackdeck", &url]).await?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("bad release info: {e}"))?;
    v["tag_name"]
        .as_str()
        .map(|t| t.trim_start_matches('v').to_string())
        .ok_or_else(|| "release info has no tag".into())
}

/// Download the latest release and swap it in for the running binary.
/// Returns the new version, or None when already current. Call `restart_self` afterwards.
pub async fn self_update() -> Result<Option<String>, String> {
    let latest = latest_version().await?;
    if latest == CURRENT {
        return Ok(None);
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("can't find the running binary: {e}"))?;
    let dir = exe.parent().ok_or("binary has no parent directory")?;
    // Stage next to the binary so the final rename stays on one filesystem (atomic).
    let staging = dir.join(".rackdeck-update");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| {
        format!(
            "can't write to {} ({e}). Run the update with sudo or reinstall.",
            dir.display()
        )
    })?;
    let tarball = staging.join("rackdeck.tar.gz");
    let url = format!(
        "https://github.com/{REPO}/releases/download/v{latest}/{}",
        asset_name()
    );
    let result = async {
        run("curl", &["-fsSL", "-m", "300", "-o", &tarball.to_string_lossy(), &url]).await?;
        run("tar", &["-xzf", &tarball.to_string_lossy(), "-C", &staging.to_string_lossy()]).await?;
        let new_bin = staging.join("rackdeck");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new_bin, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        std::fs::rename(&new_bin, &exe).map_err(|e| format!("couldn't replace {}: {e}", exe.display()))
    }
    .await;
    let _ = std::fs::remove_dir_all(&staging);
    result.map(|_| Some(latest))
}

/// Replace this process with the (new) binary on disk, same args and env. Never returns on success.
pub fn restart_self() -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let Ok(exe) = std::env::current_exe() else {
            return "can't find the running binary".into();
        };
        // Linux reports a replaced binary as "/path/rackdeck (deleted)"; we want the new file at that path.
        let exe = std::path::PathBuf::from(exe.to_string_lossy().trim_end_matches(" (deleted)").to_string());
        let err = std::process::Command::new(exe)
            .args(std::env::args_os().skip(1))
            .exec();
        return err.to_string();
    }
    #[allow(unreachable_code)]
    "restart isn't supported on this platform".into()
}
