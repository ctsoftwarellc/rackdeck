use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rackdeck_core::{AppActionResult, CoreError, CoreResult, DeploySpec};
use serde::Deserialize;
use serde_json::Value;
use tokio::process::Command;

use super::extra_run_args;

pub const SPEC_LABEL: &str = "dev.rackdeck.spec";
const CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

pub async fn docker(args: &[&str], seconds: u64) -> CoreResult<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(seconds),
        Command::new("docker")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| CoreError::Runtime(format!("Docker {} timed out.", args[0])))?
    .map_err(|e| CoreError::Runtime(format!("Docker unavailable: {e}")))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().into());
    }
    let message = String::from_utf8_lossy(&output.stderr);
    let message = message.trim();
    Err(CoreError::Runtime(if message.is_empty() {
        format!("Docker {} failed.", args[0])
    } else {
        message.into()
    }))
}

pub async fn pull_image(image: &str) -> CoreResult<()> {
    docker(&["pull", "--", image], 900).await?;
    Ok(())
}

pub fn container_args(spec: &DeploySpec, name: &str, restart: &str) -> CoreResult<Vec<String>> {
    let valid_name = !spec.name.is_empty()
        && spec.name.len() <= 63
        && spec
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid_name {
        return Err(CoreError::InvalidInput(
            "app name must be 1-63 alphanumeric, '-', or '_' characters".into(),
        ));
    }
    if spec.image.is_empty() || spec.image.contains(char::is_whitespace) {
        return Err(CoreError::InvalidInput("invalid docker image".into()));
    }

    let json = serde_json::to_string(spec).map_err(|_| {
        CoreError::InvalidInput("Could not save the app's install settings.".into())
    })?;
    let mut args = vec![
        "--name".into(),
        name.into(),
        "--restart".into(),
        restart.into(),
        "--label".into(),
        format!("{SPEC_LABEL}={json}"),
    ];
    if let (Some(host), Some(container)) = (spec.host_port, spec.container_port) {
        args.extend(["-p".into(), format!("{host}:{container}")]);
    }
    args.extend(extra_run_args(spec)?);
    for (key, value) in &spec.env {
        if !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            args.extend(["-e".into(), format!("{key}={value}")]);
        }
    }
    Ok(args)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Container {
    id: String,
    name: String,
    image: String,
    mounts: Vec<Mount>,
    state: Value,
    config: Value,
    host_config: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    #[serde(rename = "Type")]
    kind: String,
    name: Option<String>,
    destination: String,
    #[serde(rename = "RW")]
    writable: bool,
}

async fn inspect_container(id: &str) -> CoreResult<Container> {
    let json = docker(
        &["container", "inspect", "--format", "{{json .}}", "--", id],
        4,
    )
    .await?;
    serde_json::from_str(&json)
        .map_err(|_| CoreError::Runtime("Could not read the app's Docker settings.".into()))
}

pub async fn remove_container(id: &str, delete_data: bool) -> CoreResult<AppActionResult> {
    if !delete_data {
        docker(&["rm", "-f", "--", id], 12).await?;
        return Ok(AppActionResult::Done);
    }

    let container = inspect_container(id).await?;
    let mut mounts: Vec<_> = container
        .mounts
        .iter()
        .filter(|mount| mount.kind == "volume")
        .filter_map(|mount| mount.name.as_deref())
        .collect();
    mounts.sort_unstable();
    mounts.dedup();
    let mut volumes = Vec::new();
    if !mounts.is_empty() {
        let mut args = vec!["volume", "inspect", "--"];
        args.extend(mounts);
        let json = docker(&args, 4).await?;
        volumes = serde_json::from_str::<Vec<Value>>(&json)
            .map_err(|_| CoreError::Runtime("Could not read the app's Docker volumes.".into()))?;
    }
    docker(&["rm", "-f", "--", &container.id], 12).await?;
    let mut args = vec!["volume", "rm", "--"];
    args.extend(
        volumes
            .iter()
            .filter(|volume| {
                volume["Labels"]
                    .get("com.docker.volume.anonymous")
                    .is_none()
            })
            .filter_map(|volume| volume["Name"].as_str()),
    );
    if args.len() > 3 {
        docker(&args, 10).await.map_err(|e| {
            CoreError::Runtime(format!("App removed. Some data could not be deleted. {e}"))
        })?;
    }
    Ok(AppActionResult::Done)
}

fn replacement_args(
    old: &Container,
    spec: &DeploySpec,
    image: &str,
    temp_name: &str,
) -> CoreResult<Option<Vec<String>>> {
    if image == old.image {
        return Ok(None);
    }

    let policy = &old.host_config["RestartPolicy"];
    let mut restart = policy["Name"].as_str().unwrap_or("no").to_string();
    if restart.is_empty() {
        restart = "no".into();
    }
    if let Some(max) = policy["MaximumRetryCount"]
        .as_u64()
        .filter(|n| *n > 0 && restart == "on-failure")
    {
        restart.push_str(&format!(":{max}"));
    }
    let mut args = vec!["create".into(), "--pull=never".into()];
    args.extend(container_args(spec, temp_name, &restart)?);
    // Also carry over volumes Docker added from the old image's VOLUME instructions.
    for mount in old.mounts.iter().filter(|m| m.kind == "volume") {
        if spec.volumes.iter().any(|v| {
            v.split_once(':')
                .is_some_and(|(_, dst)| dst == mount.destination)
        }) {
            continue;
        }
        let name = mount
            .name
            .as_deref()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| CoreError::Runtime("Could not read the app's volume name.".into()))?;
        let mode = if mount.writable { "rw" } else { "ro" };
        args.extend(["-v".into(), format!("{name}:{}:{mode}", mount.destination)]);
    }
    args.extend(["--".into(), image.into()]);
    Ok(Some(args))
}

pub async fn update_container(id: &str) -> CoreResult<AppActionResult> {
    let old = inspect_container(id).await?;
    let missing_spec =
        || CoreError::InvalidInput("This app has no saved Rackdeck install settings.".into());
    let label = old.config["Labels"][SPEC_LABEL]
        .as_str()
        .ok_or_else(missing_spec)?;
    let spec: DeploySpec = serde_json::from_str(label).map_err(|_| missing_spec())?;

    // Ignore a label inherited from an image, which can specify arbitrary host mounts.
    let image_labels = docker(
        &[
            "image",
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
            "--",
            &old.image,
        ],
        4,
    )
    .await?;
    let image_labels: Value = serde_json::from_str(&image_labels).map_err(|_| missing_spec())?;
    if image_labels[SPEC_LABEL].as_str() == Some(label) {
        return Err(missing_spec());
    }

    pull_image(&spec.image).await?;
    let image = docker(
        &["image", "inspect", "--format", "{{.Id}}", "--", &spec.image],
        4,
    )
    .await?;
    let temp_name = format!("rackdeck-next-{}", old.id);
    let Some(args) = replacement_args(&old, &spec, &image, &temp_name)? else {
        return Ok(AppActionResult::AlreadyUpToDate);
    };
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    let new_id = docker(&args, 12).await?;
    let name = old.name.trim_start_matches('/');
    let backup = format!("rackdeck-backup-{}", old.id);
    let was_running = old.state["Running"].as_bool() == Some(true);
    let swap = async {
        if was_running {
            docker(&["stop", "-t", "10", "--", &old.id], 15).await?;
        }
        docker(&["rename", "--", &old.id, &backup], 4).await?;
        docker(&["rename", "--", &new_id, name], 4).await?;
        docker(&["start", "--", &new_id], 10).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let state = inspect_container(&new_id).await?.state;
        if state["Status"].as_str() != Some("running")
            || state["Health"]["Status"].as_str() == Some("unhealthy")
        {
            return Err(CoreError::Runtime(
                "The new container stopped during startup.".into(),
            ));
        }
        Ok(())
    }
    .await;

    if let Err(error) = swap {
        let cleanup = docker(&["rm", "-f", "--", &new_id], 5).await;
        let restore = async {
            let current = inspect_container(&old.id).await?;
            if current.name != old.name {
                docker(&["rename", "--", &old.id, name], 4).await?;
            }
            if was_running && current.state["Running"].as_bool() != Some(true) {
                docker(&["start", "--", &old.id], 10).await?;
            }
            Ok::<_, CoreError>(())
        }
        .await;
        let message = match (restore, cleanup) {
            (Ok(()), Ok(_)) => format!("Update failed. The old app was restored. {error}"),
            (Ok(()), Err(e)) => format!("Update failed. The old app was restored. Docker could not remove the new container. {e}"),
            (Err(e), _) => format!("Update failed. Docker could not restore the old container ({}). {e}", old.id),
        };
        return Err(CoreError::Runtime(message));
    }
    docker(&["rm", "--", &old.id], 5).await.map_err(|e| {
        CoreError::Runtime(format!(
            "App updated. Docker could not remove the backup container. {e}"
        ))
    })?;
    Ok(AppActionResult::Updated)
}

#[derive(Default)]
pub struct UpdateChecks(Arc<Mutex<HashMap<String, ImageCheck>>>);

struct ImageCheck {
    at: Instant,
    outdated: HashSet<String>,
}

impl UpdateChecks {
    pub fn outdated_containers(&self, candidates: HashMap<String, Vec<String>>) -> HashSet<String> {
        let mut checked = self.0.lock().expect("image checks");
        let mut outdated = HashSet::new();
        let mut pending = Vec::new();
        checked.retain(|image, check| {
            check.at.elapsed() < CHECK_INTERVAL || candidates.contains_key(image)
        });
        for (image, ids) in candidates {
            if let Some(check) = checked
                .get(&image)
                .filter(|c| c.at.elapsed() < CHECK_INTERVAL)
            {
                outdated.extend(ids.into_iter().filter(|id| check.outdated.contains(id)));
            } else {
                checked.insert(
                    image.clone(),
                    ImageCheck {
                        at: Instant::now(),
                        outdated: HashSet::new(),
                    },
                );
                pending.push((image, ids));
            }
        }
        if !pending.is_empty() {
            let checks = self.0.clone();
            tokio::spawn(async move {
                for (image, ids) in pending {
                    let outdated = check_image(&image, ids).await;
                    if let Some(check) = checks.lock().expect("image checks").get_mut(&image) {
                        check.outdated = outdated;
                    }
                }
            });
        }
        outdated
    }
}

async fn check_image(image: &str, ids: Vec<String>) -> HashSet<String> {
    let mut outdated = HashSet::new();
    // Only fetch registry metadata. Missing manifests, offline registries and throttling stay quiet.
    let Ok(raw) = docker(&["manifest", "inspect", "--verbose", "--", image], 10).await else {
        return outdated;
    };
    let Ok(manifests) = serde_json::from_str::<Value>(&raw) else {
        return outdated;
    };
    for id in ids {
        let Ok(image_id) = docker(
            &["container", "inspect", "--format", "{{.Image}}", "--", &id],
            4,
        )
        .await
        else {
            continue;
        };
        let Ok(platform) = docker(
            &[
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}",
                "--",
                &image_id,
            ],
            4,
        )
        .await
        else {
            continue;
        };
        if remote_image_id(&manifests, &platform).is_some_and(|remote| remote != image_id) {
            outdated.insert(id);
        }
    }
    outdated
}

fn remote_image_id<'a>(manifests: &'a Value, platform: &str) -> Option<&'a str> {
    let (os, arch) = platform.split_once('/')?;
    let entries = manifests
        .as_array()
        .map_or(std::slice::from_ref(manifests), Vec::as_slice);
    let mut matching = entries.iter().filter(|entry| {
        let p = entry
            .pointer("/Descriptor/platform")
            .unwrap_or(&entry["Platform"]);
        p["os"].as_str() == Some(os) && p["architecture"].as_str() == Some(arch)
    });
    let entry = matching.next()?;
    if matching.next().is_some() {
        return None; // Multiple variants of this architecture. Leave the dot off.
    }
    entry
        .pointer("/SchemaV2Manifest/config/digest")
        .or_else(|| entry.pointer("/OCIManifest/config/digest"))?
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn saved_spec_preserves_settings_when_recreating() {
        let spec: DeploySpec = serde_json::from_value(json!({
            "name": "media", "image": "example/media:stable",
            "hostPort": 8080, "containerPort": 80, "ports": ["53:53/udp"],
            "volumes": ["media-data:/data", "/srv/movies:/movies"],
            "env": { "SETTING": "text\twith\nwhitespace" }, "gpu": true
        }))
        .unwrap();
        let install = container_args(&spec, "media", "unless-stopped").unwrap();
        let label = install[install.iter().position(|arg| arg == "--label").unwrap() + 1]
            .strip_prefix("dev.rackdeck.spec=")
            .unwrap();
        assert_eq!(serde_json::from_str::<DeploySpec>(label).unwrap(), spec);

        let old: Container = serde_json::from_value(json!({
            "Id": "old", "Name": "/media", "Image": "sha256:old",
            "Mounts": [
                { "Type": "volume", "Name": "media-data", "Destination": "/data", "RW": true },
                { "Type": "bind", "Source": "/srv/movies", "Destination": "/movies", "RW": true },
                { "Type": "volume", "Name": "anonymous", "Destination": "/cache", "RW": false }
            ],
            "HostConfig": { "RestartPolicy": { "Name": "on-failure", "MaximumRetryCount": 3 } },
            "State": { "Running": true }, "Config": { "Labels": { (SPEC_LABEL): label } }
        }))
        .unwrap();
        let recreate = replacement_args(&old, &spec, "sha256:new", "next")
            .unwrap()
            .unwrap();
        assert_eq!(
            recreate,
            [
                "create",
                "--pull=never",
                "--name",
                "next",
                "--restart",
                "on-failure:3",
                "--label",
                &format!("{SPEC_LABEL}={label}"),
                "-p",
                "8080:80",
                "-p",
                "53:53/udp",
                "-v",
                "media-data:/data",
                "-v",
                "/srv/movies:/movies",
                "--gpus",
                "all",
                "-e",
                "SETTING=text\twith\nwhitespace",
                "-v",
                "anonymous:/cache:ro",
                "--",
                "sha256:new",
            ]
        );
        assert!(replacement_args(&old, &spec, "sha256:old", "next")
            .unwrap()
            .is_none());
    }

    #[test]
    fn update_checks_compare_the_same_platform_image_config() {
        let manifests = json!([
            { "Descriptor": { "platform": { "os": "linux", "architecture": "arm64" } },
              "OCIManifest": { "config": { "digest": "sha256:arm" } } },
            { "Descriptor": { "platform": { "os": "linux", "architecture": "amd64" } },
              "SchemaV2Manifest": { "config": { "digest": "sha256:amd" } } }
        ]);
        assert_eq!(
            remote_image_id(&manifests, "linux/arm64"),
            Some("sha256:arm")
        );
        assert_eq!(
            remote_image_id(&manifests, "linux/amd64"),
            Some("sha256:amd")
        );
        assert_eq!(
            remote_image_id(&manifests[0], "linux/arm64"),
            Some("sha256:arm")
        );
        assert_eq!(remote_image_id(&manifests, "windows/amd64"), None);
    }
}
