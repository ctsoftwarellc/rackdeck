use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rackdeck_core::{AppActionResult, AppStorage, CoreError, CoreResult, DeploySpec};
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

fn volume_missing(message: &str, name: &str) -> bool {
    message == format!("Error response from daemon: get {name}: no such volume")
}

pub fn require_new_volume(name: &str, inspected: CoreResult<String>) -> CoreResult<()> {
    if name.starts_with('/') {
        return Err(CoreError::Forbidden(
            "Only the owner can link a folder from the machine.".into(),
        ));
    }
    match inspected {
        Ok(_) => Err(CoreError::Forbidden(format!(
            "Storage {name} already exists. Choose a new volume name."
        ))),
        Err(CoreError::Runtime(message)) if volume_missing(&message, name) => Ok(()),
        Err(e) => Err(e),
    }
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
    #[serde(default)]
    restart_count: u64,
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
        docker(&["stop", "-t", "10", "--", id], 15).await?;
        docker(&["rm", "--", id], 12).await?;
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
    docker(&["rm", "-fv", "--", &container.id], 12).await?;
    if !mounts.is_empty() {
        // A replacement may have reattached an anonymous volume by its generated name.
        let mut args = vec!["volume", "rm", "--"];
        args.extend(mounts.iter().copied());
        match docker(&args, 10).await {
            Ok(_) => {}
            Err(CoreError::Runtime(message)) if message.lines().all(|line| {
                mounts.iter().any(|name| {
                    volume_missing(line, name) || line == format!("Error response from daemon: remove {name}: no such volume")
                })
            }) => {}
            Err(e) => return Err(CoreError::Runtime(format!("App removed. Some data could not be deleted. {e}"))),
        }
    }
    Ok(AppActionResult::Done)
}

fn mount_destination(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/"
    } else {
        trimmed
    }
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
            v.split_once(':').is_some_and(|(_, dst)| {
                mount_destination(dst) == mount_destination(&mount.destination)
            })
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

async fn wait_for_replacement(id: &str) -> CoreResult<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let started = Instant::now();
        loop {
            let container = inspect_container(id).await?;
            let running = container.state["Status"].as_str() == Some("running");
            let healthcheck = container.config["Healthcheck"]["Test"]
                .get(0)
                .and_then(Value::as_str)
                .is_some_and(|test| test != "NONE");
            if healthcheck {
                if running && container.state["Health"]["Status"].as_str() == Some("healthy") {
                    return Ok(());
                }
            } else {
                if !running || container.restart_count > 0 {
                    return Err(CoreError::Runtime("The new app stopped or restarted during startup.".into()));
                }
                if started.elapsed() >= Duration::from_secs(10) {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| {
        CoreError::Runtime("The new app did not pass its startup check within 60 seconds.".into())
    })?
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
        wait_for_replacement(&new_id).await
    }
    .await;

    if let Err(error) = swap {
        let cleanup = docker(&["rm", "-fv", "--", &new_id], 5).await;
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

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerDetails {
    id: String,
    image: String,
    mounts: Vec<Mount>,
}

pub async fn container_details(ids: &[&str]) -> HashMap<String, ContainerDetails> {
    if ids.is_empty() {
        return HashMap::new();
    }
    let mut args = vec![
        "container",
        "inspect",
        "--format",
        r#"{"Id":{{json .Id}},"Image":{{json .Image}},"Mounts":{{json .Mounts}}}"#,
        "--",
    ];
    args.extend_from_slice(ids);
    let Ok(output) = docker(&args, 4).await else {
        return HashMap::new();
    };
    output
        .lines()
        .filter_map(|line| {
            let details: ContainerDetails = serde_json::from_str(line).ok()?;
            Some((details.id.chars().take(12).collect(), details))
        })
        .collect()
}

pub async fn anonymous_volumes() -> Option<HashSet<String>> {
    let out = docker(
        &[
            "volume",
            "ls",
            "--filter",
            "label=com.docker.volume.anonymous",
            "--format",
            "{{.Name}}",
        ],
        4,
    )
    .await
    .ok()?;
    Some(out.lines().map(str::to_string).collect())
}

impl ContainerDetails {
    pub fn storage(&self, anonymous: Option<&HashSet<String>>) -> Option<AppStorage> {
        let mut storage = AppStorage {
            named_volumes: Vec::new(),
            has_anonymous_volumes: false,
            has_folders: false,
        };
        for mount in &self.mounts {
            match mount.kind.as_str() {
                "bind" => storage.has_folders = true,
                "volume" => {
                    let name = mount.name.as_ref()?;
                    if anonymous?.contains(name) {
                        storage.has_anonymous_volumes = true;
                    } else {
                        storage.named_volumes.push(name.clone());
                    }
                }
                _ => {}
            }
        }
        storage.named_volumes.sort_unstable();
        storage.named_volumes.dedup();
        Some(storage)
    }
}

#[derive(Default)]
pub struct UpdateChecks(Arc<Mutex<HashMap<String, ImageCheck>>>);

struct ImageCheck {
    at: Instant,
    manifests: Option<Arc<Value>>,
}

impl UpdateChecks {
    pub async fn outdated_containers(
        &self,
        candidates: HashMap<String, Vec<String>>,
        containers: &HashMap<String, ContainerDetails>,
    ) -> HashSet<String> {
        let mut ready = Vec::new();
        let mut pending = Vec::new();
        {
            let mut checked = self.0.lock().expect("image checks");
            checked.retain(|image, check| {
                check.at.elapsed() < CHECK_INTERVAL || candidates.contains_key(image)
            });
            for (image, ids) in candidates {
                if let Some(check) = checked
                    .get(&image)
                    .filter(|c| c.at.elapsed() < CHECK_INTERVAL)
                {
                    if let Some(manifests) = &check.manifests {
                        ready.push((manifests.clone(), ids));
                    }
                } else {
                    checked.insert(
                        image.clone(),
                        ImageCheck {
                            at: Instant::now(),
                            manifests: None,
                        },
                    );
                    pending.push(image);
                }
            }
        }
        if !pending.is_empty() {
            let checks = self.0.clone();
            tokio::spawn(async move {
                for image in pending {
                    // Only fetch registry metadata. Missing manifests and throttling stay quiet.
                    let manifests = docker(&["manifest", "inspect", "--verbose", "--", &image], 10)
                        .await
                        .ok()
                        .and_then(|raw| serde_json::from_str(&raw).ok())
                        .map(Arc::new);
                    if let Some(check) = checks.lock().expect("image checks").get_mut(&image) {
                        check.manifests = manifests;
                    }
                }
            });
        }

        let mut outdated = HashSet::new();
        let images: HashSet<_> = ready
            .iter()
            .flat_map(|(_, ids)| ids)
            .filter_map(|id| containers.get(id).map(|c| c.image.as_str()))
            .collect();
        if images.is_empty() {
            return outdated;
        }
        let mut args = vec![
            "image",
            "inspect",
            "--format",
            "{{.Id}} {{.Os}}/{{.Architecture}} {{json .RepoDigests}}",
            "--",
        ];
        args.extend(images.iter().copied());
        let Ok(details) = docker(&args, 4).await else {
            return outdated;
        };
        let images: HashMap<_, _> = args[5..].iter().copied().zip(details.lines()).collect();
        for (manifests, ids) in ready {
            for id in ids {
                if let Some(image_id) = containers.get(&id).map(|c| c.image.as_str()) {
                    if let Some(details) = images.get(image_id) {
                        if image_is_outdated(&manifests, image_id, details) {
                            outdated.insert(id);
                        }
                    }
                }
            }
        }
        outdated
    }
}

fn image_is_outdated(manifests: &Value, image_id: &str, details: &str) -> bool {
    let mut details = details.splitn(3, ' ');
    let (Some(config_id), Some(platform), Some(digests)) =
        (details.next(), details.next(), details.next())
    else {
        return false;
    };
    let Some(remote) = remote_manifest(manifests, platform) else {
        return false;
    };
    let Some(remote_config) = remote_config_digest(remote) else {
        return false;
    };
    if remote_config == image_id || remote_config == config_id {
        return false;
    }
    // ponytail: image IDs are unverified on Docker Desktop's containerd store, so compare RepoDigests too.
    let digest = remote.pointer("/Descriptor/digest").and_then(Value::as_str);
    let digests = serde_json::from_str::<Option<Vec<String>>>(digests)
        .ok()
        .flatten()
        .unwrap_or_default();
    !digests
        .iter()
        .any(|d| d.split_once('@').is_some_and(|(_, d)| Some(d) == digest))
}

fn remote_manifest<'a>(manifests: &'a Value, platform: &str) -> Option<&'a Value> {
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
    Some(entry)
}

fn remote_config_digest(entry: &Value) -> Option<&str> {
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
    fn token_deploys_require_a_missing_docker_volume() {
        let volume = "redis-data";
        assert!(matches!(
            require_new_volume(volume, Ok("[]".into())),
            Err(CoreError::Forbidden(_))
        ));
        assert!(require_new_volume(
            volume,
            Err(CoreError::Runtime(
                "Error response from daemon: get redis-data: no such volume".into(),
            ))
        )
        .is_ok());
        assert!(require_new_volume(
            volume,
            Err(CoreError::Runtime("Could not connect to Docker".into()))
        )
        .is_err());
    }

    #[test]
    fn saved_spec_preserves_settings_when_recreating() {
        let spec: DeploySpec = serde_json::from_value(json!({
            "name": "media", "image": "example/media:stable",
            "hostPort": 8080, "containerPort": 80, "ports": ["53:53/udp"],
            "volumes": ["media-data:/data/", "/srv/movies:/movies"],
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
                "media-data:/data/",
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
            remote_manifest(&manifests, "linux/arm64").and_then(remote_config_digest),
            Some("sha256:arm")
        );
        assert_eq!(
            remote_manifest(&manifests, "linux/amd64").and_then(remote_config_digest),
            Some("sha256:amd")
        );
        assert_eq!(
            remote_manifest(&manifests[0], "linux/arm64").and_then(remote_config_digest),
            Some("sha256:arm")
        );
        assert_eq!(
            remote_manifest(&manifests, "windows/amd64").and_then(remote_config_digest),
            None
        );
    }
}
