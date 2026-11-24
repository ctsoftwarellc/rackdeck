use std::collections::HashMap;
use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::Mutex;

use async_trait::async_trait;
use rackdeck_core::{
    now_unix_secs, Accelerator, AppAction, AppActionResult, AppState, AppType, AppUsage, CoreError, CoreResult,
    DeploySpec, DockerState, HardwareSpec, ManagedApp, Node, NodeKind, NodeOps, NodeStatus,
    NvidiaGpuInfo, TelemetrySample,
};
use sysinfo::{Disks, Networks, System};
use tokio::process::Command;

mod docker_apps;
use docker_apps::{
    anonymous_volumes, container_args, container_details, docker, pull_image, remove_container,
    require_new_volume, update_container, UpdateChecks,
};

pub struct LocalNodeAdapter {
    node_id: String,
    callsign: String,
    port: u16,
    sys: Mutex<System>,
    disks: Mutex<Disks>,
    networks: Mutex<Networks>,
    app_operation: tokio::sync::Mutex<()>,
    update_checks: UpdateChecks,
}

impl LocalNodeAdapter {
    pub fn try_app_operation(&self) -> CoreResult<tokio::sync::MutexGuard<'_, ()>> {
        self.app_operation.try_lock().map_err(|_| {
            CoreError::Runtime(
                "Another app change is in progress on this machine. Try again when it finishes."
                    .into(),
            )
        })
    }

    pub fn new(port: u16) -> Self {
        let host = System::host_name().unwrap_or_else(|| "rackdeck-node".into());
        let slug: String = host
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        // Display name only; node_id (from `slug`) stays tied to the raw hostname so existing fleets keep their ids.
        let callsign: String = display_host_name(&host)
            .to_uppercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(24)
            .collect();

        let mut sys = System::new_all();
        sys.refresh_all();
        let disks = Disks::new_with_refreshed_list();
        let networks = Networks::new_with_refreshed_list();

        Self {
            node_id: format!("node-{slug}"),
            callsign: if callsign.is_empty() {
                "LOCAL-NODE".into()
            } else {
                callsign
            },
            port,
            sys: Mutex::new(sys),
            disks: Mutex::new(disks),
            networks: Mutex::new(networks),
            app_operation: Default::default(),
            update_checks: Default::default(),
        }
    }

    /// Use a persisted id instead of the hostname-derived one (agents, so same-named hosts don't collide).
    pub fn with_node_id(mut self, id: String) -> Self {
        self.node_id = id;
        self
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn callsign(&self) -> &str {
        &self.callsign
    }
}

/// Friendly machine name: the macOS Computer Name ("Caleb's MacBook Pro") when available,
/// otherwise the hostname without DHCP/mDNS suffixes like `.attlocal.net` or `.local`.
fn display_host_name(host: &str) -> String {
    if cfg!(target_os = "macos") {
        if let Ok(out) = std::process::Command::new("scutil").args(["--get", "ComputerName"]).output() {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() && !name.is_empty() {
                return name;
            }
        }
    }
    strip_domain(host)
}

fn strip_domain(host: &str) -> String {
    host.split('.').next().unwrap_or(host).to_string()
}

async fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// A model server in one `ps -eo pid,args` line: (runner, port). Looks at the program itself, not
/// any word in the line, so an editor or grep mentioning "ninfer" doesn't count.
fn detect_ai_runner(line: &str) -> Option<(&'static str, u16)> {
    let args: Vec<&str> = line.split_whitespace().skip(1).collect();
    let exe = args.first()?.rsplit('/').next()?;
    let has = |t: &str| args.iter().any(|a| *a == t);
    let (runner, default_port) = if exe.starts_with("ninfer") {
        ("ninfer", 8080)
    } else if exe == "ollama" && has("serve") {
        ("ollama", 11434)
    } else if (exe == "vllm" && has("serve")) || args.iter().any(|a| a.starts_with("vllm.entrypoints")) {
        ("vllm", 8000)
    } else if exe.starts_with("mlx_lm.server") || has("mlx_lm.server") {
        ("mlx", 8080)
    } else {
        return None;
    };
    let port = args
        .iter()
        .enumerate()
        .find_map(|(i, a)| a.strip_prefix("--port=").or((*a == "--port").then(|| args.get(i + 1).copied()).flatten()))
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    Some((runner, port))
}

/// Checks before installing anything, so a bad install fails with a plain reason instead of
/// breaking the machine: Docker is up, the ports are free, and a new download leaves room on disk.
async fn preflight(spec: &DeploySpec) -> Result<(), CoreError> {
    if run_cmd("docker", &["info", "--format", "{{.ServerVersion}}"]).await.is_none() {
        return Err(CoreError::Runtime(if cfg!(target_os = "macos") {
            "Docker isn't running on this machine. Install or open Docker Desktop or OrbStack, then try again.".into()
        } else {
            "Docker isn't running on this machine. Start it (sudo systemctl start docker), then try again.".into()
        }));
    }
    let mut maps: Vec<String> = spec.ports.clone();
    if let Some(hp) = spec.host_port {
        maps.push(format!("{hp}:0"));
    }
    for m in &maps {
        let (map, proto) = m.split_once('/').unwrap_or((m.as_str(), "tcp"));
        let Some(port) = map.split(':').next().and_then(|p| p.parse::<u16>().ok()) else { continue };
        // Only "in use" counts; a permission error on a low port just means Docker binds it instead of us.
        let in_use = |e: std::io::Error| e.kind() == std::io::ErrorKind::AddrInUse;
        let free = if proto == "udp" {
            std::net::UdpSocket::bind(("0.0.0.0", port)).map(|_| ()).map_or_else(|e| !in_use(e), |_| true)
        } else {
            std::net::TcpListener::bind(("0.0.0.0", port)).map(|_| ()).map_or_else(|e| !in_use(e), |_| true)
        };
        if !free {
            return Err(CoreError::InvalidInput(format!(
                "port {port} is already in use on this machine, so the app couldn't use it"
            )));
        }
    }
    // Only a new download needs space; an image already on the machine doesn't.
    if run_cmd("docker", &["image", "inspect", "--", &spec.image])
        .await
        .is_none()
    {
        // ponytail: checks the host's / (Docker's usual home on Linux); Docker Desktop's VM disk isn't seen.
        let free_gb = run_cmd("df", &["-Pk", "/"])
            .await
            .and_then(|out| out.lines().nth(1)?.split_whitespace().nth(3)?.parse::<u64>().ok())
            .map(|kb| kb / 1024 / 1024);
        if let Some(gb) = free_gb.filter(|gb| *gb < 10) {
            return Err(CoreError::Runtime(format!(
                "only {gb} GB free on this machine. Rackdeck needs 10 GB free before downloading a new app."
            )));
        }
    }
    Ok(())
}

/// `docker run` flags for a spec's extra ports, volumes and GPU. Rejects anything malformed.
fn extra_run_args(spec: &DeploySpec) -> Result<Vec<String>, CoreError> {
    let mut args: Vec<String> = Vec::new();
    for p in &spec.ports {
        let (map, proto) = p.split_once('/').unwrap_or((p.as_str(), "tcp"));
        let ok = matches!(proto, "tcp" | "udp")
            && map.split_once(':').is_some_and(|(h, c)| h.parse::<u16>().is_ok() && c.parse::<u16>().is_ok());
        if !ok {
            return Err(CoreError::InvalidInput(format!("bad port map `{p}`")));
        }
        args.push("-p".into());
        args.push(p.clone());
    }
    for v in &spec.volumes {
        let ok = v.split_once(':').is_some_and(|(src, dst)| {
            dst.starts_with('/')
                && !dst.contains(':')
                && (src.starts_with('/')
                    || (!src.is_empty() && src.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))))
        });
        if !ok {
            return Err(CoreError::InvalidInput(format!("bad volume `{v}`")));
        }
        args.push("-v".into());
        args.push(v.clone());
    }
    if spec.gpu {
        args.push("--gpus".into());
        args.push("all".into());
    }
    Ok(args)
}

fn detect_lan_ip() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

async fn detect_nvidia() -> Option<(Vec<NvidiaGpuInfo>, Vec<f32>, Vec<u64>, Option<f32>)> {
    let out = run_cmd(
        "nvidia-smi",
        &[
            "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ],
    )
    .await?;
    let mut infos = Vec::new();
    let mut utils = Vec::new();
    let mut vrams = Vec::new();
    let mut max_temp: Option<f32> = None;

    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if cols.len() >= 5 {
            let idx = cols[0].parse().unwrap_or(0);
            let name = cols[1].to_string();
            let util = cols[2].parse().unwrap_or(0.0);
            let used = cols[3].parse().unwrap_or(0);
            let total = cols[4].parse().unwrap_or(0);
            let temp = cols.get(5).and_then(|s| s.parse::<f32>().ok());
            if let Some(t) = temp {
                max_temp = Some(max_temp.map_or(t, |m| m.max(t)));
            }
            infos.push(NvidiaGpuInfo {
                idx,
                name,
                vram_total_mb: total,
            });
            utils.push(util);
            vrams.push(used);
        }
    }
    if infos.is_empty() {
        None
    } else {
        Some((infos, utils, vrams, max_temp))
    }
}

async fn detect_docker_state() -> DockerState {
    if run_cmd("docker", &["info", "--format", "{{.ServerVersion}}"])
        .await
        .is_some()
    {
        return DockerState::Running;
    }
    if run_cmd("which", &["docker"]).await.is_some() {
        DockerState::Stopped
    } else {
        DockerState::Absent
    }
}

#[async_trait]
impl NodeOps for LocalNodeAdapter {
    async fn sample(&self) -> CoreResult<TelemetrySample> {
        let (cpu, mem_mb, disk_gb, net_rx, net_tx) = {
            let mut sys = self.sys.lock().map_err(|e| CoreError::Runtime(e.to_string()))?;
            sys.refresh_cpu_usage();
            sys.refresh_memory();
            let cpu = sys.global_cpu_usage();
            let mem_mb = sys.used_memory() / (1024 * 1024);

            let mut disks = self
                .disks
                .lock()
                .map_err(|e| CoreError::Runtime(e.to_string()))?;
            disks.refresh(false);
            let root_disk = disks
                .iter()
                .find(|d| d.mount_point().to_string_lossy() == "/")
                .or_else(|| disks.first());
            let disk_gb = root_disk
                .map(|d| (d.total_space().saturating_sub(d.available_space())) / (1024 * 1024 * 1024))
                .unwrap_or(0);

            let mut nets = self
                .networks
                .lock()
                .map_err(|e| CoreError::Runtime(e.to_string()))?;
            nets.refresh(false);
            let (rx, tx) = nets
                .iter()
                .fold((0u64, 0u64), |(r, t), (_, n)| (r + n.received(), t + n.transmitted()));

            (cpu, mem_mb, disk_gb, rx, tx)
        };

        let nv = detect_nvidia().await;
        let (gpu, vram_mb, temp_c) = match nv {
            Some((_, utils, vrams, temp)) => (Some(utils), Some(vrams), temp),
            None => (None, None, None),
        };

        Ok(TelemetrySample {
            t: now_unix_secs(),
            cpu: (cpu * 10.0).round() / 10.0,
            mem_mb,
            disk_gb,
            net_rx_bps: net_rx,
            net_tx_bps: net_tx,
            gpu,
            vram_mb,
            temp_c,
        })
    }

    async fn inspect_node(&self) -> CoreResult<Node> {
        let (cores, ram_total_mb, disk_total_gb, uptime_secs, os_str, kernel) = {
            let mut sys = self.sys.lock().map_err(|e| CoreError::Runtime(e.to_string()))?;
            sys.refresh_memory();
            let cores = sys.cpus().len().max(1) as u32;
            let ram_total_mb = sys.total_memory() / (1024 * 1024);

            let disks = self
                .disks
                .lock()
                .map_err(|e| CoreError::Runtime(e.to_string()))?;
            let disk_total_gb = disks
                .iter()
                .find(|d| d.mount_point().to_string_lossy() == "/")
                .or_else(|| disks.first())
                .map(|d| d.total_space() / (1024 * 1024 * 1024))
                .unwrap_or(0);

            let os_name = System::name().unwrap_or_else(|| std::env::consts::OS.to_string());
            let os_ver = System::os_version().unwrap_or_default();
            let os_str = if os_ver.is_empty() {
                os_name
            } else {
                format!("{os_name} {os_ver}")
            };

            (
                cores,
                ram_total_mb,
                disk_total_gb,
                System::uptime(),
                os_str,
                System::kernel_version(),
            )
        };

        let nv = detect_nvidia().await;
        let (kind, accel) = if let Some((gpus, _, _, _)) = nv {
            (
                NodeKind::Gpu,
                Accelerator::Nvidia {
                    gpus,
                    driver: None,
                    driver_loaded: true,
                },
            )
        } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            let chip = run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"])
                .await
                .unwrap_or_else(|| "Apple Silicon".into());
            (
                NodeKind::Mac,
                Accelerator::Apple {
                    chip,
                    unified_total_mb: ram_total_mb,
                    ane: true,
                },
            )
        } else {
            (NodeKind::Vps, Accelerator::None)
        };

        let docker = detect_docker_state().await;
        let tailscale_ip = run_cmd("tailscale", &["ip", "-4"])
            .await
            .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
            .filter(|s| !s.is_empty());

        Ok(Node {
            id: self.node_id.clone(),
            name: self.callsign.clone(),
            kind,
            os: os_str,
            kernel,
            status: NodeStatus::Online,
            last_seen: now_unix_secs(),
            uptime_secs,
            hw: HardwareSpec {
                cpu_cores: cores,
                ram_total_mb,
                disk_total_gb,
                accel,
            },
            docker,
            version: env!("CARGO_PKG_VERSION").to_string(),
            lan_ip: detect_lan_ip(),
            tailscale_ip,
            connect_slug: None,
            connect_enabled: false,
        })
    }

    async fn list_apps(&self) -> CoreResult<Vec<ManagedApp>> {
        let mut apps = Vec::new();
        let mut update_candidates = HashMap::<String, Vec<String>>::new();

        // 1. Docker containers
        if let Some(out) = run_cmd(
            "docker",
            &[
                "ps",
                "-a",
                "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{json (.Label \"dev.rackdeck.spec\")}}",
            ],
        )
        .await
        {
            for line in out.lines().filter(|l| !l.trim().is_empty()) {
                let cols: Vec<&str> = line.splitn(5, '\t').collect();
                if cols.len() >= 4 {
                    let state = match cols[3] {
                        "running" => AppState::Running,
                        "restarting" => AppState::Starting,
                        _ => AppState::Stopped,
                    };
                    let spec = cols.get(4)
                        .and_then(|label| serde_json::from_str::<String>(label).ok())
                        .and_then(|label| serde_json::from_str::<DeploySpec>(&label).ok());
                    if let Some(spec) = &spec {
                        update_candidates.entry(spec.image.clone()).or_default().push(cols[0].into());
                    }
                    apps.push(ManagedApp {
                        id: format!("docker:{}", cols[0]),
                        node_id: self.node_id.clone(),
                        name: cols[1].to_string(),
                        app_type: AppType::Docker,
                        runner: None,
                        image: Some(spec.as_ref().map_or(cols[2], |spec| &spec.image).to_string()),
                        model: None,
                        state,
                        can_update: Some(spec.is_some()),
                        update_available: false,
                        storage: None,
                        ports: spec.and_then(|spec| spec.host_port).into_iter().collect(),
                        domains: vec![],
                        usage: AppUsage {
                            cpu: 0.0,
                            mem_mb: 0,
                            vram_mb: None,
                            tps: None,
                        },
                    });
                }
            }
        }
        let ids: Vec<_> = apps
            .iter()
            .filter_map(|app| app.id.strip_prefix("docker:"))
            .collect();
        if !ids.is_empty() {
            let (details, anonymous) = tokio::join!(container_details(&ids), anonymous_volumes());
            let outdated = self
                .update_checks
                .outdated_containers(update_candidates, &details)
                .await;
            for app in &mut apps {
                if let Some(id) = app.id.strip_prefix("docker:") {
                    app.update_available = outdated.contains(id);
                    app.storage = details
                        .get(id)
                        .and_then(|info| info.storage(anonymous.as_ref()));
                }
            }
        }

        // 2. Native local AI runners (ninfer, mlx_lm, vllm, ollama)
        if let Some(ps_out) = run_cmd("ps", &["-eo", "pid,args"]).await {
            let mut seen: Vec<&str> = Vec::new();
            for line in ps_out.lines().skip(1) {
                let Some((runner, port)) = detect_ai_runner(line) else { continue };
                if seen.contains(&runner) {
                    continue;
                }
                seen.push(runner);
                {
                    apps.push(ManagedApp {
                        id: format!("ai:{runner}"),
                        node_id: self.node_id.clone(),
                        name: runner.to_string(),
                        app_type: AppType::Ai,
                        runner: Some(runner.to_string()),
                        image: None,
                        model: Some("local model".into()),
                        state: AppState::Running,
                        can_update: None,
                        update_available: false,
                        storage: None,
                        ports: vec![port],
                        domains: vec![],
                        usage: AppUsage {
                            cpu: 0.0,
                            mem_mb: 0,
                            vram_mb: None,
                            tps: None,
                        },
                    });
                }
            }
        }

        // Always report rackdeck control plane itself
        apps.insert(
            0,
            ManagedApp {
                id: "system:rackdeck".into(),
                node_id: self.node_id.clone(),
                name: "rackdeck".into(),
                app_type: AppType::System,
                runner: Some("rust-native".into()),
                image: Some(format!("rackdeck v{}", env!("CARGO_PKG_VERSION"))),
                model: None,
                state: AppState::Running,
                can_update: None,
                update_available: false,
                storage: None,
                ports: vec![self.port],
                domains: vec![],
                usage: AppUsage {
                    cpu: 0.2,
                    mem_mb: 16,
                    vram_mb: None,
                    tps: None,
                },
            },
        );

        Ok(apps)
    }

    async fn app_action(&self, app_id: &str, action: AppAction) -> CoreResult<AppActionResult> {
        let container_id = app_id.strip_prefix("docker:").filter(|id| !id.is_empty())
            .ok_or_else(|| CoreError::InvalidInput("This action is only available for Docker apps.".into()))?;
        let _guard = self.try_app_operation()?;
        let subcmd = match action {
            AppAction::Start => "start",
            AppAction::Stop => "stop",
            AppAction::Restart => "restart",
            AppAction::Remove { delete_data } => return remove_container(container_id, delete_data).await,
            AppAction::Update => return update_container(container_id).await,
        };
        run_cmd("docker", &[subcmd, "--", container_id])
            .await
            .ok_or_else(|| CoreError::Runtime(format!("docker {subcmd} {container_id} failed")))?;
        Ok(AppActionResult::Done)
    }

    async fn deploy_app(&self, spec: DeploySpec, fresh_volumes: bool) -> CoreResult<ManagedApp> {
        let mut args = vec!["run".into(), "-d".into()];
        args.extend(container_args(&spec, &spec.name, "unless-stopped")?);
        args.extend(["--".into(), spec.image.clone()]);
        let args: Vec<_> = args.iter().map(String::as_str).collect();

        let _guard = self.try_app_operation()?;
        preflight(&spec).await?;
        pull_image(&spec.image).await?;
        if fresh_volumes {
            for mount in &spec.volumes {
                let (name, _) = mount.split_once(':').expect("validated volume");
                require_new_volume(name, docker(&["volume", "inspect", "--", name], 4).await)?;
            }
        }
        let id_short: String = docker(&args, 60).await?.chars().take(12).collect();
        let ids = [&*id_short];
        let (details, anonymous) = tokio::join!(container_details(&ids), anonymous_volumes());
        let storage = details
            .get(&id_short)
            .and_then(|info| info.storage(anonymous.as_ref()));

        Ok(ManagedApp {
            id: format!("docker:{id_short}"),
            node_id: self.node_id.clone(),
            name: spec.name,
            app_type: AppType::Docker,
            runner: None,
            image: Some(spec.image),
            model: None,
            state: AppState::Running,
            can_update: Some(true),
            update_available: false,
            storage,
            ports: spec.host_port.into_iter().collect(),
            domains: vec![],
            usage: AppUsage {
                cpu: 0.0,
                mem_mb: 0,
                vram_mb: None,
                tps: None,
            },
        })
    }

    async fn tail_logs(&self, app_id: &str, lines: usize) -> CoreResult<Vec<String>> {
        if let Some(container_id) = app_id.strip_prefix("docker:") {
            let n = lines.to_string();
            let out = run_cmd("docker", &["logs", "--tail", &n, "--", container_id])
                .await
                .unwrap_or_default();
            return Ok(out.lines().map(|s| s.to_string()).collect());
        }
        Ok(vec![
            format!("[rackdeck] node {} ({}) healthy", self.callsign, self.node_id),
            format!("[rackdeck] listening on :{}", self.port),
            format!("[rackdeck] telemetry sampler active @ 1Hz"),
        ])
    }
}

#[cfg(test)]
mod name_tests {
    #[test]
    fn strips_dhcp_suffixes() {
        assert_eq!(super::strip_domain("mac.attlocal.net"), "mac");
        assert_eq!(super::strip_domain("CALEB-PC"), "CALEB-PC");
    }
}

#[cfg(test)]
mod deploy_args_tests {
    use super::*;

    #[test]
    fn ai_runners() {
        assert_eq!(detect_ai_runner("12 /opt/ninfer/ninfer --model q --port 9000"), Some(("ninfer", 9000)));
        assert_eq!(detect_ai_runner("12 ollama serve"), Some(("ollama", 11434)));
        assert_eq!(detect_ai_runner("12 python -m vllm.entrypoints.openai.api_server --port=8001"), Some(("vllm", 8001)));
        assert_eq!(detect_ai_runner("12 python -m mlx_lm.server"), Some(("mlx", 8080)));
        assert_eq!(detect_ai_runner("12 ugrep -i ninfer"), None);
        assert_eq!(detect_ai_runner("12 vim /src/ninfer/main.rs"), None);
        assert_eq!(detect_ai_runner("12 ollama run llama3"), None);
    }

    #[test]
    fn ports_volumes_gpu() {
        let mut spec = DeploySpec {
            name: "a".into(),
            image: "x".into(),
            host_port: None,
            container_port: None,
            env: Default::default(),
            ports: vec![],
            volumes: vec![],
            gpu: false,
        };
        spec.ports = vec!["53:53/udp".into(), "3000:3000".into()];
        spec.volumes = vec!["adguard-conf:/opt/adguardhome/conf".into(), "/srv/media:/media".into()];
        spec.gpu = true;
        let args = extra_run_args(&spec).unwrap();
        assert_eq!(args.iter().filter(|a| *a == "-p").count(), 2);
        assert!(args.ends_with(&["--gpus".into(), "all".into()]));
        for bad in ["53:53/sctp", "x:1", "1"] {
            spec.ports = vec![bad.into()];
            assert!(extra_run_args(&spec).is_err(), "{bad}");
        }
        spec.ports.clear();
        for bad in ["vol:relative", "bad name:/x", ":/x", "/a:/b:/c"] {
            spec.volumes = vec![bad.into()];
            assert!(extra_run_args(&spec).is_err(), "{bad}");
        }
    }
}
