use std::net::UdpSocket;
use std::process::Stdio;
use std::sync::Mutex;

use async_trait::async_trait;
use rackdeck_core::{
    now_unix_secs, Accelerator, AppAction, AppState, AppType, AppUsage, CoreError, CoreResult,
    DeploySpec, DockerState, HardwareSpec, ManagedApp, Node, NodeKind, NodeOps, NodeStatus,
    NvidiaGpuInfo, TelemetrySample,
};
use sysinfo::{Disks, Networks, System};
use tokio::process::Command;

pub struct LocalNodeAdapter {
    node_id: String,
    callsign: String,
    port: u16,
    sys: Mutex<System>,
    disks: Mutex<Disks>,
    networks: Mutex<Networks>,
}

impl LocalNodeAdapter {
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
            connect_slug: Some(self.callsign.to_lowercase()),
            connect_enabled: false,
        })
    }

    async fn list_apps(&self) -> CoreResult<Vec<ManagedApp>> {
        let mut apps = Vec::new();

        // 1. Docker containers
        if let Some(out) = run_cmd(
            "docker",
            &[
                "ps",
                "-a",
                "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}",
            ],
        )
        .await
        {
            for line in out.lines().filter(|l| !l.trim().is_empty()) {
                let cols: Vec<&str> = line.split('\t').collect();
                if cols.len() >= 4 {
                    let state = match cols[3] {
                        "running" => AppState::Running,
                        "restarting" => AppState::Starting,
                        _ => AppState::Stopped,
                    };
                    apps.push(ManagedApp {
                        id: format!("docker:{}", cols[0]),
                        node_id: self.node_id.clone(),
                        name: cols[1].to_string(),
                        app_type: AppType::Docker,
                        runner: None,
                        image: Some(cols[2].to_string()),
                        model: None,
                        state,
                        ports: vec![],
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

        // 2. Native local AI runners (ninfer, mlx_lm, vllm, ollama)
        if let Some(ps_out) = run_cmd("ps", &["-eo", "pid,args"]).await {
            let checks = [
                ("ninfer", "ninfer"),
                ("mlx_lm.server", "mlx"),
                ("vllm", "vllm"),
                ("ollama serve", "ollama"),
            ];
            for (needle, runner) in checks {
                if ps_out.lines().any(|l| l.contains(needle)) {
                    apps.push(ManagedApp {
                        id: format!("ai:{runner}"),
                        node_id: self.node_id.clone(),
                        name: runner.to_string(),
                        app_type: AppType::Ai,
                        runner: Some(runner.to_string()),
                        image: None,
                        model: Some("local model".into()),
                        state: AppState::Running,
                        ports: vec![8080],
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

    async fn app_action(&self, app_id: &str, action: AppAction) -> CoreResult<()> {
        if let Some(container_id) = app_id.strip_prefix("docker:") {
            let subcmd = match action {
                AppAction::Start => "start",
                AppAction::Stop => "stop",
                AppAction::Restart => "restart",
            };
            run_cmd("docker", &[subcmd, container_id])
                .await
                .ok_or_else(|| CoreError::Runtime(format!("docker {subcmd} {container_id} failed")))?;
            return Ok(());
        }
        Err(CoreError::InvalidInput(format!(
            "action {action:?} is only supported on docker containers in v0.1 (got {app_id})"
        )))
    }

    async fn deploy_app(&self, spec: DeploySpec) -> CoreResult<ManagedApp> {
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
        if spec.image.trim().is_empty() || spec.image.contains(char::is_whitespace) {
            return Err(CoreError::InvalidInput("invalid docker image".into()));
        }

        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            spec.name.clone(),
            "--restart".into(),
            "unless-stopped".into(),
        ];
        if let (Some(hp), Some(cp)) = (spec.host_port, spec.container_port) {
            args.push("-p".into());
            args.push(format!("{hp}:{cp}"));
        }
        args.extend(extra_run_args(&spec)?);
        for (k, v) in &spec.env {
            if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                args.push("-e".into());
                args.push(format!("{k}={v}"));
            }
        }
        args.push(spec.image.clone());

        // Pull first with a long timeout: AI images are several GB. `docker run` then starts quickly.
        let pull = tokio::time::timeout(
            std::time::Duration::from_secs(900),
            Command::new("docker").args(["pull", &spec.image]).stdout(Stdio::null()).stderr(Stdio::piped()).output(),
        )
        .await
        .map_err(|_| CoreError::Runtime("downloading the image took over 15 minutes".into()))?
        .map_err(|e| CoreError::Runtime(format!("docker unavailable: {e}")))?;
        if !pull.status.success() {
            return Err(CoreError::Runtime(String::from_utf8_lossy(&pull.stderr).trim().to_string()));
        }

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Command::new("docker")
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .map_err(|_| CoreError::Runtime("docker run timed out".into()))?
        .map_err(|e| CoreError::Runtime(format!("docker unavailable: {e}")))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(CoreError::Runtime(if err_msg.is_empty() {
                "docker run failed".into()
            } else {
                err_msg
            }));
        }

        let id_short: String = String::from_utf8_lossy(&output.stdout)
            .trim()
            .chars()
            .take(12)
            .collect();

        Ok(ManagedApp {
            id: format!("docker:{id_short}"),
            node_id: self.node_id.clone(),
            name: spec.name,
            app_type: AppType::Docker,
            runner: None,
            image: Some(spec.image),
            model: None,
            state: AppState::Running,
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
            let out = run_cmd("docker", &["logs", "--tail", &n, container_id])
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
