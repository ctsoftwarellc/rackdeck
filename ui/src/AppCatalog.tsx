import { useState, type FormEvent, type ReactNode } from "react";
import { CATALOG, type CatalogApp } from "./catalog";
import type { ManagedApp, Node } from "./types";

const categories: CatalogApp["category"][] = ["Media", "Home", "AI", "Tools"];
const modelRunners = new Set(["ninfer", "ollama", "vllm", "mlx", "mlx_lm"]);

export function dockerUnavailable(node: Node): string {
  if (node.docker === "running") return "";
  const message = "Docker isn’t running on " + node.name + ".";
  return node.kind === "mac" ? message + " Start or install Docker Desktop or OrbStack." : message;
}

function installationBlock(node?: Node): string {
  if (!node) return "";
  return dockerUnavailable(node) || (node.status === "online" ? "" : node.name + " is offline.");
}

function appUrl(node: Node, port: number): string | undefined {
  const address = node.lanIp || node.tailscaleIp;
  if (!address) return;
  return "http://" + (address.includes(":") ? "[" + address + "]" : address) + ":" + port;
}

function modelServers(apps: ManagedApp[], nodes: Node[]) {
  return apps.flatMap((app) => {
    const runner = app.runner;
    const port = app.ports[0];
    if (app.type !== "ai" || app.state !== "running" || !runner || !modelRunners.has(runner) || !port) return [];
    const node = nodes.find((item) => item.id === app.nodeId);
    const url = node && appUrl(node, port);
    if (!node || !url) return [];
    return [{ id: node.id + "/" + app.id, runner, port, nodeName: node.name, url }];
  });
}

function validModelUrl(address: string): boolean {
  try {
    const url = new URL(address);
    return (url.protocol === "http:" || url.protocol === "https:") && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function OpenApp({ node, port }: { node: Node; port: number }) {
  const url = appUrl(node, port);
  return url ? (
    <a className="btn btn-sm" href={url} target="_blank" rel="noopener noreferrer">Open</a>
  ) : (
    <a className="btn btn-sm" href={"#/machines/" + encodeURIComponent(node.id)}>Open machine</a>
  );
}

interface CatalogProps {
  nodes: Node[];
  apps: ManagedApp[];
  installedApps: ReactNode;
  onInstalled: (app: ManagedApp) => void;
  onCustomImage: () => void;
}

export function AppCatalog({ nodes, apps, installedApps, onInstalled, onCustomImage }: CatalogProps) {
  const [selected, setSelected] = useState<CatalogApp | null>(null);

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Apps</h1>
        <button type="button" className="btn" onClick={onCustomImage}>Custom image</button>
      </div>
      {installedApps}
      <div className="catalog-sections">
        {categories.map((category) => (
          <section key={category}>
            <h2 className="catalog-heading">{category}</h2>
            <div className="catalog-grid">
              {CATALOG.filter((app) => app.category === category).map((app) => {
                const installed = apps
                  .filter((entry) => entry.name === app.id && (entry.type === "docker" || entry.type === "compose"))
                  .flatMap((entry) => {
                    const node = nodes.find((item) => item.id === entry.nodeId);
                    return node ? [{ entry, node }] : [];
                  });
                const missing = nodes.filter((node) => !installed.some((item) => item.node.id === node.id));
                return (
                  <article className="card card-pad catalog-app" key={app.id}>
                    <h3 className="card-title">{app.name}</h3>
                    <p>{app.blurb}</p>
                    <div className="catalog-actions">
                      {installed.map(({ entry, node }) => (
                        <div className="catalog-installed" key={node.id}>
                          <span>Installed on {node.name}</span>
                          <OpenApp node={node} port={entry.ports.includes(app.hostPort) ? app.hostPort : entry.ports[0] ?? app.hostPort} />
                        </div>
                      ))}
                      {(!installed.length || missing.some((node) => !installationBlock(node))) && (
                        <button type="button" className="btn btn-primary" aria-label={"Install " + app.name}
                          onClick={() => setSelected(app)}>Install</button>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          </section>
        ))}
      </div>
      {selected && (
        <InstallApp key={selected.id} app={selected} nodes={nodes} apps={apps}
          onClose={() => setSelected(null)} onInstalled={onInstalled} />
      )}
    </>
  );
}

function InstallApp({ app, nodes, apps, onClose, onInstalled }: {
  app: CatalogApp;
  nodes: Node[];
  apps: ManagedApp[];
  onClose: () => void;
  onInstalled: (app: ManagedApp) => void;
}) {
  const [nodeId, setNodeId] = useState("");
  const [folder, setFolder] = useState("");
  const [useModelServer, setUseModelServer] = useState(false);
  const [modelServerId, setModelServerId] = useState("");
  const [modelAddress, setModelAddress] = useState("");
  const [modelKey, setModelKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [installedOn, setInstalledOn] = useState<Node | null>(null);
  const targets = nodes.filter((node) => !apps.some((entry) =>
    entry.nodeId === node.id && entry.name === app.id && (entry.type === "docker" || entry.type === "compose")));
  const node = targets.find((item) => item.id === nodeId) ?? (targets.length === 1 ? targets[0] : undefined);
  const blocked = installationBlock(node);
  const modelVariant = useModelServer ? app.modelServer : undefined;
  const servers = modelVariant ? modelServers(apps, nodes) : [];
  const server = servers.find((item) => item.id === modelServerId);
  const useOllama = server?.runner === "ollama";
  const name = app.modelServer ? "Open WebUI" : app.name;

  function close() {
    if (!busy) onClose();
  }

  async function install(event: FormEvent) {
    event.preventDefault();
    if (busy || !node || blocked) return;
    const path = folder.trim();
    if (app.folder && (!path.startsWith("/") || path.includes(":"))) {
      setError("Enter the full folder path on " + node.name + ", starting with /.");
      return;
    }
    let env: Record<string, string> = {};
    if (modelVariant) {
      if (!server && modelServerId !== "other") {
        setError("Choose a model server or enter its address.");
        return;
      }
      const address = (server?.url ?? modelAddress.trim()).replace(/\/+$/, "");
      if (!validModelUrl(address)) {
        setError("Enter the base URL for your model server, starting with http:// or https://.");
        return;
      }
      // Match open_webui_model_env in rackdeck-api.
      env = useOllama ? { OLLAMA_BASE_URL: address } : {
        OPENAI_API_BASE_URL: address.endsWith("/v1") ? address : address + "/v1",
        OPENAI_API_KEY: modelKey || "none",
        ENABLE_OLLAMA_API: "false",
      };
    }
    setBusy(true);
    setError("");
    const volumes = [...(modelVariant?.volumes ?? app.volumes)];
    if (app.folder) volumes.push(path + ":" + app.folder.path);
    try {
      const res = await fetch("/api/v1/nodes/" + encodeURIComponent(node.id) + "/deploy", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: app.id,
          image: modelVariant?.image ?? app.image,
          hostPort: app.hostPort,
          containerPort: app.containerPort,
          ports: app.ports ?? [],
          volumes,
          gpu: !modelVariant && Boolean(app.gpu) && node.hw.accel.kind === "nvidia",
          env,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.app) {
        setError(data.error || "Could not install " + name + ".");
        return;
      }
      onInstalled({ ...data.app, nodeId: node.id });
      setModelKey("");
      setInstalledOn(node);
    } catch {
      setError("Could not reach the dashboard. Check the Apps page before trying again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="backdrop" onClick={close}>
      <div className="modal" role="dialog" aria-labelledby="install-app-title" onClick={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.stopPropagation();
            close();
          }
        }}>
        <div className="card-head">
          <h2 className="card-title" id="install-app-title">{installedOn ? name + " installed" : "Install " + name}</h2>
          <button type="button" className="btn btn-sm" aria-label="Close install dialog" disabled={busy} onClick={close}>✕</button>
        </div>
        {installedOn ? (
          <div className="card-pad catalog-install">
            <p role="status">Installed on {installedOn.name}.</p>
            <p>{modelVariant ? "Open it, create the admin account, then choose a model from your server." : app.next}</p>
            <div className="catalog-installed">
              <OpenApp node={installedOn} port={app.hostPort} />
              <button type="button" className="btn" autoFocus onClick={close}>Done</button>
            </div>
          </div>
        ) : (
          <form className="card-pad catalog-install" onSubmit={install}>
            <div className="field">
              <label htmlFor="catalog-node">Computer</label>
              <select id="catalog-node" className="input" value={node?.id ?? ""} autoFocus required disabled={busy}
                onChange={(event) => {
                  setNodeId(event.target.value);
                  setError("");
                }}>
                <option value="" disabled>Choose a computer</option>
                {targets.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
              </select>
            </div>
            {app.folder && (
              <div className="field">
                <label htmlFor="catalog-folder">{app.folder.label}</label>
                <input type="text" id="catalog-folder" className="input" placeholder="/home/you/Movies"
                  value={folder} required disabled={busy} onChange={(event) => setFolder(event.target.value)} />
              </div>
            )}
            {app.modelServer && (
              <fieldset className="catalog-model-source" disabled={busy}>
                <legend>Where do models come from?</legend>
                <label>
                  <input type="radio" name="catalog-model-source" checked={!useModelServer}
                    onChange={() => {
                      setUseModelServer(false);
                      setModelKey("");
                      setError("");
                    }} />
                  Download models on this machine (Ollama included)
                </label>
                <label>
                  <input type="radio" name="catalog-model-source" checked={useModelServer}
                    onChange={() => {
                      setUseModelServer(true);
                      setError("");
                    }} />
                  A model server you already run
                </label>
                {modelVariant && (
                  <>
                    <div className="field">
                      <label htmlFor="catalog-model-server">Model server</label>
                      <select id="catalog-model-server" className="input"
                        value={server?.id ?? (modelServerId === "other" ? "other" : "")} required
                        onChange={(event) => {
                          setModelServerId(event.target.value);
                          setModelKey("");
                          setError("");
                        }}>
                        <option value="" disabled>Choose a model server</option>
                        {servers.map(({ id, runner, nodeName, port }) => (
                          <option key={id} value={id}>{runner} on {nodeName} · port {port}</option>
                        ))}
                        <option value="other">Other address</option>
                      </select>
                    </div>
                    {modelServerId === "other" && (
                      <div className="field">
                        <label htmlFor="catalog-model-address">OpenAI-compatible server URL</label>
                        <input id="catalog-model-address" className="input" type="url" required
                          placeholder="http://192.168.1.50:8080" value={modelAddress}
                          onChange={(event) => setModelAddress(event.target.value)} />
                      </div>
                    )}
                    {(server || modelServerId === "other") && !useOllama && (
                      <div className="field">
                        <label htmlFor="catalog-model-key">API key (optional)</label>
                        <input id="catalog-model-key" className="input" type="password" autoComplete="off"
                          value={modelKey} onChange={(event) => setModelKey(event.target.value)} />
                      </div>
                    )}
                  </>
                )}
              </fieldset>
            )}
            {app.note && !modelVariant && <p>{app.note}</p>}
            {blocked && <p className="inline-err" role="status">{blocked}</p>}
            {error && <p className="inline-err" role="alert">{error}</p>}
            {busy && <p role="status">Downloading and starting… this can take a few minutes for big apps.</p>}
            <button type="submit" className="btn btn-primary" disabled={busy || !node || Boolean(blocked)}>Install</button>
          </form>
        )}
      </div>
    </div>
  );
}
