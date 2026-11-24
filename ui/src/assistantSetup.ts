export const ASSISTANTS = ["Claude Code", "Codex", "Cursor"] as const;
export type Assistant = (typeof ASSISTANTS)[number];
export type AssistantSetup =
  | { kind: "command"; command: string }
  | { kind: "cursor"; link: string; config: string };

function shellQuote(value: string): string {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

export function assistantSetup(client: Assistant, origin: string, id: string, token: string): AssistantSetup {
  const name = "rackdeck-" + id.replace(/^tok[-_]/, "").replace(/[^a-zA-Z0-9_-]/g, "-");
  const url = origin + "/mcp";
  const authorization = "Bearer " + token;
  if (client === "Claude Code") {
    return {
      kind: "command",
      command: "claude mcp add --scope user --transport http " + name + " " + shellQuote(url)
        + " --header " + shellQuote("Authorization: " + authorization),
    };
  }
  if (client === "Codex") {
    // Let Codex write the server entry, then add the header its CLI cannot set.
    return {
      kind: "command",
      command: "codex mcp add " + name + " --url " + shellQuote(url)
        + ' && (config="${CODEX_HOME:-$HOME/.codex}/config.toml"; chmod go-rwx "$config" && '
        + "printf '\\n[mcp_servers.%s.http_headers]\\nAuthorization = %s\\n' "
        + shellQuote(name) + " " + shellQuote(JSON.stringify(authorization)) + ' >> "$config")',
    };
  }
  const server = { url, headers: { Authorization: authorization } };
  const query = new URLSearchParams({ name, config: btoa(JSON.stringify(server)) });
  return {
    kind: "cursor",
    link: "cursor://anysphere.cursor-deeplink/mcp/install?" + query,
    config: JSON.stringify({ mcpServers: { [name]: server } }, null, 2),
  };
}
