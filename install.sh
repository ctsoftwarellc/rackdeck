#!/usr/bin/env sh
set -eu

# Usage:
#   curl -fsSL https://get.rackdeck.dev | sh                                   install or update the binary
#   curl -fsSL https://get.rackdeck.dev | RACKDECK_PASSWORD=... sh -s -- --service
#                                                                              run the dashboard as a service
#   curl -fsSL https://get.rackdeck.dev | sh -s -- --controller URL --join TOKEN
#                                                                              join this machine as an agent service

REPO="${RACKDECK_REPO:-ctsoftwarellc/rackdeck}"
VERSION="${RACKDECK_VERSION:-latest}"
CONTROLLER=""
JOIN_TOKEN=""
CONTROLLER_KEY=""
SERVICE=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --join|--token) JOIN_TOKEN="$2"; shift 2 ;;
    --key) CONTROLLER_KEY="$2"; shift 2 ;;
    --service) SERVICE=1; shift ;;
    *) shift ;;
  esac
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
  linux) TARGET="${ARCH}-unknown-linux-gnu" ;;
  darwin) TARGET="${ARCH}-apple-darwin" ;;
  *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# macOS installs into a folder you own, so the dashboard's Update button can replace the binary
# without sudo. Linux services run as root, so /usr/local/bin is fine there.
if [ "$OS" = "darwin" ]; then
  INSTALL_DIR="${RACKDECK_INSTALL_DIR:-$HOME/.rackdeck/bin}"
else
  INSTALL_DIR="${RACKDECK_INSTALL_DIR:-/usr/local/bin}"
fi
BIN="${INSTALL_DIR}/rackdeck"
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/rackdeck-${TARGET}.tar.gz"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/rackdeck-${TARGET}.tar.gz"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading Rackdeck (${TARGET})..."
if ! curl -fsSL "$URL" -o "${TMP}/rackdeck.tar.gz"; then
  echo "No Rackdeck build for ${TARGET} at ${URL}" >&2
  exit 1
fi
tar -xzf "${TMP}/rackdeck.tar.gz" -C "$TMP"

mkdir -p "$INSTALL_DIR" 2>/dev/null || $SUDO mkdir -p "$INSTALL_DIR"
if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "${TMP}/rackdeck" "$BIN"
else
  $SUDO install -m 0755 "${TMP}/rackdeck" "$BIN"
fi
echo "Installed $("$BIN" --version) to ${BIN}"

if [ "$OS" = "darwin" ] && [ "$INSTALL_DIR" != "/usr/local/bin" ]; then
  # Keep `rackdeck` on PATH. The link points at the user-owned binary, so updates flow through.
  if [ -w /usr/local/bin ]; then
    ln -sf "$BIN" /usr/local/bin/rackdeck
  else
    $SUDO mkdir -p /usr/local/bin && $SUDO ln -sf "$BIN" /usr/local/bin/rackdeck
  fi
fi

# Secrets from the dashboard land in the installing user's ~/.config/rackdeck/secrets.env.
# Have their shells load it, once.
TARGET_USER="${SUDO_USER:-$(id -un)}"
USER_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)"
[ -n "$USER_HOME" ] || USER_HOME="$HOME"
SECRETS_FILE="${USER_HOME}/.config/rackdeck/secrets.env"
HOOK='[ -f "$HOME/.config/rackdeck/secrets.env" ] && . "$HOME/.config/rackdeck/secrets.env"'
[ "$OS" = "darwin" ] && [ ! -f "$USER_HOME/.zshrc" ] && touch "$USER_HOME/.zshrc"
for rc in "$USER_HOME/.bashrc" "$USER_HOME/.zshrc"; do
  if [ -f "$rc" ] && ! grep -q 'rackdeck/secrets.env' "$rc" 2>/dev/null; then
    printf '\n# Rackdeck secrets\n%s\n' "$HOOK" >> "$rc" 2>/dev/null || true
  fi
done

HAS_SYSTEMD=""
if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  HAS_SYSTEMD=1
fi

# install_service NAME DESCRIPTION ENV_LINES ARGS...
# ENV_LINES is "KEY=value" lines. On Linux they go in a root-only env file, on macOS in the plist.
install_service() {
  name="$1"; desc="$2"; envs="$3"; shift 3
  if [ -n "$HAS_SYSTEMD" ]; then
    $SUDO mkdir -p /etc/rackdeck
    printf '%s\n' "$envs" | $SUDO tee "/etc/rackdeck/${name}.env" >/dev/null
    $SUDO chmod 600 "/etc/rackdeck/${name}.env"
    $SUDO tee "/etc/systemd/system/${name}.service" >/dev/null <<UNIT
[Unit]
Description=${desc}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN} $*
EnvironmentFile=/etc/rackdeck/${name}.env
StateDirectory=rackdeck
WorkingDirectory=/var/lib/rackdeck
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable "$name" >/dev/null 2>&1
    $SUDO systemctl restart "$name"
    echo "Running as systemd service ${name} (logs: journalctl -u ${name} -f)"
  elif [ "$OS" = "darwin" ]; then
    label="dev.rackdeck.${name#rackdeck-}"
    plist="$HOME/Library/LaunchAgents/${label}.plist"
    mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs" "$HOME/.rackdeck"
    args_xml="<string>${BIN}</string>"
    for a in "$@"; do args_xml="${args_xml}<string>${a}</string>"; done
    env_xml=""
    for kv in $envs; do env_xml="${env_xml}<key>${kv%%=*}</key><string>${kv#*=}</string>"; done
    cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key><array>${args_xml}</array>
  <key>EnvironmentVariables</key><dict>${env_xml}</dict>
  <key>WorkingDirectory</key><string>$HOME/.rackdeck</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/${name}.log</string>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/${name}.log</string>
</dict></plist>
PLIST
    chmod 600 "$plist"
    launchctl unload "$plist" 2>/dev/null || true
    launchctl load -w "$plist"
    echo "Running as a LaunchAgent (logs: ~/Library/Logs/${name}.log)"
  else
    return 1
  fi
}

if [ -n "$CONTROLLER" ] && [ -n "$JOIN_TOKEN" ]; then
  # --controller can list several addresses separated by commas. Use the first one that answers.
  TRIED="$CONTROLLER"
  CONTROLLER=""
  for c in $(printf '%s' "$TRIED" | tr ',' ' '); do
    if curl -fsS -m 3 "${c}/api/v1/health" >/dev/null 2>&1; then CONTROLLER="$c"; break; fi
  done
  if [ -z "$CONTROLLER" ]; then
    echo "Can't reach your Rackdeck dashboard from this machine (tried ${TRIED})." >&2
    echo "Put this machine on the same network or tailnet as the dashboard, then run the command again." >&2
    exit 1
  fi
  # After the first check-in the agent uses the key in its state file; the join token is only for first contact.
  if [ "$OS" = "darwin" ]; then
    STATE="$HOME/.config/rackdeck/agent.json"  # same place earlier installs used, so the key carries over
  else
    STATE="/var/lib/rackdeck/agent.json"
  fi
  # A machine that already joined has its own key, so an old join command is fine for it.
  if ! $SUDO grep -q agentKey "$STATE" 2>/dev/null; then
    CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H "Authorization: Bearer ${JOIN_TOKEN}" "${CONTROLLER}/api/v1/agent/join-check" || true)"
    if [ "$CODE" = "401" ]; then
      echo "This join command expired or was already used. Click + Add machine in the dashboard for a new one." >&2
      exit 1
    fi
  fi
  echo "Joining controller at ${CONTROLLER}..."
  # The working address goes first; the agent falls back to the others if it stops answering.
  CONTROLLERS="${CONTROLLER},${TRIED}"
  AGENT_ENV="RACKDECK_AGENT_STATE=${STATE}"
  [ -n "$CONTROLLER_KEY" ] && AGENT_ENV="${AGENT_ENV}
RACKDECK_CONTROLLER_KEY=${CONTROLLER_KEY}"
  if [ "$OS" = "linux" ]; then
    # The service runs as root; write secrets into the user's home, owned by them.
    AGENT_ENV="${AGENT_ENV}
RACKDECK_SECRETS_FILE=${SECRETS_FILE}
RACKDECK_SECRETS_OWNER=$(id -u "$TARGET_USER"):$(id -g "$TARGET_USER")"
  fi
  if ! install_service rackdeck-agent "Rackdeck agent" "$AGENT_ENV" \
      agent --controller "$CONTROLLERS" --token "$JOIN_TOKEN"; then
    if grep -qi microsoft /proc/version 2>/dev/null; then
      echo "This is WSL without systemd, so the agent stops when this window closes. To keep it running:" >&2
      echo "  1. Add these lines to /etc/wsl.conf:  [boot]  and  systemd=true" >&2
      echo "  2. Run  wsl --shutdown  in Windows PowerShell, reopen Ubuntu, and run this command again." >&2
    fi
    echo "No systemd found, running in the foreground. It stops when this shell closes."
    RACKDECK_CONTROLLER_KEY="$CONTROLLER_KEY" exec "$BIN" agent --controller "$CONTROLLERS" --token "$JOIN_TOKEN"
  fi
elif [ -n "$SERVICE" ]; then
  if [ -z "${RACKDECK_PASSWORD:-}" ]; then
    echo "Set RACKDECK_PASSWORD for the dashboard service, e.g. curl ... | RACKDECK_PASSWORD=... sh -s -- --service" >&2
    exit 1
  fi
  case "$RACKDECK_PASSWORD" in *[[:space:]\<\>\&]*)
    echo "Use a password without spaces or < > & characters for the service." >&2; exit 1 ;;
  esac
  if [ "$OS" = "darwin" ]; then DB="$HOME/.rackdeck/rackdeck.db"; else DB="/var/lib/rackdeck/rackdeck.db"; fi
  if ! install_service rackdeck "Rackdeck dashboard" "RACKDECK_PASSWORD=${RACKDECK_PASSWORD}
RACKDECK_DB=${DB}"; then
    echo "No systemd found. Start it yourself: RACKDECK_PASSWORD=... rackdeck" >&2
    exit 1
  fi
  echo "Dashboard: http://<this-machine>:${RACKDECK_PORT:-7420}"
else
  echo "Run: RACKDECK_PASSWORD=... rackdeck   (dashboard on port 7420)"
  echo "Already running as a service? Restart it, or use Update in the dashboard next time."
fi
