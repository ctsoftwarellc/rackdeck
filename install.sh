#!/usr/bin/env sh
set -eu

# Usage:
#   curl -fsSL https://get.rackdeck.dev | sh
#     Update an existing service, or ask to join or start a dashboard. Without a terminal, install the binary.
#   curl -fsSL https://get.rackdeck.dev | sh -s -- --service
#     Start a dashboard service. Set RACKDECK_PASSWORD to use your own password.
#   curl -fsSL https://get.rackdeck.dev | sh -s -- --controller URL --join TOKEN --key KEY
#     Join a dashboard with a one-time command.

REPO="${RACKDECK_REPO:-ctsoftwarellc/rackdeck}"
VERSION="${RACKDECK_VERSION:-latest}"
CONTROLLER=""
JOIN_TOKEN=""
CONTROLLER_KEY=""
SERVICE=""
GUIDED=""
[ "$#" -eq 0 ] && GUIDED=1

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

# Secrets from the dashboard land in the installing user's ~/.config/rackdeck/secrets.env.
# Have their shells load it, once.
TARGET_USER="${SUDO_USER:-$(id -un)}"
if [ "$OS" = "darwin" ]; then
  USER_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | cut -d ' ' -f2-)"
else
  USER_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6)"
fi
[ -n "$USER_HOME" ] || USER_HOME="$HOME"
SECRETS_FILE="${USER_HOME}/.config/rackdeck/secrets.env"

SECRETS_ENV="RACKDECK_SECRETS_FILE=${SECRETS_FILE}
RACKDECK_SECRETS_OWNER=$(id -u "$TARGET_USER"):$(id -g "$TARGET_USER")"

install_binary() {
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

  # Write shell startup files as their user, even when the installer runs through sudo.
  set -- sh
  if [ "$(id -un)" != "$TARGET_USER" ]; then
    set -- sudo -u "$TARGET_USER" sh
  fi
  # shellcheck disable=SC2016
  HOOK='[ -f "$HOME/.config/rackdeck/secrets.env" ] && . "$HOME/.config/rackdeck/secrets.env"'
  "$@" -c '
    [ "$1" = darwin ] && [ ! -f "$2/.zshrc" ] && touch "$2/.zshrc"
    for rc in "$2/.bashrc" "$2/.zshrc"; do
      if [ -f "$rc" ] && ! grep -q "rackdeck/secrets.env" "$rc" 2>/dev/null; then
        printf "\n# Rackdeck secrets\n%s\n" "$3" >> "$rc" 2>/dev/null || true
      fi
    done
  ' sh "$OS" "$USER_HOME" "$HOOK"
}

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
    # shellcheck disable=SC2016
    printf '%s\n' "$envs" | $SUDO sh -eu -c 'umask 077; cat > "$1"; chmod 600 "$1"' sh "/etc/rackdeck/${name}.env"
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
    (umask 077; cat > "$plist") <<PLIST
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

restart_services() {
  UPDATED=""
  if [ -n "$HAS_SYSTEMD" ]; then
    for unit in rackdeck rackdeck-agent; do
      [ -f "/etc/systemd/system/${unit}.service" ] || continue
      [ -n "$UPDATED" ] || install_binary
      # Keep the existing service arguments and any secrets home already configured.
      dropin="/etc/systemd/system/${unit}.service.d/90-rackdeck-secrets.conf"
      extra_env="/etc/rackdeck/${unit}-secrets.env"
      service_env="/etc/rackdeck/${unit}.env"
      if [ ! -f "$dropin" ] || [ ! -f "$extra_env" ]; then
        if ! $SUDO grep -q '^RACKDECK_SECRETS_FILE=' "$service_env" 2>/dev/null ||
           ! $SUDO grep -q '^RACKDECK_SECRETS_OWNER=' "$service_env" 2>/dev/null; then
          $SUDO mkdir -p "$(dirname "$dropin")" /etc/rackdeck
          printf '%s\n' "$SECRETS_ENV" | $SUDO sh -eu -c 'umask 077; cat > "$1"; chmod 600 "$1"' sh "$extra_env"
          printf '[Service]\nEnvironmentFile=%s\n' "$extra_env" | $SUDO tee "$dropin" >/dev/null
        fi
      fi
      $SUDO systemctl daemon-reload
      $SUDO systemctl restart "$unit"
      printf 'Updated and restarted %s.\n' "$unit"
      UPDATED=1
    done
  elif [ "$OS" = "darwin" ]; then
    for label in dev.rackdeck.rackdeck dev.rackdeck.agent dev.rackdeck; do
      plist="$HOME/Library/LaunchAgents/${label}.plist"
      [ -f "$plist" ] || continue
      [ -n "$UPDATED" ] || install_binary
      launchctl unload "$plist" 2>/dev/null || true
      launchctl load -w "$plist"
      printf 'Updated and restarted %s.\n' "$label"
      UPDATED=1
    done
  fi
}

ask_yes() {
  printf '%s [Y/n] ' "$1"
  IFS= read -r answer <&3 || return 1
  case "$answer" in ''|[Yy]|[Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac
}

if [ -n "$GUIDED" ] && [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; then
  exec 3</dev/tty
  restart_services
  [ -z "$UPDATED" ] || exit 0
  echo "Looking for Rackdeck dashboards on this network..."
  if FOUND="$("${TMP}/rackdeck" find)"; then
    # Replies come from the network. Keep addresses and keys safe for service files and strip terminal controls.
    DASHBOARDS="$(printf '%s\n' "$FOUND" | LC_ALL=C awk '
      $1 ~ /^http:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/ && length($2) == 64 && $2 ~ /^[[:xdigit:]]+$/ {
        address = $1
        key = $2
        sub(/^[[:blank:]]*[^[:blank:]]+[[:blank:]]+[^[:blank:]]+[[:blank:]]*/, "")
        gsub(/[[:cntrl:]]/, "", $0)
        print address, key, $0
      }')"
    if [ -n "$DASHBOARDS" ]; then
      COUNT="$(printf '%s\n' "$DASHBOARDS" | awk 'END { print NR }')"
      CHOICE=1
      if [ "$COUNT" -gt 1 ]; then
        printf '%s\n' "$DASHBOARDS" | while read -r address _key dashboard; do
          printf '  %s. %s (%s)\n' "$CHOICE" "$dashboard" "$address"
          CHOICE=$((CHOICE + 1))
        done
        printf 'Which dashboard do you want to use? [1] '
        IFS= read -r CHOICE <&3 || exit 0
        CHOICE="${CHOICE:-1}"
        case "$CHOICE" in *[!0-9]*) echo "Choose a dashboard by its number." >&2; exit 1 ;; esac
      fi
      PICK="$(printf '%s\n' "$DASHBOARDS" | awk -v choice="$CHOICE" 'NR == choice')"
      if [ -z "$PICK" ]; then
        echo "Choose a dashboard by its number." >&2
        exit 1
      fi
      read -r CONTROLLER CONTROLLER_KEY DASHBOARD <<PICKED
$PICK
PICKED
      printf 'Found %s (%s).\n' "$DASHBOARD" "$CONTROLLER"
      ask_yes "Add this computer to it?" || { echo "Nothing was installed."; exit 0; }
      if RACKDECK_AGENT_STATE="${TMP}/agent.json" "${TMP}/rackdeck" join-request --controller "$CONTROLLER" --key "$CONTROLLER_KEY" <&3; then
        :
      else
        status="$?"
        [ "$status" -ne 3 ] || exit 0
        echo "Could not join the dashboard. Nothing was installed." >&2
        exit "$status"
      fi
    else
      echo "No Rackdeck dashboard was found on this network."
      echo "If you already have one on another network, click + Add machine there and run that command here."
      ask_yes "Make this computer your dashboard?" || exit 0
      SERVICE=1
    fi
  fi
  exec 3<&-
fi

install_binary

start_agent() {
  AGENT_ENV="RACKDECK_AGENT_STATE=${STATE}"
  [ -n "$CONTROLLER_KEY" ] && AGENT_ENV="${AGENT_ENV}
RACKDECK_CONTROLLER_KEY=${CONTROLLER_KEY}"
  if [ -n "$HAS_SYSTEMD" ]; then
    # The service runs as root; write secrets into the user's home, owned by them.
    AGENT_ENV="${AGENT_ENV}
${SECRETS_ENV}"
  fi
  if [ -n "$HAS_SYSTEMD" ] || [ "$OS" = "darwin" ]; then
    install_service rackdeck-agent "Rackdeck agent" "$AGENT_ENV" agent "$@"
    return
  fi
  if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "This is WSL without systemd, so the agent stops when this window closes. To keep it running:" >&2
    echo "  1. Add these lines to /etc/wsl.conf:  [boot]  and  systemd=true" >&2
    echo "  2. Run  wsl --shutdown  in Windows PowerShell, reopen Ubuntu, and run this command again." >&2
  fi
  echo "No systemd found, running in the foreground. It stops when this shell closes."
  RACKDECK_AGENT_STATE="$STATE" RACKDECK_CONTROLLER_KEY="$CONTROLLER_KEY" exec "$BIN" agent "$@"
}

save_dashboard_password() {
  set -- sh
  if [ "$(id -un)" != "$TARGET_USER" ]; then
    set -- sudo -u "$TARGET_USER" sh
  fi
  # shellcheck disable=SC2016
  printf '%s\n' "$RACKDECK_PASSWORD" | "$@" -eu -c '
    umask 077
    mkdir -p "$1"
    tmp="$(mktemp "$1/password.XXXXXX")"
    trap '\''rm -f "$tmp"'\'' EXIT
    cat > "$tmp"
    [ ! -d "$1/password" ]
    mv -f "$tmp" "$1/password"
  ' sh "$USER_HOME/.config/rackdeck"
}

dashboard_ip() {
  if [ "$OS" = "darwin" ]; then
    interface="$(route -n get default 2>/dev/null | awk '$1 == "interface:" { print $2; exit }')"
    if [ -n "$interface" ] && ipconfig getifaddr "$interface"; then return; fi
    ifconfig | awk '$1 == "inet" && $2 !~ /^127\./ { print $2; exit }'
  else
    address="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '
      { for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')"
    if [ -n "$address" ]; then
      printf '%s\n' "$address"
    else
      hostname -I 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\./) { print $i; exit } }'
    fi
  fi
}

if [ -n "$HAS_SYSTEMD" ]; then
  STATE="/var/lib/rackdeck/agent.json"
elif [ "$OS" = "darwin" ]; then
  STATE="$HOME/.config/rackdeck/agent.json"
else
  STATE="${RACKDECK_AGENT_STATE:-$HOME/.config/rackdeck/agent.json}"
fi

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
  # A machine that already joined has its own key, so an old join command is fine for it.
  if ! $SUDO grep -Eq '"agentKey"[[:space:]]*:[[:space:]]*"[^"]+"' "$STATE" 2>/dev/null; then
    # Send only the token's hash: this request isn't encrypted.
    if command -v sha256sum >/dev/null 2>&1; then
      TOKEN_SHA="$(printf '%s' "$JOIN_TOKEN" | sha256sum | cut -d' ' -f1)"
    else
      TOKEN_SHA="$(printf '%s' "$JOIN_TOKEN" | shasum -a 256 | cut -d' ' -f1)"
    fi
    CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H "X-Join-Check: ${TOKEN_SHA}" "${CONTROLLER}/api/v1/agent/join-check" || true)"
    if [ "$CODE" = "401" ]; then
      CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H "Authorization: Bearer ${JOIN_TOKEN}" "${CONTROLLER}/api/v1/agent/join-check" || true)"
    fi
    if [ "$CODE" = "401" ]; then
      echo "This join command expired or was already used. Click + Add machine in the dashboard for a new one." >&2
      exit 1
    fi
  fi
  echo "Joining controller at ${CONTROLLER}..."
  # The working address goes first; the agent falls back to the others if it stops answering.
  start_agent --controller "${CONTROLLER},${TRIED}" --token "$JOIN_TOKEN"
elif [ -n "$GUIDED" ] && [ -n "$CONTROLLER" ]; then
  if [ -n "$HAS_SYSTEMD" ]; then
    $SUDO mkdir -p "$(dirname "$STATE")"
    $SUDO install -m 0600 "${TMP}/agent.json" "$STATE"
  else
    mkdir -p "$(dirname "$STATE")"
    install -m 0600 "${TMP}/agent.json" "$STATE"
  fi
  start_agent --controller "$CONTROLLER" --key "$CONTROLLER_KEY"
elif [ -n "$SERVICE" ]; then
  if [ "$OS" = "darwin" ]; then
    DB="$HOME/.rackdeck/rackdeck.db"
  elif [ -n "$HAS_SYSTEMD" ]; then
    DB="/var/lib/rackdeck/rackdeck.db"
  else
    echo "No systemd found. Start it yourself: RACKDECK_PASSWORD=... rackdeck" >&2
    exit 1
  fi
  GENERATED=""
  if [ -z "${RACKDECK_PASSWORD:-}" ]; then
    RACKDECK_PASSWORD="$(dd if=/dev/urandom bs=512 count=1 2>/dev/null |
      LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9' | head -c 20)"
    if [ "${#RACKDECK_PASSWORD}" -ne 20 ] || ! save_dashboard_password; then
      echo "Could not save a dashboard password to ~/.config/rackdeck/password." >&2
      exit 1
    fi
    GENERATED=1
  fi
  case "$RACKDECK_PASSWORD" in *[[:space:]\<\>\&]*)
    echo "Use a password without spaces or < > & characters for the service." >&2; exit 1 ;;
  esac
  PORT="${RACKDECK_PORT:-7420}"
  case "$PORT" in *[!0-9]*) PORT=7420 ;; esac
  DASHBOARD_ENV="RACKDECK_PASSWORD=${RACKDECK_PASSWORD}
RACKDECK_DB=${DB}
RACKDECK_PORT=${PORT}"
  if [ -n "$HAS_SYSTEMD" ]; then
    DASHBOARD_ENV="${DASHBOARD_ENV}
${SECRETS_ENV}"
  fi
  install_service rackdeck "Rackdeck dashboard" "$DASHBOARD_ENV"
  LAN_IP="$(dashboard_ip)"
  printf 'Dashboard: http://%s:%s\n' "${LAN_IP:-localhost}" "$PORT"
  if [ -n "$GENERATED" ]; then
    printf 'Password: %s\n' "$RACKDECK_PASSWORD"
    echo "Forgot it? It's saved in ~/.config/rackdeck/password"
  fi
else
  echo "Run: RACKDECK_PASSWORD=... rackdeck   (dashboard on port 7420)"
  echo "Already running as a service? Restart it, or use Update in the dashboard next time."
fi
