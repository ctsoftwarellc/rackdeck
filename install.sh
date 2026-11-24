#!/usr/bin/env sh
set -eu

REPO="${RACKDECK_REPO:-ctsoftwarellc/rackdeck}"
VERSION="${RACKDECK_VERSION:-latest}"
INSTALL_DIR="${RACKDECK_INSTALL_DIR:-/usr/local/bin}"
CONTROLLER=""
JOIN_TOKEN=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --join|--token) JOIN_TOKEN="$2"; shift 2 ;;
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

if [ "$VERSION" = "latest" ]; then
  URL="https://github.com/${REPO}/releases/latest/download/rackdeck-${TARGET}.tar.gz"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/rackdeck-${TARGET}.tar.gz"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading Rackdeck (${TARGET})..."
curl -fsSL "$URL" -o "${TMP}/rackdeck.tar.gz"
tar -xzf "${TMP}/rackdeck.tar.gz" -C "$TMP"

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "${TMP}/rackdeck" "${INSTALL_DIR}/rackdeck"
else
  sudo install -m 0755 "${TMP}/rackdeck" "${INSTALL_DIR}/rackdeck"
fi

echo "Installed rackdeck to ${INSTALL_DIR}/rackdeck"
BIN="${INSTALL_DIR}/rackdeck"
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

if [ -n "$CONTROLLER" ] && [ -n "$JOIN_TOKEN" ]; then
  echo "Joining controller at ${CONTROLLER}..."
  # Run the agent as a background service so it survives logout and reboots.
  # After the first check-in it uses the key saved in its state file; the join token is just for first contact.
  if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    $SUDO tee /etc/systemd/system/rackdeck-agent.service >/dev/null <<UNIT
[Unit]
Description=Rackdeck agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN} agent --controller ${CONTROLLER} --token ${JOIN_TOKEN}
Environment=RACKDECK_AGENT_STATE=/var/lib/rackdeck/agent.json
StateDirectory=rackdeck
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now rackdeck-agent
    echo "Agent running as systemd service rackdeck-agent (logs: journalctl -u rackdeck-agent -f)"
  elif [ "$OS" = "darwin" ]; then
    PLIST="$HOME/Library/LaunchAgents/dev.rackdeck.agent.plist"
    mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.rackdeck.agent</string>
  <key>ProgramArguments</key><array>
    <string>${BIN}</string><string>agent</string>
    <string>--controller</string><string>${CONTROLLER}</string>
    <string>--token</string><string>${JOIN_TOKEN}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/rackdeck-agent.log</string>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/rackdeck-agent.log</string>
</dict></plist>
PLIST
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load -w "$PLIST"
    echo "Agent running as a LaunchAgent (logs: ~/Library/Logs/rackdeck-agent.log)"
  else
    echo "No systemd found, running in the foreground. It stops when this shell closes."
    exec "$BIN" agent --controller "$CONTROLLER" --token "$JOIN_TOKEN"
  fi
else
  echo "Run: rackdeck   (opens control panel on http://127.0.0.1:7420)"
fi
