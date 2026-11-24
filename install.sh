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
if [ -n "$CONTROLLER" ] && [ -n "$JOIN_TOKEN" ]; then
  echo "Joining controller at ${CONTROLLER}..."
  exec "${INSTALL_DIR}/rackdeck" agent --controller "$CONTROLLER" --token "$JOIN_TOKEN"
else
  echo "Run: rackdeck   (opens control panel on http://127.0.0.1:7420)"
fi
