#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/iptblocker"
BINARY="iptblocker"
SERVICE="iptblocker.service"
CONFIG_PATH="$INSTALL_DIR/config.yaml"

install_conntrack_if_missing() {
    if command -v conntrack >/dev/null 2>&1; then
        echo "==> conntrack is already installed"
        return 0
    fi

    echo "==> conntrack not found, attempting to install it"

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y conntrack
        return 0
    fi

    if command -v dnf >/dev/null 2>&1; then
        dnf install -y conntrack-tools
        return 0
    fi

    if command -v yum >/dev/null 2>&1; then
        yum install -y conntrack-tools
        return 0
    fi

    echo "Warning: could not install conntrack automatically"
    echo "Warning: install conntrack manually to drop existing connections on ban"
}

echo "==> Installing iptblocker..."

if [ "$EUID" -ne 0 ]; then
    echo "Error: please run as root"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "Error: binary '$BINARY' not found in current directory"
    echo "Build it first: go build -o iptblocker ./cmd/xray-ip-limit/"
    exit 1
fi

install_conntrack_if_missing

mkdir -p "$INSTALL_DIR"

cp "$BINARY" "$INSTALL_DIR/$BINARY"
chmod 0755 "$INSTALL_DIR/$BINARY"

if [ ! -f "$CONFIG_PATH" ]; then
    cp config.yaml.default "$CONFIG_PATH"
    chmod 0644 "$CONFIG_PATH"
    echo "==> Created default config at $CONFIG_PATH"
else
    echo "==> Config already exists, keeping existing file"
fi

cp "$SERVICE" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable "$SERVICE"

echo ""
echo "==> Installation complete"
echo ""
echo "Next steps:"
echo "  1. Edit config:  $CONFIG_PATH"
echo "  2. Validate run: $INSTALL_DIR/$BINARY -config $CONFIG_PATH"
echo "  3. Start:        systemctl start iptblocker"
echo "  4. Logs:         journalctl -u iptblocker -f"
