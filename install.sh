#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/xray-ip-limit"
BINARY="xray-ip-limit"
SERVICE="xray-ip-limit.service"
CONFIG_PATH="$INSTALL_DIR/config.yaml"

echo "==> Installing xray-ip-limit..."

if [ "$EUID" -ne 0 ]; then
    echo "Error: please run as root"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "Error: binary '$BINARY' not found in current directory"
    echo "Build it first: go build -o xray-ip-limit ./cmd/xray-ip-limit/"
    exit 1
fi

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
echo "  3. Start:        systemctl start xray-ip-limit"
echo "  4. Logs:         journalctl -u xray-ip-limit -f"
