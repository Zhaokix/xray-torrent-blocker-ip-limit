#!/bin/bash
set -euo pipefail

REPO="${REPO:-Zhaokix/xray-torrent-blocker-ip-limit}"
ASSET_NAME="${ASSET_NAME:-xray-ip-limit_linux_amd64.tar.gz}"
TMP_DIR="$(mktemp -d)"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command '$1' is not installed"
        exit 1
    fi
}

require_command curl
require_command tar

echo "==> Downloading ${ASSET_NAME}..."
curl -fL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET_NAME}"

echo "==> Extracting release archive..."
tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "$TMP_DIR"

cd "${TMP_DIR}/xray-ip-limit"
bash ./install.sh
