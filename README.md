# Xray Torrent Blocker IP Limit

`iptblocker` is a local-first daemon that watches the Xray access log, tracks unique client IPs per subscription identifier inside a sliding window, and applies firewall bans when the configured policy is violated. It can also ban on torrent-tagged log events when Xray is configured to mark bittorrent traffic with a dedicated tag.

## Requirements

- Linux host with Xray access logs enabled
- `iptables` or `nftables`
- `conntrack` available in `PATH` if you want existing connections to be dropped on ban
- `ssh` available in `PATH` if you want remote enforcement

## Build

```bash
go mod tidy
go build -o iptblocker ./cmd/xray-ip-limit/
```

## Install

```bash
sudo bash install.sh
```

The installer:

- copies the binary to `/opt/iptblocker/`
- creates `/opt/iptblocker/config.yaml` if it does not exist
- tries to install `conntrack` when it is missing
- installs the systemd unit
- enables the service

## Install From GitHub Release

The repository publishes a Linux amd64 tarball on tagged releases.

```bash
curl -fsSL https://raw.githubusercontent.com/Zhaokix/xray-torrent-blocker-ip-limit/main/install-release.sh | sudo bash
```

Current default release asset:

- `iptblocker_linux_amd64.tar.gz`

## Quick Start

1. Install from the latest GitHub release:

```bash
curl -fsSL https://raw.githubusercontent.com/Zhaokix/xray-torrent-blocker-ip-limit/main/install-release.sh | sudo bash
```

2. Edit the main config:

```bash
sudo nano /opt/iptblocker/config.yaml
```

Minimum fields to set:

- `log_file`
- `ip_limit`
- `window`
- `ban_duration`
- `ban_mode`
- `dry_run`

3. Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart iptblocker
sudo systemctl status iptblocker
```

4. Watch logs:

```bash
sudo journalctl -u iptblocker -f
```

## Guides

- [Configuration guide](guides/CONFIGURATION.md)
- [Client notifications guide](guides/CLIENT_NOTIFICATIONS.md)
- [Admin notifications guide](guides/ADMIN_NOTIFICATIONS.md)
- [Remote enforcement and SSH guide](guides/REMOTE_ENFORCEMENT.md)

## Linux Smoke Check

1. Build the binary:
```bash
go build -o iptblocker ./cmd/xray-ip-limit/
```

2. Copy the default config and enable dry-run first:
```bash
cp config.yaml.default /opt/iptblocker/config.yaml
sed -i 's/^dry_run: false/dry_run: true/' /opt/iptblocker/config.yaml
```

3. Point `log_file` to the real Xray access log.

4. Validate the daemon directly before systemd:
```bash
/opt/iptblocker/iptblocker -config /opt/iptblocker/config.yaml
```

5. If the daemon starts and tails the log correctly, disable dry-run and start the service:
```bash
sed -i 's/^dry_run: true/dry_run: false/' /opt/iptblocker/config.yaml
systemctl start iptblocker
journalctl -u iptblocker -f
```

## Verification Commands

```bash
systemctl status iptblocker
journalctl -u iptblocker -f
iptables -S XRAY_IP_LIMIT_BLOCKED
nft list set inet xray_ip_limit banned_ips
```

Use the `iptables` command only when `ban_mode` is `iptables`, and the `nft` command only when `ban_mode` is `nftables` or `nft`.
