# Xray IP Limit

`xray-ip-limit` is a local daemon that watches the Xray access log, tracks unique client IPs per subscription email inside a sliding window, and applies local firewall bans when the configured limit is exceeded.

## Current Scope

- Local daemon only
- Local firewall enforcement through `iptables` or `nftables`
- Persistent local ban state in SQLite
- Optional webhook notifications
- Dry-run mode for safe validation

This repository does not yet implement distributed enforcement or remote ban propagation in the current phase.

## Requirements

- Linux host with Xray access logs enabled
- `iptables` or `nftables`
- `conntrack` available in `PATH` if you want existing connections to be dropped on ban

## Build

```bash
go mod tidy
go build -o xray-ip-limit ./cmd/xray-ip-limit/
```

## Install

```bash
sudo bash install.sh
```

The installer:

- copies the binary to `/opt/xray-ip-limit/`
- creates `/opt/xray-ip-limit/config.yaml` if it does not exist
- installs the systemd unit
- enables the service

## Configuration

Start from [config.yaml.default](/e:/1-Development/IP-Torrent-Ban/xray-ip-limit/config.yaml.default).

Important fields:

- `log_file`: path to the Xray access log
- `ip_limit`: max unique IPs allowed per email within the window
- `window`: sliding duration used for counting unique IPs
- `ban_duration`: local ban duration
- `ban_mode`: `iptables`, `nftables`, or `nft`
- `dry_run`: when `true`, no firewall changes are applied
- `storage_dir`: local SQLite state directory

## Linux Smoke Check

1. Build the binary:
```bash
go build -o xray-ip-limit ./cmd/xray-ip-limit/
```

2. Copy the default config and enable dry-run first:
```bash
cp config.yaml.default /opt/xray-ip-limit/config.yaml
sed -i 's/^dry_run: false/dry_run: true/' /opt/xray-ip-limit/config.yaml
```

3. Point `log_file` to the real Xray access log.

4. Validate the daemon directly before systemd:
```bash
/opt/xray-ip-limit/xray-ip-limit -config /opt/xray-ip-limit/config.yaml
```

5. If the daemon starts and tails the log correctly, disable dry-run and start the service:
```bash
sed -i 's/^dry_run: true/dry_run: false/' /opt/xray-ip-limit/config.yaml
systemctl start xray-ip-limit
journalctl -u xray-ip-limit -f
```

## Verification Commands

```bash
systemctl status xray-ip-limit
journalctl -u xray-ip-limit -f
iptables -S XRAY_IP_LIMIT_BLOCKED
nft list set inet xray_ip_limit banned_ips
```

Use the `iptables` command only when `ban_mode` is `iptables`, and the `nft` command only when `ban_mode` is `nftables` or `nft`.
