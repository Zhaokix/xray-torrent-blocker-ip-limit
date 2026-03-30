# Xray Torrent Blocker IP Limit

`iptblocker` is a local daemon that watches the Xray access log, tracks unique client IPs per subscription email inside a sliding window, and applies local firewall bans when the configured limit is exceeded. It can also ban on torrent-tagged log events when Xray is configured to mark bittorrent traffic with a dedicated tag.

## Current Scope

- Local daemon only
- Local firewall enforcement through `iptables` or `nftables`
- Optional torrent-tag based enforcement from Xray access logs
- Persistent local ban state in SQLite
- Optional webhook notifications
- Dry-run mode for safe validation

This repository does not yet implement distributed enforcement or remote ban propagation in the current phase.

## Project Basis

This project was built with ideas and reference materials from:

- [V2IpLimit](https://github.com/houshmand-2005/V2IpLimit) by `houshmand-2005`
- [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker) by `kutovoys`

### How This Project Differs

- Compared to `V2IpLimit`, `iptblocker` is focused on a production-safe local daemon flow with persistent SQLite state, explicit firewall reconciliation, dry-run validation, webhook integration, and clearer layering between extraction, detection, enforcement, and notifications.
- Compared to `xray-torrent-blocker`, `iptblocker` combines IP-limit enforcement and torrent-tag enforcement in one local daemon, while keeping a simpler local-first scope instead of moving immediately into broader distributed enforcement patterns.
- The current implementation reuses useful architectural ideas from both projects, but keeps its own code structure and avoids legacy patterns such as overly global mutable state.

## Requirements

- Linux host with Xray access logs enabled
- `iptables` or `nftables`
- `conntrack` available in `PATH` if you want existing connections to be dropped on ban

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

This installer downloads the latest release archive, extracts it to a temporary directory, and runs the bundled `install.sh`.

Current default release asset:

- `iptblocker_linux_amd64.tar.gz`

## Configuration

Start from [config.yaml.default](/e:/1-Development/IP-Torrent-Ban/xray-ip-limit/config.yaml.default).

Important fields:

- `log_file`: path to the Xray access log
- `ip_limit`: max unique IPs allowed per email within the window
- `window`: sliding duration used for counting unique IPs
- `ban_duration`: local ban duration
- `enable_torrent_detection`: enable torrent-triggered bans from tagged Xray log lines
- `torrent_tag`: string marker that identifies torrent traffic in the log, typically an Xray `outboundTag`
- `ban_mode`: `iptables`, `nftables`, or `nft`
- `dry_run`: when `true`, no firewall changes are applied
- `storage_dir`: local SQLite state directory
- `webhook_username_regex`: regex used to transform the raw subscription identifier before it is inserted into the webhook payload
- `webhook_template_ip_limit`: optional template override used only for `ip_limit` events
- `webhook_template_torrent`: optional template override used only for `torrent` events

### Telegram Webhook Example

If your user identifier looks like `user.123456789` and the Telegram chat ID is the numeric suffix after the dot, use:

```yaml
send_webhook: true
webhook_url: "https://api.telegram.org/bot<token>/sendMessage"
webhook_template: '{"chat_id":"%s","text":"⚠️ Subscription sharing detected.\n\n🌐 IP: %s\n🛡 Action: %s\n⏱ Ban: %s"}'
webhook_username_regex: '^\d+\.(\d+)$'
webhook_notify_unban: false
```

### Torrent Tag Detection Example

If you already route bittorrent traffic in Xray to a dedicated outbound tag such as `TORRENT`, enable torrent detection like this:

```yaml
enable_torrent_detection: true
torrent_tag: "TORRENT"
```

The current implementation expects the tagged line to still contain the client address in `from ...` and the subscription identifier in `email: ...`.

### Reason-Specific Webhook Templates

If you want different payloads for subscription sharing and torrent events, keep a generic fallback in `webhook_template` and override per reason:

```yaml
webhook_template: '{"chat_id":"%s","text":"Action: %s, IP: %s, Duration: %s"}'
webhook_template_ip_limit: '{"chat_id":"%s","text":"Sharing detected.\nIP: %s\nAction: %s\nBan: %s"}'
webhook_template_torrent: '{"chat_id":"%s","text":"Torrent traffic detected.\nIP: %s\nAction: %s\nBan: %s"}'
```

All webhook templates currently receive the same placeholders in this order:

- `%s`: processed username
- `%s`: client IP
- `%s`: action
- `%s`: ban duration

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
