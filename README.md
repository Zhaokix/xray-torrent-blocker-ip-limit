# Xray Torrent Blocker IP Limit

`iptblocker` is a local-first daemon that watches the Xray access log, tracks unique client IPs per subscription identifier inside a sliding window, and applies firewall bans when the configured policy is violated. It can also ban on torrent-tagged log events when Xray is configured to mark bittorrent traffic with a dedicated tag.

## Current Scope

- Local firewall enforcement through `iptables` or `nftables`
- Optional remote enforcement on explicitly configured edge hosts over SSH
- Optional torrent-tag based enforcement from Xray access logs
- Persistent local state in SQLite
- Optional webhook notifications
- Optional admin webhook notifications with selectable fields
- Dry-run mode for safe validation

The current implementation includes a minimal remote-enforcement MVP for explicitly configured targets. It does not yet include admin notifications or a richer distributed control plane.

## Project Basis

This project was built with ideas and reference materials from:

- [V2IpLimit](https://github.com/houshmand-2005/V2IpLimit) by `houshmand-2005`
- [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker) by `kutovoys`

### How This Project Differs

- Compared to `V2IpLimit`, `iptblocker` is focused on a production-safe daemon flow with persistent SQLite state, explicit firewall reconciliation, dry-run validation, webhook integration, and clearer layering between extraction, detection, enforcement, distribution, and notifications.
- Compared to `xray-torrent-blocker`, `iptblocker` combines IP-limit enforcement and torrent-tag enforcement in one daemon and keeps the architecture local-first, while adding a small, configuration-driven remote-enforcement path instead of moving directly to a broader control plane.
- The implementation reuses useful architectural ideas from both projects, but keeps its own code structure and avoids legacy patterns such as overly global mutable state.

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

## Configuration

Start from [config.yaml.default](/e:/1-Development/IP-Torrent-Ban/xray-ip-limit/config.yaml.default).

Important fields:

- `log_file`: path to the Xray access log
- `ip_limit`: max unique IPs allowed per identifier inside the window
- `window`: sliding duration used for unique IP counting
- `ban_duration`: global fallback ban duration
- `ban_duration_ip_limit`: optional override for `ip_limit` bans
- `ban_duration_torrent`: optional override for `torrent` bans
- `enable_torrent_detection`: enable torrent-triggered bans from tagged Xray log lines
- `torrent_tag`: marker that identifies torrent traffic in the log, typically an Xray `outboundTag`
- `ban_mode`: `iptables`, `nftables`, or `nft`
- `dry_run`: when `true`, no local or remote firewall changes are applied
- `storage_dir`: local SQLite state directory
- `remote_enforcement`: optional SSH-based remote enforcement configuration
- `webhook_username_regex`: regex used to transform the raw identifier before it is inserted into the webhook payload
- `webhook_template_ip_limit`: optional template override used only for `ip_limit` events
- `webhook_template_torrent`: optional template override used only for `torrent` events
- `webhook_notify_ip_limit`: enable or disable webhook delivery for `ip_limit` events
- `webhook_notify_torrent`: enable or disable webhook delivery for `torrent` events
- `webhook_server_name`: optional hostname override used in webhook payloads; when empty, `iptblocker` uses the system hostname
- `admin_notifications`: optional admin-focused webhook channel with selectable JSON fields and optional unban notifications

### Telegram Webhook Example

If your user identifier looks like `user.123456789` and the Telegram chat ID is the numeric suffix after the dot, use:

```yaml
send_webhook: true
webhook_url: "https://api.telegram.org/bot<token>/sendMessage"
webhook_template: '{"chat_id":"%s","text":"Subscription sharing detected.\n\nIP: %s\nServer: %s\nAction: %s\nBan: %s"}'
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
webhook_template: '{"chat_id":"%s","text":"IP: %s\nServer: %s\nAction: %s\nDuration: %s"}'
webhook_template_ip_limit: '{"chat_id":"%s","text":"Sharing detected.\nIP: %s\nServer: %s\nAction: %s\nBan: %s"}'
webhook_template_torrent: '{"chat_id":"%s","text":"Torrent traffic detected.\nIP: %s\nServer: %s\nAction: %s\nBan: %s"}'
webhook_notify_ip_limit: true
webhook_notify_torrent: false
webhook_server_name: "usa-edge-1"
```

All webhook templates receive placeholders in this order:

- `%s`: processed username
- `%s`: client IP
- `%s`: server name
- `%s`: action
- `%s`: ban duration

### Reason-Specific Ban Duration

If you want a stricter torrent ban than a normal IP-limit ban, keep the global fallback and override only what you need:

```yaml
ban_duration: "30m"
ban_duration_ip_limit: "15m"
ban_duration_torrent: "24h"
```

### Remote Enforcement Example

If the real client traffic enters the infrastructure through remote edge or HAProxy hosts, you can explicitly define remote targets:

```yaml
remote_enforcement:
  enabled: true
  mode: "local_and_remote"
  connect_timeout: "10s"
  targets:
    - name: "edge-1"
      host: "198.51.100.10"
      port: 22
      user: "root"
      backend: "iptables"
    - name: "edge-2"
      host: "198.51.100.11"
      port: 22
      user: "root"
      backend: "iptables"
```

Supported modes:

- `local_only`
- `remote_only`
- `local_and_remote`

Use remote enforcement only when the client IP visible in Xray logs is trustworthy for the target topology.

### Admin Notification Example

If you want a separate admin webhook without client IP, enable the admin channel and select only the fields you care about:

```yaml
admin_notifications:
  enabled: true
  webhook_url: "https://example.com/admin-hook"
  headers:
    Authorization: "Bearer <token>"
  fields:
    - "reason"
    - "action"
    - "username"
    - "server"
    - "unique_ips"
    - "limit"
    - "window"
    - "ban_duration"
  notify_unban: false
```

### Admin Telegram Bot Example

If you want `iptblocker` to send a normal Telegram `sendMessage` body directly, use the admin template mode:

```yaml
admin_notifications:
  enabled: true
  webhook_url: "https://api.telegram.org/bot<token>/sendMessage"
  headers:
    Content-Type: "application/json"
  template_ip_limit: '{"chat_id":"123456789","text":"Subscription sharing detected.\n\nUser: {{username}}\nServer: {{server}}\nUnique IPs: {{unique_ips}}\nLimit: {{limit}}\nWindow: {{window}}\nAction: {{action}}\nBan duration: {{ban_duration}}"}'
  template_torrent: '{"chat_id":"123456789","text":"Torrent traffic detected.\n\nUser: {{username}}\nServer: {{server}}\nTag: {{torrent_tag}}\nSource: {{source}}\nAction: {{action}}\nBan duration: {{ban_duration}}"}'
  notify_unban: false
```

Supported admin template tokens:

- `{{reason}}`
- `{{action}}`
- `{{username}}`
- `{{processed_username}}`
- `{{server}}`
- `{{source}}`
- `{{ban_duration}}`
- `{{detected_at}}`
- `{{enforced_at}}`
- `{{expires_at}}`
- `{{unique_ips}}`
- `{{limit}}`
- `{{window}}`
- `{{torrent_tag}}`
- `{{distribution_scope}}`
- `{{distribution_full_success}}`
- `{{distribution_partial_failure}}`

If you do not configure `template`, `template_ip_limit`, or `template_torrent`, the admin channel falls back to JSON field mode and sends only the fields listed in `admin_notifications.fields`.

Example direct Telegram body for an `ip_limit` event:

```json
{"chat_id":"123456789","text":"Subscription sharing detected.\n\nUser: user.123456789\nServer: usa-edge-1\nUnique IPs: 10\nLimit: 1\nWindow: 5m0s\nAction: ban\nBan duration: 15m0s"}
```

Supported admin notification fields:

- `reason`
- `action`
- `username`
- `processed_username`
- `server`
- `source`
- `ban_duration`
- `detected_at`
- `enforced_at`
- `expires_at`
- `unique_ips`
- `limit`
- `window`
- `torrent_tag`
- `distribution_scope`
- `distribution_full_success`
- `distribution_partial_failure`

Reason-specific context:

- For `ip_limit`, the admin payload can include `unique_ips`, `limit`, and `window`
- For `torrent`, the admin payload can include `torrent_tag` and `source`
- `client_ip` is intentionally not included in the supported admin field list

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
