# Configuration Guide

This guide covers the main runtime behavior of `iptblocker` and the most important config fields in `config.yaml`.

## Core Fields

- `log_file`: path to the Xray access log
- `ip_limit`: max unique IPs allowed per identifier inside the window
- `window`: sliding duration used for unique IP counting
- `ban_duration`: global fallback ban duration
- `ban_duration_ip_limit`: optional override for `ip_limit` bans
- `ban_duration_torrent`: optional override for `torrent` bans
- `ban_mode`: `iptables`, `nftables`, or `nft`
- `dry_run`: when `true`, no local or remote firewall changes are applied
- `storage_dir`: local SQLite state directory

## Minimal Example

```yaml
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "10m"
ban_duration: "1h"
ban_mode: "iptables"
dry_run: false
storage_dir: "/opt/iptblocker"
```

## Torrent Detection

Enable torrent-triggered bans from tagged Xray log lines:

```yaml
enable_torrent_detection: true
torrent_tag: "TORRENT"
```

The current implementation expects the tagged line to still contain:

- the client address in `from ...`
- the subscription identifier in `email: ...`

## Reason-Specific Ban Durations

If you want a stricter torrent ban than a normal IP-limit ban:

```yaml
ban_duration: "30m"
ban_duration_ip_limit: "15m"
ban_duration_torrent: "24h"
```

## Bypass Lists

Never ban specific IPs:

```yaml
bypass_ips:
  - "127.0.0.1"
  - "::1"
```

Never ban specific usernames:

```yaml
bypass_emails:
  - "admin@example.com"
```

Never ban specific processed usernames after `webhook_username_regex` is applied:

```yaml
webhook_username_regex: '^\d+\.(\d+)$'
bypass_processed_usernames:
  - "7679754426"
```

This is useful when your raw identifier in the Xray log looks like `123412312.7679754426`, but you want the bypass rule to match only the Telegram ID suffix.
