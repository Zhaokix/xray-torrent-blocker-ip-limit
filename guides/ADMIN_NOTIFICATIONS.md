# Admin Notifications Guide

This guide covers the separate admin notification channel configured through `admin_notifications`.

## Main Fields

- `admin_notifications.enabled`
- `admin_notifications.webhook_url`
- `admin_notifications.headers`
- `admin_notifications.fields`
- `admin_notifications.template`
- `admin_notifications.template_ip_limit`
- `admin_notifications.template_torrent`
- `admin_notifications.notify_unban`

## JSON Field Mode

If you want a structured admin webhook:

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
    - "client_ip"
    - "server"
    - "unique_ips"
    - "limit"
    - "window"
    - "ban_duration"
  notify_unban: false
```

Supported fields:

- `reason`
- `action`
- `username`
- `processed_username`
- `client_ip`
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

## Template Mode

If you want `iptblocker` to send a normal Telegram `sendMessage` body directly:

```yaml
admin_notifications:
  enabled: true
  webhook_url: "https://api.telegram.org/bot<token>/sendMessage"
  headers:
    Content-Type: "application/json"
  template_ip_limit: '{"chat_id":"123456789","text":"Subscription sharing detected.\n\nUser: {{username}}\nIP: {{client_ip}}\nServer: {{server}}\nUnique IPs: {{unique_ips}}\nLimit: {{limit}}\nWindow: {{window}}\nAction: {{action}}\nBan duration: {{ban_duration}}"}'
  template_torrent: '{"chat_id":"123456789","text":"Torrent traffic detected.\n\nUser: {{username}}\nIP: {{client_ip}}\nServer: {{server}}\nTag: {{torrent_tag}}\nSource: {{source}}\nAction: {{action}}\nBan duration: {{ban_duration}}"}'
  notify_unban: false
```

## Supported Template Tokens

- `{{reason}}`
- `{{action}}`
- `{{username}}`
- `{{processed_username}}`
- `{{client_ip}}`
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

## Reason-Specific Context

For `ip_limit` notifications:

- `unique_ips`
- `limit`
- `window`

For `torrent` notifications:

- `torrent_tag`
- `source`
