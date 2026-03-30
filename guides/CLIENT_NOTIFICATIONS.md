# Client Notifications Guide

This guide covers the client-facing webhook channel configured through `send_webhook`.

## Main Fields

- `send_webhook`
- `webhook_url`
- `webhook_template`
- `webhook_template_ip_limit`
- `webhook_template_torrent`
- `webhook_notify_ip_limit`
- `webhook_notify_torrent`
- `webhook_notify_unban`
- `webhook_headers`
- `webhook_username_regex`
- `webhook_server_name`

## Generic Webhook Example

```yaml
send_webhook: true
webhook_url: "https://example.com/hook"
webhook_template: '{"email":"%s","ip":"%s","server":"%s","action":"%s","duration":"%s"}'
webhook_notify_ip_limit: true
webhook_notify_torrent: true
webhook_notify_unban: false
webhook_server_name: "usa-edge-1"
```

All client webhook templates receive placeholders in this order:

1. processed username
2. client IP
3. server name
4. action
5. ban duration

## Telegram Example

If your user identifier looks like `user.123456789` and the Telegram chat ID is the numeric suffix after the dot:

```yaml
send_webhook: true
webhook_url: "https://api.telegram.org/bot<token>/sendMessage"
webhook_template: '{"chat_id":"%s","text":"Subscription sharing detected.\n\nIP: %s\nServer: %s\nAction: %s\nBan: %s"}'
webhook_username_regex: '^\d+\.(\d+)$'
webhook_notify_unban: false
```

## Reason-Specific Templates

```yaml
webhook_template: '{"chat_id":"%s","text":"IP: %s\nServer: %s\nAction: %s\nDuration: %s"}'
webhook_template_ip_limit: '{"chat_id":"%s","text":"Sharing detected.\nIP: %s\nServer: %s\nAction: %s\nBan: %s"}'
webhook_template_torrent: '{"chat_id":"%s","text":"Torrent traffic detected.\nIP: %s\nServer: %s\nAction: %s\nBan: %s"}'
webhook_notify_ip_limit: true
webhook_notify_torrent: false
```
