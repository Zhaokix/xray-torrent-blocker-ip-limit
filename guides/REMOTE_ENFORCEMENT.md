# Remote Enforcement Guide

This guide covers SSH-based remote enforcement on edge or HAProxy hosts.

## Example Configuration

```yaml
remote_enforcement:
  enabled: true
  mode: "local_and_remote"
  connect_timeout: "10s"
  ssh_config_path: "/opt/iptblocker/ssh_config"
  ssh_key_path: "/opt/iptblocker/id_ed25519"
  known_hosts_path: "/opt/iptblocker/known_hosts"
  use_sudo: true
  targets:
    - name: "edge-1"
      host: "edge-1"
      port: 22
      user: "iptblocker"
      backend: "iptables"
    - name: "edge-2"
      host: "198.51.100.11"
      port: 22
      user: "iptblocker"
      backend: "iptables"
```

Supported modes:

- `local_only`
- `remote_only`
- `local_and_remote`

Use remote enforcement only when the client IP visible in Xray logs is trustworthy for the target topology.

The SSH-related fields are optional. If you leave them empty and keep `use_sudo: false`, the old behavior remains:

```bash
ssh -p 2222 iptblocker@198.51.100.10 'iptables ...'
```

When you set `ssh_config_path`, `ssh_key_path`, `known_hosts_path`, or `use_sudo: true`, `iptblocker` switches to the extended SSH path.

## Operational Notes

- If `remote_enforcement.targets[].host` is an SSH alias like `edge-1`, it must match a `Host edge-1` block inside `ssh_config_path`.
- If `remote_enforcement.targets[].host` is a raw IP or hostname, `ssh_config_path` is optional. In that case `ssh_key_path` and `known_hosts_path` are usually enough.
- Set `use_sudo: true` when the remote user is allowed to run firewall commands only through passwordless `sudo`.
- For non-default SSH ports, `known_hosts` must contain an entry for the exact host and port, for example `[198.51.100.10]:2222`.

## SSH Key Setup

Generate a dedicated key on the node where `iptblocker` runs:

```bash
ssh-keygen -t ed25519 -f /opt/iptblocker/id_ed25519 -C "iptblocker remote enforcement"
chmod 600 /opt/iptblocker/id_ed25519
chmod 644 /opt/iptblocker/id_ed25519.pub
```

The service expects a non-interactive key. Do not use a passphrase-protected private key for unattended remote enforcement.

## SSH Config

Example `ssh_config` entry:

```sshconfig
Host edge-1
  HostName 198.51.100.10
  User iptblocker
  Port 22
  IdentityFile /opt/iptblocker/id_ed25519
  UserKnownHostsFile /opt/iptblocker/known_hosts
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
```

If you use an SSH alias like `edge-1`, set `host: "edge-1"` in `remote_enforcement.targets`.

## Remote User Setup

Create a dedicated remote user:

```bash
sudo useradd -m -s /bin/bash iptblocker
sudo mkdir -p /home/iptblocker/.ssh
sudo chmod 700 /home/iptblocker/.ssh
sudo chown -R iptblocker:iptblocker /home/iptblocker/.ssh
```

Install the public key:

```bash
sudo sh -c 'cat >> /home/iptblocker/.ssh/authorized_keys' < /opt/iptblocker/id_ed25519.pub
sudo chmod 600 /home/iptblocker/.ssh/authorized_keys
sudo chown iptblocker:iptblocker /home/iptblocker/.ssh/authorized_keys
```

## Sudo Rules

For `iptables` targets:

```bash
sudo tee /etc/sudoers.d/iptblocker >/dev/null <<'EOF'
iptblocker ALL=(root) NOPASSWD: /usr/sbin/iptables, /sbin/iptables, /usr/bin/iptables, /usr/sbin/conntrack, /sbin/conntrack, /usr/bin/conntrack
EOF
sudo chmod 440 /etc/sudoers.d/iptblocker
```

`iptables` remote enforcement now ensures the `raw/PREROUTING` hook exists on the target and also tries to clear `conntrack` entries for the banned IP. If `conntrack` is unavailable or not permitted, the ban rule is still applied but existing sessions may survive until they expire.

For `nftables` targets:

```bash
sudo tee /etc/sudoers.d/iptblocker >/dev/null <<'EOF'
iptblocker ALL=(root) NOPASSWD: /usr/sbin/nft, /sbin/nft, /usr/bin/nft
EOF
sudo chmod 440 /etc/sudoers.d/iptblocker
```

## Recommended SSH Layout

Keep SSH material inside `/opt/iptblocker`:

```text
/opt/iptblocker/
  id_ed25519
  id_ed25519.pub
  ssh_config
  known_hosts
```

Example `ssh_config`:

```sshconfig
Host edge-1
  HostName 198.51.100.10
  User iptblocker
  Port 22
  IdentityFile /opt/iptblocker/id_ed25519
  UserKnownHostsFile /opt/iptblocker/known_hosts
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
```

Populate `known_hosts`:

```bash
ssh-keyscan -p 22 -H 198.51.100.10 >> /opt/iptblocker/known_hosts
chmod 600 /opt/iptblocker/known_hosts
```

For a non-default SSH port, include the port explicitly:

```bash
ssh-keyscan -p 2222 -H 198.51.100.10 >> /opt/iptblocker/known_hosts
chmod 600 /opt/iptblocker/known_hosts
```

## Smoke Check

Before enabling remote enforcement in `config.yaml`, verify SSH access manually from the `iptblocker` node using the same SSH material that the daemon will use.

### `iptables` target with `ssh_config_path`

```bash
sudo ssh -F /opt/iptblocker/ssh_config edge-1 'sudo iptables -t raw -S XRAY_IP_LIMIT_BLOCKED'
```

### `nftables` target with `ssh_config_path`

```bash
sudo ssh -F /opt/iptblocker/ssh_config edge-1 'sudo nft list ruleset'
```

### Raw host without SSH alias

If `remote_enforcement.targets[].host` is not an alias from `ssh_config`, verify using the key and known_hosts files directly:

```bash
sudo ssh -i /opt/iptblocker/id_ed25519 \
  -o UserKnownHostsFile=/opt/iptblocker/known_hosts \
  -o StrictHostKeyChecking=yes \
  -p 2222 iptblocker@198.51.100.10 \
  'sudo iptables -t raw -S XRAY_IP_LIMIT_BLOCKED'
```

### What must work before enabling remote enforcement

- SSH must connect without interactive questions
- the remote command must run successfully with the same key/config files that `iptblocker` will use
- if you rely on `sudo`, the remote user must be able to run the firewall command without a password

If the manual smoke-check command fails, `iptblocker` remote enforcement will also fail.
