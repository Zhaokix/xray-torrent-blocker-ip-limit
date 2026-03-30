# Remote Enforcement Guide

This guide covers SSH-based remote enforcement on edge or HAProxy hosts.

## Example Configuration

```yaml
remote_enforcement:
  enabled: true
  mode: "local_and_remote"
  connect_timeout: "10s"
  targets:
    - name: "edge-1"
      host: "198.51.100.10"
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

## SSH Key Setup

Generate a dedicated key on the node where `iptblocker` runs:

```bash
ssh-keygen -t ed25519 -f /opt/iptblocker/id_ed25519 -C "iptblocker remote enforcement"
chmod 600 /opt/iptblocker/id_ed25519
chmod 644 /opt/iptblocker/id_ed25519.pub
```

## SSH Config

Example `/root/.ssh/config` entry:

```sshconfig
Host edge-1
  HostName 198.51.100.10
  User iptblocker
  Port 22
  IdentityFile /opt/iptblocker/id_ed25519
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking yes
```

If you use an SSH alias like `edge-1`, you can set `host: "edge-1"` in `remote_enforcement.targets`.

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
iptblocker ALL=(root) NOPASSWD: /usr/sbin/iptables, /sbin/iptables
EOF
sudo chmod 440 /etc/sudoers.d/iptblocker
```

For `nftables` targets:

```bash
sudo tee /etc/sudoers.d/iptblocker >/dev/null <<'EOF'
iptblocker ALL=(root) NOPASSWD: /usr/sbin/nft, /sbin/nft, /usr/bin/nft
EOF
sudo chmod 440 /etc/sudoers.d/iptblocker
```

## Smoke Check

Before enabling remote enforcement in `config.yaml`, verify SSH access manually from the `iptblocker` node:

```bash
ssh edge-1 'sudo iptables -S XRAY_IP_LIMIT_BLOCKED'
```

Or for `nftables`:

```bash
ssh edge-1 'sudo nft list ruleset'
```

## More Production-Friendly SSH Layout

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
ssh-keyscan -H 198.51.100.10 >> /opt/iptblocker/known_hosts
chmod 600 /opt/iptblocker/known_hosts
```

Systemd override:

```bash
sudo systemctl edit iptblocker
```

```ini
[Service]
Environment="HOME=/opt/iptblocker"
Environment="GIT_SSH_COMMAND=ssh -F /opt/iptblocker/ssh_config"
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart iptblocker
```
