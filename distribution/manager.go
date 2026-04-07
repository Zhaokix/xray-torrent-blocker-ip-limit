package distribution

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/events"
	"xray-ip-limit/firewall"
)

type Manager struct {
	cfg    config.RemoteEnforcement
	dryRun bool
	local  *firewall.Manager
	runner Runner
}

func NewManager(cfg *config.Config, local *firewall.Manager) *Manager {
	var runner Runner = SSHRunner{}
	if strings.TrimSpace(cfg.RemoteEnforcement.SSHConfigPath) != "" ||
		strings.TrimSpace(cfg.RemoteEnforcement.SSHKeyPath) != "" ||
		strings.TrimSpace(cfg.RemoteEnforcement.KnownHostsPath) != "" {
		runner = ConfiguredSSHRunner{cfg: cfg.RemoteEnforcement}
	}
	return &Manager{
		cfg:    cfg.RemoteEnforcement,
		dryRun: cfg.DryRun,
		local:  local,
		runner: runner,
	}
}

func newManagerWithRunner(cfg *config.Config, local *firewall.Manager, runner Runner) *Manager {
	return &Manager{
		cfg:    cfg.RemoteEnforcement,
		dryRun: cfg.DryRun,
		local:  local,
		runner: runner,
	}
}

func (m *Manager) Apply(event events.Event) Result {
	scope := Scope(strings.ToLower(strings.TrimSpace(m.cfg.Mode)))
	result := Result{
		Scope:    scope,
		Reason:   event.Reason,
		ClientIP: event.ClientIP,
	}

	if scope == ScopeLocalOnly || scope == ScopeLocalAndRemote || !m.cfg.Enabled {
		result.LocalAttempted = true
		if err := m.local.Ban(event.ClientIP); err != nil {
			result.LocalError = err.Error()
		} else {
			result.LocalApplied = true
		}
	}

	if m.cfg.Enabled && (scope == ScopeRemoteOnly || scope == ScopeLocalAndRemote) {
		result.TargetResults = m.applyRemote(event, events.ActionBan)
	}

	summarizeResult(&result)
	return result
}

func (m *Manager) Revoke(event events.Event) Result {
	scope := Scope(strings.ToLower(strings.TrimSpace(m.cfg.Mode)))
	result := Result{
		Scope:    scope,
		Reason:   event.Reason,
		ClientIP: event.ClientIP,
	}

	if scope == ScopeLocalOnly || scope == ScopeLocalAndRemote || !m.cfg.Enabled {
		result.LocalAttempted = true
		if err := m.local.Unban(event.ClientIP); err != nil {
			result.LocalError = err.Error()
		} else {
			result.LocalApplied = true
		}
	}

	if m.cfg.Enabled && (scope == ScopeRemoteOnly || scope == ScopeLocalAndRemote) {
		result.TargetResults = m.applyRemote(event, events.ActionUnban)
	}

	summarizeResult(&result)
	return result
}

func (m *Manager) applyRemote(event events.Event, action events.Action) []TargetResult {
	results := make([]TargetResult, 0, len(m.cfg.Targets))
	for _, target := range m.cfg.Targets {
		startedAt := time.Now()
		if m.dryRun {
			slog.Info("dry-run: would apply remote enforcement", "target", target.Name, "host", target.Host, "action", action, "ip", event.ClientIP, "backend", effectiveBackend(target))
			results = append(results, TargetResult{
				TargetName: target.Name,
				Host:       target.Host,
				Action:     action,
				Success:    true,
				StartedAt:  startedAt,
				FinishedAt: time.Now(),
			})
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), m.cfg.ConnectTimeout)
		err := m.runner.Run(ctx, target, remoteCommand(action, m.cfg, target, event.ClientIP))
		cancel()

		targetResult := TargetResult{
			TargetName: target.Name,
			Host:       target.Host,
			Action:     action,
			StartedAt:  startedAt,
			FinishedAt: time.Now(),
		}
		if err != nil {
			targetResult.ErrorKind = "ssh_execution"
			targetResult.ErrorText = err.Error()
		} else {
			targetResult.Success = true
		}
		results = append(results, targetResult)
	}
	return results
}

func remoteCommand(action events.Action, cfg config.RemoteEnforcement, target config.RemoteTarget, ip string) string {
	commandPrefix := ""
	if cfg.UseSudo {
		commandPrefix = "sudo "
	}

	switch strings.ToLower(strings.TrimSpace(effectiveBackend(target))) {
	case "nftables", "nft":
		if action == events.ActionBan {
			return fmt.Sprintf("%snft add element inet xray_ip_limit banned_ips { %s }", commandPrefix, ip)
		}
		return fmt.Sprintf("%snft delete element inet xray_ip_limit banned_ips { %s }", commandPrefix, ip)
	default:
		if action == events.ActionBan {
			return fmt.Sprintf("%siptables -C XRAY_IP_LIMIT_BLOCKED -s %s -j DROP >/dev/null 2>&1 || %siptables -I XRAY_IP_LIMIT_BLOCKED -s %s -j DROP", commandPrefix, ip, commandPrefix, ip)
		}
		return fmt.Sprintf("%siptables -D XRAY_IP_LIMIT_BLOCKED -s %s -j DROP >/dev/null 2>&1 || true", commandPrefix, ip)
	}
}

func effectiveBackend(target config.RemoteTarget) string {
	if strings.TrimSpace(target.Backend) != "" {
		return target.Backend
	}
	return "iptables"
}

func summarizeResult(result *Result) {
	requiredLocal := result.Scope == ScopeLocalOnly || result.Scope == ScopeLocalAndRemote
	requiredRemote := result.Scope == ScopeRemoteOnly || result.Scope == ScopeLocalAndRemote

	localOK := !requiredLocal || result.LocalApplied
	remoteOK := !requiredRemote
	remoteFailures := 0
	if requiredRemote {
		remoteOK = len(result.TargetResults) > 0
		for _, target := range result.TargetResults {
			if !target.Success {
				remoteOK = false
				remoteFailures++
			}
		}
	}

	result.FullySuccessful = localOK && remoteOK
	result.PartiallyFailed = result.AnyApplied() && !result.FullySuccessful
}
