package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
)

const (
	ipTablesChain = "XRAY_IP_LIMIT_BLOCKED"
)

var ipTablesRulePattern = regexp.MustCompile(`-A\s+` + ipTablesChain + `\s+-s\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:/32)?\s+-j\s+DROP`)

type ipTablesBackend struct{}

func newIPTablesBackend() Backend {
	return &ipTablesBackend{}
}

func (b *ipTablesBackend) Name() string {
	return "iptables"
}

func (b *ipTablesBackend) EnsureSetup() error {
	if !b.chainExists() {
		if err := runCommand("iptables", "-w", "-N", ipTablesChain); err != nil {
			return fmt.Errorf("create iptables chain: %w", err)
		}
	}

	if err := runCommand("iptables", "-w", "-C", "INPUT", "-j", ipTablesChain); err != nil {
		if err := runCommand("iptables", "-w", "-I", "INPUT", "1", "-j", ipTablesChain); err != nil {
			return fmt.Errorf("add iptables jump rule: %w", err)
		}
	}

	return nil
}

func (b *ipTablesBackend) Ban(ip string) error {
	if err := b.EnsureSetup(); err != nil {
		return err
	}

	if err := runCommand("iptables", "-w", "-C", ipTablesChain, "-s", ip, "-j", "DROP"); err == nil {
		return nil
	}

	if err := runCommand("iptables", "-w", "-A", ipTablesChain, "-s", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("block ip with iptables: %w", err)
	}

	return nil
}

func (b *ipTablesBackend) Unban(ip string) error {
	if err := b.EnsureSetup(); err != nil {
		return err
	}

	if err := runCommand("iptables", "-w", "-C", ipTablesChain, "-s", ip, "-j", "DROP"); err != nil {
		return nil
	}

	if err := runCommand("iptables", "-w", "-D", ipTablesChain, "-s", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("unblock ip with iptables: %w", err)
	}

	return nil
}

func (b *ipTablesBackend) ListBlocked() (map[string]struct{}, error) {
	if err := b.EnsureSetup(); err != nil {
		return nil, err
	}

	cmd := exec.Command("iptables", "-w", "-S", ipTablesChain)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list iptables rules: %w", err)
	}

	blocked := make(map[string]struct{})
	matches := ipTablesRulePattern.FindAllSubmatch(output, -1)
	for _, match := range matches {
		if len(match) > 1 {
			blocked[string(match[1])] = struct{}{}
		}
	}

	return blocked, nil
}

func (b *ipTablesBackend) chainExists() bool {
	cmd := exec.Command("iptables", "-w", "-S", ipTablesChain)
	return cmd.Run() == nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, stderr.String())
		}
		return err
	}
	return nil
}

