package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

const (
	nftTableName = "xray_ip_limit"
	nftChainName = "input"
	nftSetName   = "banned_ips"
)

var nftIPPattern = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)

type nfTablesBackend struct{}

func newNFTablesBackend() Backend {
	return &nfTablesBackend{}
}

func (b *nfTablesBackend) Name() string {
	return "nftables"
}

func (b *nfTablesBackend) EnsureSetup() error {
	if !b.tableExists() {
		if err := runCommand("nft", "add", "table", "inet", nftTableName); err != nil {
			return fmt.Errorf("create nft table: %w", err)
		}
	}

	if !b.chainExists() {
		if err := runCommand("nft", "add", "chain", "inet", nftTableName, nftChainName, "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"); err != nil {
			return fmt.Errorf("create nft chain: %w", err)
		}
	}

	if !b.setExists() {
		if err := runCommand("nft", "add", "set", "inet", nftTableName, nftSetName, "{", "type", "ipv4_addr", ";", "}"); err != nil {
			return fmt.Errorf("create nft set: %w", err)
		}
	}

	if !b.ruleExists() {
		if err := runCommand("nft", "add", "rule", "inet", nftTableName, nftChainName, "ip", "saddr", "@"+nftSetName, "drop"); err != nil {
			return fmt.Errorf("create nft rule: %w", err)
		}
	}

	return nil
}

func (b *nfTablesBackend) Ban(ip string) error {
	if err := b.EnsureSetup(); err != nil {
		return err
	}

	if err := runCommand("nft", "add", "element", "inet", nftTableName, nftSetName, "{", ip, "}"); err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return fmt.Errorf("block ip with nftables: %w", err)
	}

	return nil
}

func (b *nfTablesBackend) Unban(ip string) error {
	if err := b.EnsureSetup(); err != nil {
		return err
	}

	if err := runCommand("nft", "delete", "element", "inet", nftTableName, nftSetName, "{", ip, "}"); err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return nil
		}
		return fmt.Errorf("unblock ip with nftables: %w", err)
	}

	return nil
}

func (b *nfTablesBackend) ListBlocked() (map[string]struct{}, error) {
	if err := b.EnsureSetup(); err != nil {
		return nil, err
	}

	cmd := exec.Command("nft", "list", "set", "inet", nftTableName, nftSetName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list nft set: %w", err)
	}

	blocked := make(map[string]struct{})
	matches := nftIPPattern.FindAllSubmatch(output, -1)
	for _, match := range matches {
		if len(match) > 1 {
			blocked[string(match[1])] = struct{}{}
		}
	}

	return blocked, nil
}

func (b *nfTablesBackend) tableExists() bool {
	return exec.Command("nft", "list", "table", "inet", nftTableName).Run() == nil
}

func (b *nfTablesBackend) chainExists() bool {
	return exec.Command("nft", "list", "chain", "inet", nftTableName, nftChainName).Run() == nil
}

func (b *nfTablesBackend) setExists() bool {
	return exec.Command("nft", "list", "set", "inet", nftTableName, nftSetName).Run() == nil
}

func (b *nfTablesBackend) ruleExists() bool {
	cmd := exec.Command("nft", "list", "chain", "inet", nftTableName, nftChainName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return bytes.Contains(output, []byte("@"+nftSetName)) && bytes.Contains(output, []byte("drop"))
}
