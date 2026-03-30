package banner

import (
	"fmt"
	"log/slog"
	"os/exec"
)

type Banner struct {
	mode   string
	dryRun bool
}

func New(mode string, dryRun bool) *Banner {
	return &Banner{mode: mode, dryRun: dryRun}
}

func (b *Banner) Ban(ip string) error {
	if b.dryRun {
		slog.Info("dry-run: would ban", "ip", ip)
		return nil
	}

	// Drop existing connections first so the block takes effect immediately.
	if err := b.conntrackDel(ip); err != nil {
		slog.Warn("conntrack del failed", "ip", ip, "err", err)
	}

	return b.addRule(ip)
}

func (b *Banner) Unban(ip string) error {
	if b.dryRun {
		slog.Info("dry-run: would unban", "ip", ip)
		return nil
	}
	return b.delRule(ip)
}

func (b *Banner) conntrackDel(ip string) error {
	return exec.Command("conntrack", "-D", "-s", ip).Run()
}

func (b *Banner) addRule(ip string) error {
	switch b.mode {
	case "nftables", "nft":
		return exec.Command("nft", "add", "element", "inet", "filter", "banned_ips", fmt.Sprintf("{ %s }", ip)).Run()
	default:
		return exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP").Run()
	}
}

func (b *Banner) delRule(ip string) error {
	switch b.mode {
	case "nftables", "nft":
		return exec.Command("nft", "delete", "element", "inet", "filter", "banned_ips", fmt.Sprintf("{ %s }", ip)).Run()
	default:
		return exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	}
}
