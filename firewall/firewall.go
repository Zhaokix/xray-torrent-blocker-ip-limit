package firewall

import (
	"fmt"
	"log/slog"
	"strings"
)

type Backend interface {
	EnsureSetup() error
	Ban(ip string) error
	Unban(ip string) error
	ListBlocked() (map[string]struct{}, error)
	Name() string
}

type Manager struct {
	backend Backend
	dryRun  bool
}

func NewManager(mode string, dryRun bool) (*Manager, error) {
	backend, err := newBackend(mode)
	if err != nil {
		return nil, err
	}

	if !dryRun {
		if err := backend.EnsureSetup(); err != nil {
			return nil, err
		}
	}

	return &Manager{
		backend: backend,
		dryRun:  dryRun,
	}, nil
}

func (m *Manager) Name() string {
	return m.backend.Name()
}

func (m *Manager) Ban(ip string) error {
	if m.dryRun {
		slog.Info("dry-run: would ban", "ip", ip, "backend", m.backend.Name())
		return nil
	}

	if err := conntrackDel(ip); err != nil {
		slog.Warn("conntrack del failed", "ip", ip, "err", err)
	}

	return m.backend.Ban(ip)
}

func (m *Manager) Unban(ip string) error {
	if m.dryRun {
		slog.Info("dry-run: would unban", "ip", ip, "backend", m.backend.Name())
		return nil
	}

	return m.backend.Unban(ip)
}

func (m *Manager) ListBlocked() (map[string]struct{}, error) {
	if m.dryRun {
		return map[string]struct{}{}, nil
	}

	return m.backend.ListBlocked()
}

func newBackend(mode string) (Backend, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "iptables", "":
		return newIPTablesBackend(), nil
	case "nftables", "nft":
		return newNFTablesBackend(), nil
	default:
		return nil, fmt.Errorf("unsupported firewall backend %q", mode)
	}
}
