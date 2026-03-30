package firewall

import "testing"

func TestNewManagerDryRunSupportsKnownBackends(t *testing.T) {
	testCases := []struct {
		mode string
		name string
	}{
		{mode: "iptables", name: "iptables"},
		{mode: "nft", name: "nftables"},
		{mode: "nftables", name: "nftables"},
	}

	for _, tc := range testCases {
		manager, err := NewManager(tc.mode, true)
		if err != nil {
			t.Fatalf("NewManager(%q, true) returned error: %v", tc.mode, err)
		}
		if manager.Name() != tc.name {
			t.Fatalf("expected backend name %q for mode %q, got %q", tc.name, tc.mode, manager.Name())
		}
	}
}

func TestNewManagerRejectsUnknownBackend(t *testing.T) {
	if _, err := NewManager("unknown-backend", true); err == nil {
		t.Fatal("expected unknown backend to return error")
	}
}

func TestDryRunListBlockedReturnsEmptySet(t *testing.T) {
	manager, err := NewManager("iptables", true)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	blocked, err := manager.ListBlocked()
	if err != nil {
		t.Fatalf("ListBlocked returned error: %v", err)
	}
	if len(blocked) != 0 {
		t.Fatalf("expected empty blocked set in dry-run mode, got %d entries", len(blocked))
	}
}
