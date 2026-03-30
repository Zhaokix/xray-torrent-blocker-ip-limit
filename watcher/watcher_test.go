package watcher

import (
	"testing"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/firewall"
	"xray-ip-limit/storage"
)

func TestProcessLineBansNewestIPAfterLimit(t *testing.T) {
	cfg := config.Default()
	cfg.IPLimit = 2
	cfg.Window = 10 * time.Minute
	cfg.BanDuration = 30 * time.Minute

	fw, err := firewall.NewManager("iptables", true)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	st, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("storage.New returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	w := New(cfg, st, fw)
	email := "user@example.com"

	w.processLine(`2026/03/30 10:00:00 from tcp:203.0.113.1:443 accepted email: ` + email)
	w.processLine(`2026/03/30 10:00:01 from tcp:203.0.113.2:443 accepted email: ` + email)

	if st.IsBanned("203.0.113.1") || st.IsBanned("203.0.113.2") {
		t.Fatal("expected first two IPs to remain unbanned within limit")
	}

	w.processLine(`2026/03/30 10:00:02 from tcp:203.0.113.3:443 accepted email: ` + email)

	if !st.IsBanned("203.0.113.3") {
		t.Fatal("expected newest IP to be banned after limit exceeded")
	}

	if w.detector.ActiveCount(email) != 2 {
		t.Fatalf("expected active window to keep two IPs after banning newest one, got %d", w.detector.ActiveCount(email))
	}
	if w.detector.HasActiveIP(email, "203.0.113.3") {
		t.Fatal("expected banned IP to be removed from detector window")
	}
}
