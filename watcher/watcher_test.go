package watcher

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestProcessLineBansTorrentTaggedIPImmediately(t *testing.T) {
	cfg := config.Default()
	cfg.IPLimit = 10
	cfg.Window = 10 * time.Minute
	cfg.BanDuration = 30 * time.Minute
	cfg.EnableTorrentDetection = true
	cfg.TorrentTag = "TORRENT"

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
	email := "torrent@example.com"

	w.processLine(`2026/03/30 10:00:00 from tcp:203.0.113.9:443 accepted email: ` + email + ` outboundTag=TORRENT`)

	if !st.IsBanned("203.0.113.9") {
		t.Fatal("expected torrent-tagged IP to be banned immediately")
	}

	active, err := st.ActiveBans()
	if err != nil {
		t.Fatalf("ActiveBans returned error: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected one active ban, got %d", len(active))
	}
	if active[0].Reason != "torrent" {
		t.Fatalf("expected torrent reason, got %q", active[0].Reason)
	}
	if active[0].ProcessedUsername != email {
		t.Fatalf("expected processed username %q, got %q", email, active[0].ProcessedUsername)
	}
	if active[0].Source != cfg.LogFile {
		t.Fatalf("expected source %q, got %q", cfg.LogFile, active[0].Source)
	}
	if active[0].DetectedAt.IsZero() || active[0].EnforcedAt.IsZero() {
		t.Fatal("expected detected_at and enforced_at to be stored")
	}
}

func TestProcessLineSendsAdminNotificationForIPLimit(t *testing.T) {
	requestBody := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		requestBody <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.IPLimit = 1
	cfg.Window = 5 * time.Minute
	cfg.BanDuration = 15 * time.Minute
	cfg.AdminNotifications.Enabled = true
	cfg.AdminNotifications.WebhookURL = server.URL
	cfg.AdminNotifications.Fields = []string{"reason", "username", "client_ip", "server", "unique_ips", "limit", "window", "ban_duration"}
	cfg.WebhookServerName = "usa-edge-1"

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

	select {
	case payload := <-requestBody:
		if payload["reason"] != "ip_limit" {
			t.Fatalf("expected reason ip_limit, got %#v", payload["reason"])
		}
		if payload["username"] != email {
			t.Fatalf("expected username %q, got %#v", email, payload["username"])
		}
		if payload["client_ip"] != "203.0.113.2" {
			t.Fatalf("expected client_ip 203.0.113.2, got %#v", payload["client_ip"])
		}
		if payload["server"] != "usa-edge-1" {
			t.Fatalf("expected server usa-edge-1, got %#v", payload["server"])
		}
		if payload["ban_duration"] != "15m0s" {
			t.Fatalf("expected ban_duration 15m0s, got %#v", payload["ban_duration"])
		}
		if got, ok := payload["unique_ips"].(float64); !ok || got != 2 {
			t.Fatalf("expected unique_ips 2, got %#v", payload["unique_ips"])
		}
		if got, ok := payload["limit"].(float64); !ok || got != 1 {
			t.Fatalf("expected limit 1, got %#v", payload["limit"])
		}
		if payload["window"] != "5m0s" {
			t.Fatalf("expected window 5m0s, got %#v", payload["window"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected admin notification to be received")
	}
}

func TestProcessLineSkipsBanForProcessedUsernameBypass(t *testing.T) {
	cfg := config.Default()
	cfg.IPLimit = 1
	cfg.Window = 10 * time.Minute
	cfg.BanDuration = 30 * time.Minute
	cfg.WebhookUsernameRegex = `^\d+\.(\d+)$`
	cfg.BypassProcessedUsers = []string{"7679754426"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

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
	email := "123412312.7679754426"

	w.processLine(`2026/03/30 10:00:00 from tcp:203.0.113.1:443 accepted email: ` + email)
	w.processLine(`2026/03/30 10:00:01 from tcp:203.0.113.2:443 accepted email: ` + email)

	if st.IsBanned("203.0.113.2") {
		t.Fatal("expected processed username bypass to skip banning")
	}

	active, err := st.ActiveBans()
	if err != nil {
		t.Fatalf("ActiveBans returned error: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active bans, got %d", len(active))
	}
}

func TestProcessLineTorrentIgnoresProcessedUsernameBypass(t *testing.T) {
	cfg := config.Default()
	cfg.EnableTorrentDetection = true
	cfg.TorrentTag = "TORRENT"
	cfg.WebhookUsernameRegex = `^\d+\.(\d+)$`
	cfg.BypassProcessedUsers = []string{"7679754426"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

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
	email := "123412312.7679754426"

	w.processLine(`2026/03/30 10:00:00 from tcp:203.0.113.9:443 accepted email: ` + email + ` outboundTag=TORRENT`)

	if !st.IsBanned("203.0.113.9") {
		t.Fatal("expected torrent detection to ignore processed username bypass")
	}
}
