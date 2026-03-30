package watcher

import (
	"testing"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/firewall"
	"xray-ip-limit/storage"
)

func TestParseLineParsesIPv4WithTransportPrefix(t *testing.T) {
	line := `2026/03/30 10:00:00 from tcp:203.0.113.10:443 accepted email: user@example.com`

	ip, email, ok := parseLine(line)
	if !ok {
		t.Fatal("expected parseLine to succeed")
	}
	if ip != "203.0.113.10" {
		t.Fatalf("expected IP 203.0.113.10, got %q", ip)
	}
	if email != "user@example.com" {
		t.Fatalf("expected email user@example.com, got %q", email)
	}
}

func TestParseLineReturnsIPWithoutEmail(t *testing.T) {
	line := `2026/03/30 10:00:00 from udp:203.0.113.11:53 accepted`

	ip, email, ok := parseLine(line)
	if !ok {
		t.Fatal("expected parseLine to succeed")
	}
	if ip != "203.0.113.11" {
		t.Fatalf("expected IP 203.0.113.11, got %q", ip)
	}
	if email != "" {
		t.Fatalf("expected empty email, got %q", email)
	}
}

func TestParseLineRejectsInvalidInput(t *testing.T) {
	testCases := []string{
		`2026/03/30 accepted email: user@example.com`,
		`2026/03/30 from tcp:not-an-ip:443 accepted email: user@example.com`,
		`2026/03/30 from tcp: accepted email: user@example.com`,
	}

	for _, tc := range testCases {
		if _, _, ok := parseLine(tc); ok {
			t.Fatalf("expected parseLine to reject %q", tc)
		}
	}
}

func TestParseLineParsesIPv6(t *testing.T) {
	line := `2026/03/30 10:00:00 from tcp:[2001:db8::1]:443 accepted email: user@example.com`

	ip, email, ok := parseLine(line)
	if !ok {
		t.Fatal("expected parseLine to succeed for IPv6")
	}
	if ip != "2001:db8::1" {
		t.Fatalf("expected IPv6 2001:db8::1, got %q", ip)
	}
	if email != "user@example.com" {
		t.Fatalf("expected email user@example.com, got %q", email)
	}
}

func TestParseClientIPRejectsGarbage(t *testing.T) {
	if _, ok := parseClientIP("not-an-ip:443"); ok {
		t.Fatal("expected parseClientIP to reject invalid address")
	}
	if _, ok := parseClientIP("203.0.113.20:"); ok {
		t.Fatal("expected parseClientIP to reject malformed host:port")
	}
}

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

	if len(w.windows[email]) != 2 {
		t.Fatalf("expected active window to keep two IPs after banning newest one, got %d", len(w.windows[email]))
	}
	if _, exists := w.windows[email]["203.0.113.3"]; exists {
		t.Fatal("expected banned IP to be removed from active window")
	}
}
