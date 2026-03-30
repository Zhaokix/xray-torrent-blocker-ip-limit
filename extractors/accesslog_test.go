package extractors

import "testing"

func TestParseXrayAccessLogLineParsesIPv4WithTransportPrefix(t *testing.T) {
	line := `2026/03/30 10:00:00 from tcp:203.0.113.10:443 accepted email: user@example.com`

	entry, ok := ParseXrayAccessLogLine(line)
	if !ok {
		t.Fatal("expected parser to succeed")
	}
	if entry.ClientIP != "203.0.113.10" {
		t.Fatalf("expected IP 203.0.113.10, got %q", entry.ClientIP)
	}
	if entry.Username != "user@example.com" {
		t.Fatalf("expected username user@example.com, got %q", entry.Username)
	}
}

func TestParseXrayAccessLogLineReturnsIPWithoutUsername(t *testing.T) {
	line := `2026/03/30 10:00:00 from udp:203.0.113.11:53 accepted`

	entry, ok := ParseXrayAccessLogLine(line)
	if !ok {
		t.Fatal("expected parser to succeed")
	}
	if entry.ClientIP != "203.0.113.11" {
		t.Fatalf("expected IP 203.0.113.11, got %q", entry.ClientIP)
	}
	if entry.Username != "" {
		t.Fatalf("expected empty username, got %q", entry.Username)
	}
}

func TestParseXrayAccessLogLineRejectsInvalidInput(t *testing.T) {
	testCases := []string{
		`2026/03/30 accepted email: user@example.com`,
		`2026/03/30 from tcp:not-an-ip:443 accepted email: user@example.com`,
		`2026/03/30 from tcp: accepted email: user@example.com`,
	}

	for _, tc := range testCases {
		if _, ok := ParseXrayAccessLogLine(tc); ok {
			t.Fatalf("expected parser to reject %q", tc)
		}
	}
}

func TestParseXrayAccessLogLineParsesIPv6(t *testing.T) {
	line := `2026/03/30 10:00:00 from tcp:[2001:db8::1]:443 accepted email: user@example.com`

	entry, ok := ParseXrayAccessLogLine(line)
	if !ok {
		t.Fatal("expected parser to succeed for IPv6")
	}
	if entry.ClientIP != "2001:db8::1" {
		t.Fatalf("expected IPv6 2001:db8::1, got %q", entry.ClientIP)
	}
	if entry.Username != "user@example.com" {
		t.Fatalf("expected username user@example.com, got %q", entry.Username)
	}
}
