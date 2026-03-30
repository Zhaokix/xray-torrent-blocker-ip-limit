package torrent

import "testing"

func TestObserveMatchesTorrentTag(t *testing.T) {
	detector := New("TORRENT")
	decision := detector.Observe(
		`2026/03/30 10:00:00 from tcp:203.0.113.10:443 accepted email: user@example.com outboundTag=TORRENT`,
		"user@example.com",
		"203.0.113.10",
	)

	if !decision.Matched {
		t.Fatal("expected torrent detector to match the configured tag")
	}
	if decision.BanningIP != "203.0.113.10" {
		t.Fatalf("expected banning IP 203.0.113.10, got %q", decision.BanningIP)
	}
}

func TestObserveIgnoresNonTorrentLines(t *testing.T) {
	detector := New("TORRENT")
	decision := detector.Observe(
		`2026/03/30 10:00:00 from tcp:203.0.113.10:443 accepted email: user@example.com outboundTag=DIRECT`,
		"user@example.com",
		"203.0.113.10",
	)

	if decision.Matched {
		t.Fatal("did not expect torrent detector to match a non-torrent line")
	}
}
