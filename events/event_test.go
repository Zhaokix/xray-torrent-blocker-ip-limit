package events

import (
	"testing"
	"time"
)

func TestNewIPLimitBanEvent(t *testing.T) {
	now := time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)
	event := NewIPLimitBanEvent(
		"user.123456789",
		"7679754426",
		"203.0.113.10",
		"/var/log/xray/access.log",
		now,
		90*time.Second,
	)

	if event.Reason != ReasonIPLimit {
		t.Fatalf("expected reason %q, got %q", ReasonIPLimit, event.Reason)
	}
	if event.Action != ActionBan {
		t.Fatalf("expected action %q, got %q", ActionBan, event.Action)
	}
	if event.ProcessedUsername != "7679754426" {
		t.Fatalf("expected processed username 7679754426, got %q", event.ProcessedUsername)
	}
	if event.ExpiresAt != now.Add(90*time.Second) {
		t.Fatalf("expected expires_at %s, got %s", now.Add(90*time.Second), event.ExpiresAt)
	}
}

func TestNewIPLimitUnbanEvent(t *testing.T) {
	now := time.Date(2026, 3, 30, 12, 1, 0, 0, time.UTC)
	event := NewIPLimitUnbanEvent(
		"user.123456789",
		"7679754426",
		"203.0.113.10",
		"/var/log/xray/access.log",
		now,
	)

	if event.Reason != ReasonIPLimit {
		t.Fatalf("expected reason %q, got %q", ReasonIPLimit, event.Reason)
	}
	if event.Action != ActionUnban {
		t.Fatalf("expected action %q, got %q", ActionUnban, event.Action)
	}
	if event.BanDuration != 0 {
		t.Fatalf("expected zero ban duration, got %s", event.BanDuration)
	}
}
