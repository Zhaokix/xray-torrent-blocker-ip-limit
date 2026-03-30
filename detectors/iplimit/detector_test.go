package iplimit

import (
	"testing"
	"time"
)

func TestObserveWithinLimit(t *testing.T) {
	detector := New(2, 10*time.Minute)
	now := time.Now()

	first := detector.Observe("user@example.com", "203.0.113.1", now)
	second := detector.Observe("user@example.com", "203.0.113.2", now.Add(time.Second))

	if first.Exceeded {
		t.Fatal("did not expect first IP to exceed the limit")
	}
	if second.Exceeded {
		t.Fatal("did not expect second IP to exceed the limit")
	}
	if detector.ActiveCount("user@example.com") != 2 {
		t.Fatalf("expected active count 2, got %d", detector.ActiveCount("user@example.com"))
	}
}

func TestObserveBansNewestIPAfterLimit(t *testing.T) {
	detector := New(2, 10*time.Minute)
	now := time.Now()

	detector.Observe("user@example.com", "203.0.113.1", now)
	detector.Observe("user@example.com", "203.0.113.2", now.Add(time.Second))
	decision := detector.Observe("user@example.com", "203.0.113.3", now.Add(2*time.Second))

	if !decision.Exceeded {
		t.Fatal("expected limit to be exceeded")
	}
	if decision.BanningIP != "203.0.113.3" {
		t.Fatalf("expected newest IP to be banned, got %q", decision.BanningIP)
	}
	if detector.ActiveCount("user@example.com") != 2 {
		t.Fatalf("expected active count to stay at 2, got %d", detector.ActiveCount("user@example.com"))
	}
	if detector.HasActiveIP("user@example.com", "203.0.113.3") {
		t.Fatal("expected banned IP to be removed from the active window")
	}
}

func TestCleanupRemovesExpiredIPs(t *testing.T) {
	detector := New(2, time.Minute)
	now := time.Now()

	detector.Observe("user@example.com", "203.0.113.1", now)
	detector.Observe("user@example.com", "203.0.113.2", now.Add(30*time.Second))
	detector.Cleanup(now.Add(2 * time.Minute))

	if detector.ActiveCount("user@example.com") != 0 {
		t.Fatalf("expected active count 0 after cleanup, got %d", detector.ActiveCount("user@example.com"))
	}
}
