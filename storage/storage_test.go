package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"xray-ip-limit/events"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})
	return st
}

func TestNewCreatesDatabaseFile(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	dbPath := filepath.Join(dir, "iplimit.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected database file to exist: %v", err)
	}
}

func TestAddBanAndIsBanned(t *testing.T) {
	st := newTestStorage(t)

	expiresAt := time.Now().Add(5 * time.Minute)
	if err := st.AddBan("203.0.113.10", "user@example.com", events.ReasonIPLimit, expiresAt); err != nil {
		t.Fatalf("AddBan returned error: %v", err)
	}

	if !st.IsBanned("203.0.113.10") {
		t.Fatal("expected IP to be banned")
	}
}

func TestActiveAndExpiredBans(t *testing.T) {
	st := newTestStorage(t)

	if err := st.AddBan("203.0.113.11", "active@example.com", events.ReasonTorrent, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("AddBan active returned error: %v", err)
	}
	if err := st.AddBan("203.0.113.12", "expired@example.com", events.ReasonIPLimit, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("AddBan expired returned error: %v", err)
	}

	active, err := st.ActiveBans()
	if err != nil {
		t.Fatalf("ActiveBans returned error: %v", err)
	}
	if len(active) != 1 || active[0].IP != "203.0.113.11" {
		t.Fatalf("expected one active ban for 203.0.113.11, got %+v", active)
	}
	if active[0].Reason != events.ReasonTorrent {
		t.Fatalf("expected active reason torrent, got %q", active[0].Reason)
	}

	expired, err := st.ExpiredBans()
	if err != nil {
		t.Fatalf("ExpiredBans returned error: %v", err)
	}
	if len(expired) != 1 || expired[0].IP != "203.0.113.12" {
		t.Fatalf("expected one expired ban for 203.0.113.12, got %+v", expired)
	}
}

func TestRemoveBan(t *testing.T) {
	st := newTestStorage(t)

	if err := st.AddBan("203.0.113.13", "remove@example.com", events.ReasonIPLimit, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("AddBan returned error: %v", err)
	}
	if err := st.RemoveBan("203.0.113.13"); err != nil {
		t.Fatalf("RemoveBan returned error: %v", err)
	}
	if st.IsBanned("203.0.113.13") {
		t.Fatal("expected IP to be removed from bans")
	}
}
