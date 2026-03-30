package storage

import (
	"database/sql"
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

	now := time.Now().UTC().Truncate(time.Second)
	event := events.NewIPLimitBanEvent(
		"user@example.com",
		"user-processed",
		"203.0.113.10",
		"/var/log/xray/access.log",
		now,
		5*time.Minute,
	)
	event.EnforcedAt = now.Add(3 * time.Second)
	if err := st.AddBan(event); err != nil {
		t.Fatalf("AddBan returned error: %v", err)
	}

	if !st.IsBanned("203.0.113.10") {
		t.Fatal("expected IP to be banned")
	}
}

func TestActiveAndExpiredBans(t *testing.T) {
	st := newTestStorage(t)

	activeEvent := events.NewTorrentBanEvent(
		"active@example.com",
		"active-processed",
		"203.0.113.11",
		"/var/log/xray/access.log",
		time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		6*time.Minute,
	)
	activeEvent.EnforcedAt = activeEvent.DetectedAt.Add(5 * time.Second)
	if err := st.AddBan(activeEvent); err != nil {
		t.Fatalf("AddBan active returned error: %v", err)
	}

	expiredEvent := events.NewIPLimitBanEvent(
		"expired@example.com",
		"expired-processed",
		"203.0.113.12",
		"/var/log/xray/access.log",
		time.Now().Add(-10*time.Minute).UTC().Truncate(time.Second),
		5*time.Minute,
	)
	expiredEvent.EnforcedAt = expiredEvent.DetectedAt.Add(2 * time.Second)
	if err := st.AddBan(expiredEvent); err != nil {
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
	if active[0].ProcessedUsername != "active-processed" {
		t.Fatalf("expected processed username active-processed, got %q", active[0].ProcessedUsername)
	}
	if active[0].Source != "/var/log/xray/access.log" {
		t.Fatalf("expected source to be preserved, got %q", active[0].Source)
	}
	if !active[0].DetectedAt.Equal(activeEvent.DetectedAt) {
		t.Fatalf("expected detected_at %s, got %s", activeEvent.DetectedAt, active[0].DetectedAt)
	}
	if !active[0].EnforcedAt.Equal(activeEvent.EnforcedAt) {
		t.Fatalf("expected enforced_at %s, got %s", activeEvent.EnforcedAt, active[0].EnforcedAt)
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

	event := events.NewIPLimitBanEvent(
		"remove@example.com",
		"remove-processed",
		"203.0.113.13",
		"/var/log/xray/access.log",
		time.Now().UTC().Truncate(time.Second),
		5*time.Minute,
	)
	if err := st.AddBan(event); err != nil {
		t.Fatalf("AddBan returned error: %v", err)
	}
	if err := st.RemoveBan("203.0.113.13"); err != nil {
		t.Fatalf("RemoveBan returned error: %v", err)
	}
	if st.IsBanned("203.0.113.13") {
		t.Fatal("expected IP to be removed from bans")
	}
}

func TestNewMigratesLegacyBanRows(t *testing.T) {
	dir := t.TempDir()
	st, err := New(dir)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	dbPath := filepath.Join(dir, "iplimit.db")
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer legacy.Close()

	if _, err := legacy.Exec(`DROP TABLE bans`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := legacy.Exec(`
		CREATE TABLE bans (
			ip         TEXT PRIMARY KEY,
			email      TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT 'ip_limit',
			banned_at  INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)
	`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}

	legacyNow := time.Now().UTC().Truncate(time.Second)
	if _, err := legacy.Exec(
		`INSERT INTO bans (ip, email, reason, banned_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		"203.0.113.21", "legacy@example.com", "ip_limit", legacyNow.Unix(), legacyNow.Add(5*time.Minute).Unix(),
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	migrated, err := New(dir)
	if err != nil {
		t.Fatalf("New after legacy schema returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := migrated.Close(); err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	})

	active, err := migrated.ActiveBans()
	if err != nil {
		t.Fatalf("ActiveBans returned error: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected one active ban after migration, got %d", len(active))
	}
	if active[0].ProcessedUsername != "legacy@example.com" {
		t.Fatalf("expected processed username fallback to email, got %q", active[0].ProcessedUsername)
	}
	if active[0].DetectedAt.IsZero() || active[0].EnforcedAt.IsZero() {
		t.Fatalf("expected migrated timestamps to be backfilled, got detected_at=%s enforced_at=%s", active[0].DetectedAt, active[0].EnforcedAt)
	}
}
