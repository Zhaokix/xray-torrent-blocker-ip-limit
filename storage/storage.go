package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"xray-ip-limit/events"

	_ "modernc.org/sqlite"
)

type BanRecord struct {
	IP                string
	Email             string
	ProcessedUsername string
	Reason            events.Reason
	Source            string
	DetectedAt        time.Time
	EnforcedAt        time.Time
	ExpiresAt         time.Time
}

type Storage struct {
	db *sql.DB
}

func New(dir string) (*Storage, error) {
	path := filepath.Join(dir, "iplimit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS bans (
			ip                 TEXT PRIMARY KEY,
			email              TEXT NOT NULL,
			processed_username TEXT NOT NULL DEFAULT '',
			reason             TEXT NOT NULL DEFAULT 'ip_limit',
			source             TEXT NOT NULL DEFAULT '',
			detected_at        INTEGER NOT NULL DEFAULT 0,
			enforced_at        INTEGER NOT NULL DEFAULT 0,
			expires_at         INTEGER NOT NULL
		)
	`); err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	migrations := []string{
		`ALTER TABLE bans ADD COLUMN processed_username TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE bans ADD COLUMN reason TEXT NOT NULL DEFAULT 'ip_limit'`,
		`ALTER TABLE bans ADD COLUMN source TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE bans ADD COLUMN detected_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bans ADD COLUMN enforced_at INTEGER NOT NULL DEFAULT 0`,
	}
	for _, query := range migrations {
		if err := ignoreDuplicateColumn(db.Exec(query)); err != nil {
			return nil, err
		}
	}

	// Backfill old rows so pre-M5 databases keep meaningful audit timestamps.
	if _, err := db.Exec(`
		UPDATE bans
		SET enforced_at = COALESCE(NULLIF(enforced_at, 0), banned_at, 0)
		WHERE enforced_at = 0
	`); err != nil && !isMissingColumn(err, "banned_at") {
		return nil, fmt.Errorf("backfill enforced_at: %w", err)
	}
	if _, err := db.Exec(`
		UPDATE bans
		SET detected_at = COALESCE(NULLIF(detected_at, 0), enforced_at, banned_at, 0)
		WHERE detected_at = 0
	`); err != nil && !isMissingColumn(err, "banned_at") {
		return nil, fmt.Errorf("backfill detected_at: %w", err)
	}

	return &Storage{db: db}, nil
}

func ignoreDuplicateColumn(_ sql.Result, err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return nil
	}
	return fmt.Errorf("migrate bans table: %w", err)
}

func isMissingColumn(err error, column string) bool {
	return strings.Contains(strings.ToLower(err.Error()), "no such column: "+strings.ToLower(column))
}

func (s *Storage) AddBan(event events.Event) error {
	enforcedAt := event.EnforcedAt
	if enforcedAt.IsZero() {
		enforcedAt = time.Now()
	}
	detectedAt := event.DetectedAt
	if detectedAt.IsZero() {
		detectedAt = enforcedAt
	}

	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO bans (ip, email, processed_username, reason, source, detected_at, enforced_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ClientIP,
		event.RawUsername,
		event.ProcessedUsername,
		string(event.Reason),
		event.Source,
		detectedAt.Unix(),
		enforcedAt.Unix(),
		event.ExpiresAt.Unix(),
	)
	return err
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) RemoveBan(ip string) error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE ip = ?`, ip)
	return err
}

func (s *Storage) IsBanned(ip string) bool {
	var expiresAt int64
	err := s.db.QueryRow(`SELECT expires_at FROM bans WHERE ip = ?`, ip).Scan(&expiresAt)
	if err != nil {
		return false
	}
	return time.Now().Before(time.Unix(expiresAt, 0))
}

func (s *Storage) ActiveBans() ([]BanRecord, error) {
	return s.listBans(`SELECT ip, email, processed_username, reason, source, detected_at, enforced_at, expires_at FROM bans WHERE expires_at > ?`, time.Now().Unix())
}

func (s *Storage) ExpiredBans() ([]BanRecord, error) {
	return s.listBans(`SELECT ip, email, processed_username, reason, source, detected_at, enforced_at, expires_at FROM bans WHERE expires_at <= ?`, time.Now().Unix())
}

func (s *Storage) listBans(query string, now int64) ([]BanRecord, error) {
	rows, err := s.db.Query(query, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []BanRecord
	for rows.Next() {
		record, err := scanBanRecord(rows)
		if err != nil {
			continue
		}
		bans = append(bans, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bans, nil
}

func scanBanRecord(scanner interface {
	Scan(dest ...any) error
}) (BanRecord, error) {
	var record BanRecord
	var reason string
	var detectedAt, enforcedAt, expiresAt int64
	if err := scanner.Scan(
		&record.IP,
		&record.Email,
		&record.ProcessedUsername,
		&reason,
		&record.Source,
		&detectedAt,
		&enforcedAt,
		&expiresAt,
	); err != nil {
		return BanRecord{}, err
	}

	record.Reason = events.Reason(reason)
	record.DetectedAt = unixOrZero(detectedAt)
	record.EnforcedAt = unixOrZero(enforcedAt)
	record.ExpiresAt = unixOrZero(expiresAt)
	if record.DetectedAt.IsZero() {
		record.DetectedAt = record.EnforcedAt
	}
	if record.ProcessedUsername == "" {
		record.ProcessedUsername = record.Email
	}

	return record, nil
}

func unixOrZero(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0)
}

func (s *Storage) CleanExpired() error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE expires_at <= ?`, time.Now().Unix())
	return err
}
