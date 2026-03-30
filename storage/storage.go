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
	IP        string
	Email     string
	Reason    events.Reason
	BannedAt  time.Time
	ExpiresAt time.Time
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
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS bans (
			ip         TEXT PRIMARY KEY,
			email      TEXT NOT NULL,
			reason     TEXT NOT NULL DEFAULT 'ip_limit',
			banned_at  INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE bans ADD COLUMN reason TEXT NOT NULL DEFAULT 'ip_limit'`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return nil, fmt.Errorf("migrate bans table: %w", err)
		}
	}
	return &Storage{db: db}, nil
}

func (s *Storage) AddBan(ip, email string, reason events.Reason, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO bans (ip, email, reason, banned_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		ip, email, string(reason), time.Now().Unix(), expiresAt.Unix(),
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
	rows, err := s.db.Query(
		`SELECT ip, email, reason, banned_at, expires_at FROM bans WHERE expires_at > ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []BanRecord
	for rows.Next() {
		var b BanRecord
		var reason string
		var bannedAt, expiresAt int64
		if err := rows.Scan(&b.IP, &b.Email, &reason, &bannedAt, &expiresAt); err != nil {
			continue
		}
		b.Reason = events.Reason(reason)
		b.BannedAt = time.Unix(bannedAt, 0)
		b.ExpiresAt = time.Unix(expiresAt, 0)
		bans = append(bans, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bans, nil
}

func (s *Storage) ExpiredBans() ([]BanRecord, error) {
	rows, err := s.db.Query(
		`SELECT ip, email, reason, banned_at, expires_at FROM bans WHERE expires_at <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bans []BanRecord
	for rows.Next() {
		var b BanRecord
		var reason string
		var bannedAt, expiresAt int64
		if err := rows.Scan(&b.IP, &b.Email, &reason, &bannedAt, &expiresAt); err != nil {
			continue
		}
		b.Reason = events.Reason(reason)
		b.BannedAt = time.Unix(bannedAt, 0)
		b.ExpiresAt = time.Unix(expiresAt, 0)
		bans = append(bans, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bans, nil
}

func (s *Storage) CleanExpired() error {
	_, err := s.db.Exec(`DELETE FROM bans WHERE expires_at <= ?`, time.Now().Unix())
	return err
}
