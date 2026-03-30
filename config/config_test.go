package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 5
window: "15m"
ban_duration: "2h"
ban_mode: "iptables"
storage_dir: "/opt/xray-ip-limit"
send_webhook: true
webhook_url: "https://example.com/hook"
webhook_template: '{"email":"%s","ip":"%s","action":"%s","duration":"%s"}'
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.IPLimit != 5 {
		t.Fatalf("expected ip_limit 5, got %d", cfg.IPLimit)
	}
	if cfg.Window != 15*time.Minute {
		t.Fatalf("expected window 15m, got %s", cfg.Window)
	}
	if cfg.BanDuration != 2*time.Hour {
		t.Fatalf("expected ban_duration 2h, got %s", cfg.BanDuration)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "bad"
ban_duration: "1h"
storage_dir: "/opt/xray-ip-limit"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid duration error")
	}
}

func TestLoadRejectsInvalidIPLimit(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 0
window: "10m"
ban_duration: "1h"
storage_dir: "/opt/xray-ip-limit"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid ip_limit error")
	}
}

func TestLoadRejectsWebhookWithoutURL(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "10m"
ban_duration: "1h"
storage_dir: "/opt/xray-ip-limit"
send_webhook: true
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected webhook validation error")
	}
}
