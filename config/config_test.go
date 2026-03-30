package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"xray-ip-limit/events"
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
ban_duration_ip_limit: "30m"
ban_duration_torrent: "4h"
enable_torrent_detection: true
torrent_tag: "TORRENT"
ban_mode: "iptables"
storage_dir: "/opt/iptblocker"
send_webhook: true
webhook_url: "https://example.com/hook"
webhook_template: '{"email":"%s","ip":"%s","action":"%s","duration":"%s"}'
webhook_template_torrent: '{"email":"%s","kind":"torrent","ip":"%s","action":"%s","duration":"%s"}'
webhook_notify_ip_limit: false
webhook_notify_torrent: true
webhook_server_name: "edge-1"
webhook_username_regex: "^(.+)$"
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
	if cfg.BanDurationIPLimit != 30*time.Minute {
		t.Fatalf("expected ban_duration_ip_limit 30m, got %s", cfg.BanDurationIPLimit)
	}
	if cfg.BanDurationTorrent != 4*time.Hour {
		t.Fatalf("expected ban_duration_torrent 4h, got %s", cfg.BanDurationTorrent)
	}
	if cfg.WebhookTemplateTorrent == "" {
		t.Fatal("expected torrent webhook template to be loaded")
	}
	if cfg.WebhookNotifyIPLimit {
		t.Fatal("expected webhook_notify_ip_limit false")
	}
	if !cfg.WebhookNotifyTorrent {
		t.Fatal("expected webhook_notify_torrent true")
	}
	if cfg.WebhookServerName != "edge-1" {
		t.Fatalf("expected webhook_server_name edge-1, got %q", cfg.WebhookServerName)
	}
	if !cfg.EnableTorrentDetection {
		t.Fatal("expected torrent detection to be enabled")
	}
	if cfg.TorrentTag != "TORRENT" {
		t.Fatalf("expected torrent_tag TORRENT, got %q", cfg.TorrentTag)
	}
}

func TestLoadSupportsLegacyWebhookTemplateKey(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "10m"
ban_duration: "1h"
storage_dir: "/opt/iptblocker"
send_webhook: true
webhook_url: "https://example.com/hook"
WebhookTemplate: '{"chat_id":"%s","text":"IP %s"}'
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.WebhookTemplate != `{"chat_id":"%s","text":"IP %s"}` {
		t.Fatalf("expected legacy webhook template to load, got %q", cfg.WebhookTemplate)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "bad"
ban_duration: "1h"
storage_dir: "/opt/iptblocker"
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
storage_dir: "/opt/iptblocker"
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
storage_dir: "/opt/iptblocker"
send_webhook: true
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected webhook validation error")
	}
}

func TestLoadRejectsEmptyTorrentTagWhenTorrentDetectionEnabled(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "10m"
ban_duration: "1h"
storage_dir: "/opt/iptblocker"
enable_torrent_detection: true
torrent_tag: ""
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected torrent_tag validation error")
	}
}

func TestLoadRejectsInvalidReasonSpecificBanDuration(t *testing.T) {
	path := writeTempConfig(t, `
log_file: "/var/log/xray/access.log"
ip_limit: 3
window: "10m"
ban_duration: "1h"
ban_duration_torrent: "invalid"
storage_dir: "/opt/iptblocker"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid ban_duration_torrent error")
	}
}

func TestProcessWebhookUsernameRegexSuffixAfterDot(t *testing.T) {
	cfg := Default()
	cfg.WebhookUsernameRegex = `^\d+\.(\d+)$`
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	username := cfg.ProcessWebhookUsername("user.123456789")
	if username != "7679754426" {
		t.Fatalf("expected username 7679754426, got %q", username)
	}
}

func TestProcessWebhookUsernameFallsBackToRawValue(t *testing.T) {
	cfg := Default()
	cfg.WebhookUsernameRegex = `^\d+\.(\d+)$`
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	username := cfg.ProcessWebhookUsername("user.without_numeric_suffix")
	if username != "user.without_numeric_suffix" {
		t.Fatalf("expected raw username fallback, got %q", username)
	}
}

func TestWebhookTemplateForReasonUsesSpecificTemplate(t *testing.T) {
	cfg := Default()
	cfg.WebhookTemplate = `{"type":"default"}`
	cfg.WebhookTemplateTorrent = `{"type":"torrent"}`

	template := cfg.WebhookTemplateForReason("torrent")
	if template != `{"type":"torrent"}` {
		t.Fatalf("expected torrent template, got %q", template)
	}
}

func TestWebhookTemplateForReasonFallsBackToDefault(t *testing.T) {
	cfg := Default()
	cfg.WebhookTemplate = `{"type":"default"}`

	template := cfg.WebhookTemplateForReason("torrent")
	if template != `{"type":"default"}` {
		t.Fatalf("expected default template fallback, got %q", template)
	}
}

func TestShouldNotifyUsesReasonSpecificFlags(t *testing.T) {
	cfg := Default()
	cfg.SendWebhook = true
	cfg.WebhookNotifyIPLimit = false
	cfg.WebhookNotifyTorrent = true

	if cfg.ShouldNotify(events.ReasonIPLimit) {
		t.Fatal("expected ip_limit notifications to be disabled")
	}
	if !cfg.ShouldNotify(events.ReasonTorrent) {
		t.Fatal("expected torrent notifications to be enabled")
	}
}

func TestBanDurationForReasonUsesSpecificOverride(t *testing.T) {
	cfg := Default()
	cfg.BanDuration = 10 * time.Minute
	cfg.BanDurationTorrent = 2 * time.Hour

	if cfg.BanDurationForReason(events.ReasonTorrent) != 2*time.Hour {
		t.Fatalf("expected torrent ban duration override, got %s", cfg.BanDurationForReason(events.ReasonTorrent))
	}
	if cfg.BanDurationForReason(events.ReasonIPLimit) != 10*time.Minute {
		t.Fatalf("expected default ip_limit ban duration, got %s", cfg.BanDurationForReason(events.ReasonIPLimit))
	}
}
