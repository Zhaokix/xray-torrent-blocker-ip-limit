package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"xray-ip-limit/events"
)

type Config struct {
	LogFile                string            `yaml:"log_file"`
	IPLimit                int               `yaml:"ip_limit"`
	Window                 time.Duration     `yaml:"window"`
	BanDuration            time.Duration     `yaml:"ban_duration"`
	BanDurationIPLimit     time.Duration     `yaml:"ban_duration_ip_limit"`
	BanDurationTorrent     time.Duration     `yaml:"ban_duration_torrent"`
	EnableTorrentDetection bool              `yaml:"enable_torrent_detection"`
	TorrentTag             string            `yaml:"torrent_tag"`
	BypassIPs              []string          `yaml:"bypass_ips"`
	BypassEmails           []string          `yaml:"bypass_emails"`
	BanMode                string            `yaml:"ban_mode"`
	SendWebhook            bool              `yaml:"send_webhook"`
	WebhookURL             string            `yaml:"webhook_url"`
	WebhookTemplate        string            `yaml:"webhook_template"`
	WebhookTemplateIPLimit string            `yaml:"webhook_template_ip_limit"`
	WebhookTemplateTorrent string            `yaml:"webhook_template_torrent"`
	WebhookNotifyIPLimit   bool              `yaml:"webhook_notify_ip_limit"`
	WebhookNotifyTorrent   bool              `yaml:"webhook_notify_torrent"`
	WebhookHeaders         map[string]string `yaml:"webhook_headers"`
	WebhookUsernameRegex   string            `yaml:"webhook_username_regex"`
	webhookUsernameExpr    *regexp.Regexp
	WebhookNotifyUnban     bool   `yaml:"webhook_notify_unban"`
	WebhookServerName      string `yaml:"webhook_server_name"`
	DryRun                 bool   `yaml:"dry_run"`
	StorageDir             string `yaml:"storage_dir"`
}

func Default() *Config {
	return &Config{
		LogFile:                "/var/log/xray/access.log",
		IPLimit:                3,
		Window:                 10 * time.Minute,
		BanDuration:            60 * time.Minute,
		BanDurationIPLimit:     0,
		BanDurationTorrent:     0,
		EnableTorrentDetection: false,
		TorrentTag:             "TORRENT",
		BypassIPs:              []string{"127.0.0.1", "::1"},
		BypassEmails:           []string{},
		BanMode:                "iptables",
		SendWebhook:            false,
		WebhookURL:             "",
		WebhookTemplate:        `{"email":"%s","ip":"%s","action":"%s","duration":"%s"}`,
		WebhookTemplateIPLimit: "",
		WebhookTemplateTorrent: "",
		WebhookNotifyIPLimit:   true,
		WebhookNotifyTorrent:   true,
		WebhookHeaders:         map[string]string{},
		WebhookUsernameRegex:   `^(.+)$`,
		WebhookNotifyUnban:     false,
		WebhookServerName:      "",
		DryRun:                 false,
		StorageDir:             "/opt/iptblocker",
	}
}

// rawConfig keeps duration fields as strings so the loader can validate them explicitly.
type rawConfig struct {
	LogFile                string            `yaml:"log_file"`
	IPLimit                *int              `yaml:"ip_limit"`
	Window                 string            `yaml:"window"`
	BanDuration            string            `yaml:"ban_duration"`
	BanDurationIPLimit     string            `yaml:"ban_duration_ip_limit"`
	BanDurationTorrent     string            `yaml:"ban_duration_torrent"`
	EnableTorrentDetection bool              `yaml:"enable_torrent_detection"`
	TorrentTag             *string           `yaml:"torrent_tag"`
	BypassIPs              []string          `yaml:"bypass_ips"`
	BypassEmails           []string          `yaml:"bypass_emails"`
	BanMode                string            `yaml:"ban_mode"`
	SendWebhook            bool              `yaml:"send_webhook"`
	WebhookURL             string            `yaml:"webhook_url"`
	WebhookTemplate        string            `yaml:"webhook_template"`
	WebhookTemplateIPLimit string            `yaml:"webhook_template_ip_limit"`
	WebhookTemplateTorrent string            `yaml:"webhook_template_torrent"`
	WebhookNotifyIPLimit   *bool             `yaml:"webhook_notify_ip_limit"`
	WebhookNotifyTorrent   *bool             `yaml:"webhook_notify_torrent"`
	LegacyWebhookTemplate  string            `yaml:"WebhookTemplate"`
	WebhookHeaders         map[string]string `yaml:"webhook_headers"`
	LegacyWebhookHeaders   map[string]string `yaml:"WebhookHeaders"`
	WebhookUsernameRegex   string            `yaml:"webhook_username_regex"`
	WebhookNotifyUnban     bool              `yaml:"webhook_notify_unban"`
	WebhookServerName      string            `yaml:"webhook_server_name"`
	DryRun                 bool              `yaml:"dry_run"`
	StorageDir             string            `yaml:"storage_dir"`
}

func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if raw.LogFile != "" {
		cfg.LogFile = raw.LogFile
	}
	if raw.IPLimit != nil {
		cfg.IPLimit = *raw.IPLimit
	}
	if raw.Window != "" {
		d, err := time.ParseDuration(raw.Window)
		if err != nil {
			return nil, fmt.Errorf("parse window: %w", err)
		}
		cfg.Window = d
	}
	if raw.BanDuration != "" {
		d, err := time.ParseDuration(raw.BanDuration)
		if err != nil {
			return nil, fmt.Errorf("parse ban_duration: %w", err)
		}
		cfg.BanDuration = d
	}
	if raw.BanDurationIPLimit != "" {
		d, err := time.ParseDuration(raw.BanDurationIPLimit)
		if err != nil {
			return nil, fmt.Errorf("parse ban_duration_ip_limit: %w", err)
		}
		cfg.BanDurationIPLimit = d
	}
	if raw.BanDurationTorrent != "" {
		d, err := time.ParseDuration(raw.BanDurationTorrent)
		if err != nil {
			return nil, fmt.Errorf("parse ban_duration_torrent: %w", err)
		}
		cfg.BanDurationTorrent = d
	}
	cfg.EnableTorrentDetection = raw.EnableTorrentDetection
	if raw.TorrentTag != nil {
		cfg.TorrentTag = *raw.TorrentTag
	}
	if raw.BypassIPs != nil {
		cfg.BypassIPs = raw.BypassIPs
	}
	if raw.BypassEmails != nil {
		cfg.BypassEmails = raw.BypassEmails
	}
	if raw.BanMode != "" {
		cfg.BanMode = raw.BanMode
	}
	cfg.SendWebhook = raw.SendWebhook
	if raw.WebhookURL != "" {
		cfg.WebhookURL = raw.WebhookURL
	}
	if raw.WebhookTemplate != "" {
		cfg.WebhookTemplate = raw.WebhookTemplate
	} else if raw.LegacyWebhookTemplate != "" {
		cfg.WebhookTemplate = raw.LegacyWebhookTemplate
	}
	if raw.WebhookTemplateIPLimit != "" {
		cfg.WebhookTemplateIPLimit = raw.WebhookTemplateIPLimit
	}
	if raw.WebhookTemplateTorrent != "" {
		cfg.WebhookTemplateTorrent = raw.WebhookTemplateTorrent
	}
	if raw.WebhookNotifyIPLimit != nil {
		cfg.WebhookNotifyIPLimit = *raw.WebhookNotifyIPLimit
	}
	if raw.WebhookNotifyTorrent != nil {
		cfg.WebhookNotifyTorrent = *raw.WebhookNotifyTorrent
	}
	if raw.WebhookHeaders != nil {
		cfg.WebhookHeaders = raw.WebhookHeaders
	} else if raw.LegacyWebhookHeaders != nil {
		cfg.WebhookHeaders = raw.LegacyWebhookHeaders
	}
	if raw.WebhookUsernameRegex != "" {
		cfg.WebhookUsernameRegex = raw.WebhookUsernameRegex
	}
	cfg.WebhookNotifyUnban = raw.WebhookNotifyUnban
	if raw.WebhookServerName != "" {
		cfg.WebhookServerName = raw.WebhookServerName
	}
	cfg.DryRun = raw.DryRun
	if raw.StorageDir != "" {
		cfg.StorageDir = raw.StorageDir
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.LogFile) == "" {
		return fmt.Errorf("log_file must not be empty")
	}
	if c.IPLimit <= 0 {
		return fmt.Errorf("ip_limit must be greater than zero")
	}
	if c.Window <= 0 {
		return fmt.Errorf("window must be greater than zero")
	}
	if c.BanDuration < 0 {
		return fmt.Errorf("ban_duration must not be negative")
	}
	if c.BanDurationIPLimit < 0 {
		return fmt.Errorf("ban_duration_ip_limit must not be negative")
	}
	if c.BanDurationTorrent < 0 {
		return fmt.Errorf("ban_duration_torrent must not be negative")
	}
	if c.EnableTorrentDetection && strings.TrimSpace(c.TorrentTag) == "" {
		return fmt.Errorf("torrent_tag must not be empty when enable_torrent_detection is enabled")
	}
	if strings.TrimSpace(c.StorageDir) == "" {
		return fmt.Errorf("storage_dir must not be empty")
	}

	switch strings.ToLower(strings.TrimSpace(c.BanMode)) {
	case "iptables", "nftables", "nft":
	default:
		return fmt.Errorf("ban_mode must be one of: iptables, nftables, nft")
	}

	if c.SendWebhook {
		if strings.TrimSpace(c.WebhookURL) == "" {
			return fmt.Errorf("webhook_url must not be empty when send_webhook is enabled")
		}
		if strings.TrimSpace(c.WebhookTemplate) == "" &&
			strings.TrimSpace(c.WebhookTemplateIPLimit) == "" &&
			strings.TrimSpace(c.WebhookTemplateTorrent) == "" {
			return fmt.Errorf("at least one webhook template must be configured when send_webhook is enabled")
		}
	}

	expr, err := regexp.Compile(c.WebhookUsernameRegex)
	if err != nil {
		return fmt.Errorf("webhook_username_regex is invalid: %w", err)
	}
	c.webhookUsernameExpr = expr

	return nil
}

func (c *Config) ProcessWebhookUsername(value string) string {
	if c.webhookUsernameExpr == nil {
		return value
	}

	matches := c.webhookUsernameExpr.FindStringSubmatch(value)
	if len(matches) > 1 {
		return matches[1]
	}

	return value
}

func (c *Config) WebhookTemplateForReason(reason string) string {
	switch reason {
	case "ip_limit":
		if strings.TrimSpace(c.WebhookTemplateIPLimit) != "" {
			return c.WebhookTemplateIPLimit
		}
	case "torrent":
		if strings.TrimSpace(c.WebhookTemplateTorrent) != "" {
			return c.WebhookTemplateTorrent
		}
	}

	return c.WebhookTemplate
}

func (c *Config) ShouldNotify(reason events.Reason) bool {
	if !c.SendWebhook {
		return false
	}

	switch reason {
	case events.ReasonIPLimit:
		return c.WebhookNotifyIPLimit
	case events.ReasonTorrent:
		return c.WebhookNotifyTorrent
	default:
		return true
	}
}

func (c *Config) BanDurationForReason(reason events.Reason) time.Duration {
	switch reason {
	case events.ReasonIPLimit:
		if c.BanDurationIPLimit > 0 {
			return c.BanDurationIPLimit
		}
	case events.ReasonTorrent:
		if c.BanDurationTorrent > 0 {
			return c.BanDurationTorrent
		}
	}

	return c.BanDuration
}

func (c *Config) EffectiveWebhookServerName() string {
	if strings.TrimSpace(c.WebhookServerName) != "" {
		return c.WebhookServerName
	}

	host, err := os.Hostname()
	if err != nil {
		return ""
	}

	return host
}
