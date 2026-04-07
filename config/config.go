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
	WebhookNotifyUnban     bool               `yaml:"webhook_notify_unban"`
	WebhookServerName      string             `yaml:"webhook_server_name"`
	AdminNotifications     AdminNotifications `yaml:"admin_notifications"`
	DryRun                 bool               `yaml:"dry_run"`
	StorageDir             string             `yaml:"storage_dir"`
	RemoteEnforcement      RemoteEnforcement  `yaml:"remote_enforcement"`
}

type AdminNotifications struct {
	Enabled         bool              `yaml:"enabled"`
	WebhookURL      string            `yaml:"webhook_url"`
	Headers         map[string]string `yaml:"headers"`
	Fields          []string          `yaml:"fields"`
	Template        string            `yaml:"template"`
	TemplateIPLimit string            `yaml:"template_ip_limit"`
	TemplateTorrent string            `yaml:"template_torrent"`
	NotifyUnban     bool              `yaml:"notify_unban"`
}

type RemoteEnforcement struct {
	Enabled        bool           `yaml:"enabled"`
	Mode           string         `yaml:"mode"`
	ConnectTimeout time.Duration  `yaml:"connect_timeout"`
	SSHConfigPath  string         `yaml:"ssh_config_path"`
	SSHKeyPath     string         `yaml:"ssh_key_path"`
	KnownHostsPath string         `yaml:"known_hosts_path"`
	UseSudo        bool           `yaml:"use_sudo"`
	Targets        []RemoteTarget `yaml:"targets"`
}

type RemoteTarget struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	User    string `yaml:"user"`
	Backend string `yaml:"backend"`
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
		WebhookTemplate:        `{"email":"%s","ip":"%s","server":"%s","action":"%s","duration":"%s"}`,
		WebhookTemplateIPLimit: "",
		WebhookTemplateTorrent: "",
		WebhookNotifyIPLimit:   true,
		WebhookNotifyTorrent:   true,
		WebhookHeaders:         map[string]string{},
		WebhookUsernameRegex:   `^(.+)$`,
		WebhookNotifyUnban:     false,
		WebhookServerName:      "",
		AdminNotifications: AdminNotifications{
			Enabled:    false,
			WebhookURL: "",
			Headers:    map[string]string{},
			Fields: []string{
				"reason",
				"action",
				"username",
				"server",
				"ban_duration",
				"unique_ips",
				"limit",
				"window",
				"torrent_tag",
				"source",
			},
			Template:        "",
			TemplateIPLimit: "",
			TemplateTorrent: "",
			NotifyUnban:     false,
		},
		DryRun:     false,
		StorageDir: "/opt/iptblocker",
		RemoteEnforcement: RemoteEnforcement{
			Enabled:        false,
			Mode:           "local_only",
			ConnectTimeout: 10 * time.Second,
			SSHConfigPath:  "",
			SSHKeyPath:     "",
			KnownHostsPath: "",
			UseSudo:        false,
			Targets:        nil,
		},
	}
}

// rawConfig keeps duration fields as strings so the loader can validate them explicitly.
type rawConfig struct {
	LogFile                string                `yaml:"log_file"`
	IPLimit                *int                  `yaml:"ip_limit"`
	Window                 string                `yaml:"window"`
	BanDuration            string                `yaml:"ban_duration"`
	BanDurationIPLimit     string                `yaml:"ban_duration_ip_limit"`
	BanDurationTorrent     string                `yaml:"ban_duration_torrent"`
	EnableTorrentDetection bool                  `yaml:"enable_torrent_detection"`
	TorrentTag             *string               `yaml:"torrent_tag"`
	BypassIPs              []string              `yaml:"bypass_ips"`
	BypassEmails           []string              `yaml:"bypass_emails"`
	BanMode                string                `yaml:"ban_mode"`
	SendWebhook            bool                  `yaml:"send_webhook"`
	WebhookURL             string                `yaml:"webhook_url"`
	WebhookTemplate        string                `yaml:"webhook_template"`
	WebhookTemplateIPLimit string                `yaml:"webhook_template_ip_limit"`
	WebhookTemplateTorrent string                `yaml:"webhook_template_torrent"`
	WebhookNotifyIPLimit   *bool                 `yaml:"webhook_notify_ip_limit"`
	WebhookNotifyTorrent   *bool                 `yaml:"webhook_notify_torrent"`
	LegacyWebhookTemplate  string                `yaml:"WebhookTemplate"`
	WebhookHeaders         map[string]string     `yaml:"webhook_headers"`
	LegacyWebhookHeaders   map[string]string     `yaml:"WebhookHeaders"`
	WebhookUsernameRegex   string                `yaml:"webhook_username_regex"`
	WebhookNotifyUnban     bool                  `yaml:"webhook_notify_unban"`
	WebhookServerName      string                `yaml:"webhook_server_name"`
	AdminNotifications     rawAdminNotifications `yaml:"admin_notifications"`
	DryRun                 bool                  `yaml:"dry_run"`
	StorageDir             string                `yaml:"storage_dir"`
	RemoteEnforcement      rawRemoteEnforcement  `yaml:"remote_enforcement"`
}

type rawAdminNotifications struct {
	Enabled         bool              `yaml:"enabled"`
	WebhookURL      string            `yaml:"webhook_url"`
	Headers         map[string]string `yaml:"headers"`
	Fields          []string          `yaml:"fields"`
	Template        string            `yaml:"template"`
	TemplateIPLimit string            `yaml:"template_ip_limit"`
	TemplateTorrent string            `yaml:"template_torrent"`
	NotifyUnban     bool              `yaml:"notify_unban"`
}

type rawRemoteEnforcement struct {
	Enabled        bool           `yaml:"enabled"`
	Mode           string         `yaml:"mode"`
	ConnectTimeout string         `yaml:"connect_timeout"`
	SSHConfigPath  string         `yaml:"ssh_config_path"`
	SSHKeyPath     string         `yaml:"ssh_key_path"`
	KnownHostsPath string         `yaml:"known_hosts_path"`
	UseSudo        bool           `yaml:"use_sudo"`
	Targets        []RemoteTarget `yaml:"targets"`
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
	cfg.AdminNotifications.Enabled = raw.AdminNotifications.Enabled
	if raw.AdminNotifications.WebhookURL != "" {
		cfg.AdminNotifications.WebhookURL = raw.AdminNotifications.WebhookURL
	}
	if raw.AdminNotifications.Headers != nil {
		cfg.AdminNotifications.Headers = raw.AdminNotifications.Headers
	}
	if raw.AdminNotifications.Fields != nil {
		cfg.AdminNotifications.Fields = raw.AdminNotifications.Fields
	}
	if raw.AdminNotifications.Template != "" {
		cfg.AdminNotifications.Template = raw.AdminNotifications.Template
	}
	if raw.AdminNotifications.TemplateIPLimit != "" {
		cfg.AdminNotifications.TemplateIPLimit = raw.AdminNotifications.TemplateIPLimit
	}
	if raw.AdminNotifications.TemplateTorrent != "" {
		cfg.AdminNotifications.TemplateTorrent = raw.AdminNotifications.TemplateTorrent
	}
	cfg.AdminNotifications.NotifyUnban = raw.AdminNotifications.NotifyUnban
	cfg.DryRun = raw.DryRun
	if raw.StorageDir != "" {
		cfg.StorageDir = raw.StorageDir
	}
	cfg.RemoteEnforcement.Enabled = raw.RemoteEnforcement.Enabled
	if raw.RemoteEnforcement.Mode != "" {
		cfg.RemoteEnforcement.Mode = raw.RemoteEnforcement.Mode
	}
	if raw.RemoteEnforcement.ConnectTimeout != "" {
		d, err := time.ParseDuration(raw.RemoteEnforcement.ConnectTimeout)
		if err != nil {
			return nil, fmt.Errorf("parse remote_enforcement.connect_timeout: %w", err)
		}
		cfg.RemoteEnforcement.ConnectTimeout = d
	}
	if raw.RemoteEnforcement.SSHConfigPath != "" {
		cfg.RemoteEnforcement.SSHConfigPath = raw.RemoteEnforcement.SSHConfigPath
	}
	if raw.RemoteEnforcement.SSHKeyPath != "" {
		cfg.RemoteEnforcement.SSHKeyPath = raw.RemoteEnforcement.SSHKeyPath
	}
	if raw.RemoteEnforcement.KnownHostsPath != "" {
		cfg.RemoteEnforcement.KnownHostsPath = raw.RemoteEnforcement.KnownHostsPath
	}
	cfg.RemoteEnforcement.UseSudo = raw.RemoteEnforcement.UseSudo
	if raw.RemoteEnforcement.Targets != nil {
		cfg.RemoteEnforcement.Targets = raw.RemoteEnforcement.Targets
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
	if c.RemoteEnforcement.ConnectTimeout <= 0 {
		return fmt.Errorf("remote_enforcement.connect_timeout must be greater than zero")
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

	if c.AdminNotifications.Enabled {
		if strings.TrimSpace(c.AdminNotifications.WebhookURL) == "" {
			return fmt.Errorf("admin_notifications.webhook_url must not be empty when admin notifications are enabled")
		}
		hasTemplate := strings.TrimSpace(c.AdminNotifications.Template) != "" ||
			strings.TrimSpace(c.AdminNotifications.TemplateIPLimit) != "" ||
			strings.TrimSpace(c.AdminNotifications.TemplateTorrent) != ""
		if !hasTemplate {
			if len(c.AdminNotifications.Fields) == 0 {
				return fmt.Errorf("admin_notifications.fields must not be empty when admin notifications are enabled without admin notification templates")
			}
			for _, field := range c.AdminNotifications.Fields {
				if !isSupportedAdminNotificationField(field) {
					return fmt.Errorf("admin_notifications.fields contains unsupported field %q", field)
				}
			}
		}
	}

	switch strings.ToLower(strings.TrimSpace(c.RemoteEnforcement.Mode)) {
	case "local_only", "remote_only", "local_and_remote":
	default:
		return fmt.Errorf("remote_enforcement.mode must be one of: local_only, remote_only, local_and_remote")
	}

	if c.RemoteEnforcement.Enabled {
		if len(c.RemoteEnforcement.Targets) == 0 {
			return fmt.Errorf("remote_enforcement.targets must not be empty when remote enforcement is enabled")
		}
		for i, target := range c.RemoteEnforcement.Targets {
			if strings.TrimSpace(target.Name) == "" {
				return fmt.Errorf("remote_enforcement.targets[%d].name must not be empty", i)
			}
			if strings.TrimSpace(target.Host) == "" {
				return fmt.Errorf("remote_enforcement.targets[%d].host must not be empty", i)
			}
			if target.Port <= 0 {
				return fmt.Errorf("remote_enforcement.targets[%d].port must be greater than zero", i)
			}
			if strings.TrimSpace(target.User) == "" {
				return fmt.Errorf("remote_enforcement.targets[%d].user must not be empty", i)
			}
			switch strings.ToLower(strings.TrimSpace(target.Backend)) {
			case "", "iptables", "nftables", "nft":
			default:
				return fmt.Errorf("remote_enforcement.targets[%d].backend must be one of: iptables, nftables, nft", i)
			}
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

func isSupportedAdminNotificationField(field string) bool {
	switch strings.TrimSpace(field) {
	case "reason",
		"action",
		"username",
		"processed_username",
		"server",
		"source",
		"ban_duration",
		"detected_at",
		"enforced_at",
		"expires_at",
		"unique_ips",
		"limit",
		"window",
		"torrent_tag",
		"distribution_scope",
		"distribution_full_success",
		"distribution_partial_failure":
		return true
	default:
		return false
	}
}

func (c *Config) AdminTemplateForReason(reason events.Reason) string {
	switch reason {
	case events.ReasonIPLimit:
		if strings.TrimSpace(c.AdminNotifications.TemplateIPLimit) != "" {
			return c.AdminNotifications.TemplateIPLimit
		}
	case events.ReasonTorrent:
		if strings.TrimSpace(c.AdminNotifications.TemplateTorrent) != "" {
			return c.AdminNotifications.TemplateTorrent
		}
	}

	return c.AdminNotifications.Template
}
