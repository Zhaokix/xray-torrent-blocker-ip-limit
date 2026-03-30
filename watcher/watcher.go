package watcher

import (
	"bytes"
	"io"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"xray-ip-limit/detectors/iplimit"
	"github.com/nxadm/tail"
	"xray-ip-limit/config"
	"xray-ip-limit/events"
	"xray-ip-limit/extractors"
	"xray-ip-limit/firewall"
	"xray-ip-limit/storage"
)

type Watcher struct {
	cfg          *config.Config
	storage      *storage.Storage
	firewall     *firewall.Manager
	httpClient   *http.Client
	detector     *iplimit.Detector
	bypass       map[string]struct{}
	bypassEmails map[string]struct{}
}

func New(cfg *config.Config, st *storage.Storage, fw *firewall.Manager) *Watcher {
	bypass := make(map[string]struct{})
	for _, ip := range cfg.BypassIPs {
		bypass[ip] = struct{}{}
	}
	bypassEmails := make(map[string]struct{})
	for _, email := range cfg.BypassEmails {
		bypassEmails[email] = struct{}{}
	}
	return &Watcher{
		cfg:          cfg,
		storage:      st,
		firewall:     fw,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		detector:     iplimit.New(cfg.IPLimit, cfg.Window),
		bypass:       bypass,
		bypassEmails: bypassEmails,
	}
}

func (w *Watcher) Run() error {
	if err := w.restoreBans(); err != nil {
		slog.Warn("restore bans failed", "err", err)
	}

	go w.unbanLoop()
	go w.cleanupLoop()

	t, err := tail.TailFile(w.cfg.LogFile, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: 2},
	})
	if err != nil {
		return fmt.Errorf("tail: %w", err)
	}

	slog.Info("watching log", "file", w.cfg.LogFile)

	for line := range t.Lines {
		if line.Err != nil {
			slog.Warn("tail error", "err", line.Err)
			continue
		}
		w.processLine(line.Text)
	}
	return nil
}

func (w *Watcher) processLine(line string) {
	entry, ok := extractors.ParseXrayAccessLogLine(line)
	if !ok || entry.Username == "" {
		return
	}

	if _, ok := w.bypass[entry.ClientIP]; ok {
		return
	}
	if _, ok := w.bypassEmails[entry.Username]; ok {
		return
	}
	if w.storage.IsBanned(entry.ClientIP) {
		return
	}

	now := time.Now()
	decision := w.detector.Observe(entry.Username, entry.ClientIP, now)
	if !decision.Exceeded {
		return
	}

	slog.Warn("ip limit exceeded",
		"email", entry.Username,
		"unique_ips", decision.UniqueIPs,
		"limit", w.cfg.IPLimit,
		"banning_ip", decision.BanningIP,
	)

	event := events.NewIPLimitBanEvent(
		entry.Username,
		w.cfg.ProcessWebhookUsername(entry.Username),
		decision.BanningIP,
		w.cfg.LogFile,
		now,
		w.cfg.BanDuration,
	)

	if err := w.firewall.Ban(event.ClientIP); err != nil {
		slog.Error("ban failed", "ip", event.ClientIP, "err", err)
		return
	}

	if err := w.storage.AddBan(event.ClientIP, event.RawUsername, event.ExpiresAt); err != nil {
		slog.Error("storage add ban failed after firewall ban", "ip", event.ClientIP, "err", err)
		if rollbackErr := w.firewall.Unban(event.ClientIP); rollbackErr != nil {
			slog.Error("ban rollback failed", "ip", event.ClientIP, "err", rollbackErr)
		}
		return
	}

	slog.Info("banned",
		"reason", event.Reason,
		"ip", event.ClientIP,
		"email", event.RawUsername,
		"processed_username", event.ProcessedUsername,
		"expires", event.ExpiresAt.Format(time.RFC3339),
	)

	if w.cfg.SendWebhook && w.cfg.WebhookURL != "" {
		go w.sendWebhook(event)
	}
}

func (w *Watcher) restoreBans() error {
	currentlyBlocked, err := w.firewall.ListBlocked()
	if err != nil {
		slog.Warn("list blocked IPs failed, continuing with full restore", "err", err)
		currentlyBlocked = map[string]struct{}{}
	}

	bans, err := w.storage.ActiveBans()
	if err != nil {
		return err
	}
	for _, b := range bans {
		if _, exists := currentlyBlocked[b.IP]; exists {
			slog.Info("ban already present in firewall", "ip", b.IP, "email", b.Email, "expires", b.ExpiresAt.Format(time.RFC3339))
			continue
		}

		if err := w.firewall.Ban(b.IP); err != nil {
			slog.Warn("restore ban failed", "ip", b.IP, "err", err)
		} else {
			slog.Info("restored ban", "ip", b.IP, "email", b.Email, "expires", b.ExpiresAt.Format(time.RFC3339))
		}
	}
	return nil
}

func (w *Watcher) unbanLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		expired, err := w.storage.ExpiredBans()
		if err != nil {
			slog.Error("expired bans query failed", "err", err)
			continue
		}
		for _, b := range expired {
			if err := w.firewall.Unban(b.IP); err != nil {
				slog.Warn("unban failed", "ip", b.IP, "err", err)
				continue
			}

			if err := w.storage.RemoveBan(b.IP); err != nil {
				slog.Error("remove ban failed after firewall unban", "ip", b.IP, "err", err)
				continue
			}

			event := events.NewIPLimitUnbanEvent(
				b.Email,
				w.cfg.ProcessWebhookUsername(b.Email),
				b.IP,
				w.cfg.LogFile,
				time.Now(),
			)

			slog.Info("unbanned",
				"reason", event.Reason,
				"ip", event.ClientIP,
				"email", event.RawUsername,
				"processed_username", event.ProcessedUsername,
			)
			if w.cfg.SendWebhook && w.cfg.WebhookURL != "" && w.cfg.WebhookNotifyUnban {
				go w.sendWebhook(event)
			}
		}
	}
}

func (w *Watcher) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		w.detector.Cleanup(time.Now())
	}
}

func (w *Watcher) sendWebhook(event events.Event) {
	body := fmt.Sprintf(
		w.cfg.WebhookTemplate,
		event.ProcessedUsername,
		event.ClientIP,
		string(event.Action),
		event.BanDuration.String(),
	)
	req, err := http.NewRequest(http.MethodPost, w.cfg.WebhookURL, bytes.NewBufferString(body))
	if err != nil {
		slog.Error("webhook request creation failed", "err", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range w.cfg.WebhookHeaders {
		req.Header.Set(key, value)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		slog.Error("webhook failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		slog.Warn(
			"webhook returned non-success status",
			"status", resp.StatusCode,
			"action", event.Action,
			"reason", event.Reason,
			"body", string(responseBody),
		)
		return
	}

	slog.Info(
		"webhook sent",
		"status", resp.StatusCode,
		"action", event.Action,
		"reason", event.Reason,
		"username", event.ProcessedUsername,
	)
}
