package watcher

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/nxadm/tail"
	"xray-ip-limit/config"
	"xray-ip-limit/detectors/iplimit"
	"xray-ip-limit/detectors/torrent"
	"xray-ip-limit/events"
	"xray-ip-limit/extractors"
	"xray-ip-limit/firewall"
	"xray-ip-limit/notifications/webhook"
	"xray-ip-limit/storage"
)

type Watcher struct {
	cfg             *config.Config
	storage         *storage.Storage
	firewall        *firewall.Manager
	notifier        *webhook.Client
	detector        *iplimit.Detector
	torrentDetector *torrent.Detector
	bypass          map[string]struct{}
	bypassEmails    map[string]struct{}
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

	var notifier *webhook.Client
	if cfg.SendWebhook && cfg.WebhookURL != "" {
		notifier = webhook.New(cfg)
	}
	return &Watcher{
		cfg:             cfg,
		storage:         st,
		firewall:        fw,
		notifier:        notifier,
		detector:        iplimit.New(cfg.IPLimit, cfg.Window),
		torrentDetector: torrent.New(cfg.TorrentTag),
		bypass:          bypass,
		bypassEmails:    bypassEmails,
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
	if w.cfg.EnableTorrentDetection {
		torrentDecision := w.torrentDetector.Observe(line, entry.Username, entry.ClientIP)
		if torrentDecision.Matched {
			slog.Warn("torrent traffic detected",
				"email", entry.Username,
				"torrent_tag", torrentDecision.Tag,
				"banning_ip", torrentDecision.BanningIP,
			)

			event := events.NewTorrentBanEvent(
				entry.Username,
				w.cfg.ProcessWebhookUsername(entry.Username),
				torrentDecision.BanningIP,
				w.cfg.LogFile,
				now,
				w.cfg.BanDuration,
			)

			w.applyBan(event)
			return
		}
	}

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

	w.applyBan(event)
}

func (w *Watcher) applyBan(event events.Event) {
	if err := w.firewall.Ban(event.ClientIP); err != nil {
		slog.Error("ban failed", "ip", event.ClientIP, "err", err)
		return
	}

	if err := w.storage.AddBan(event.ClientIP, event.RawUsername, event.Reason, event.ExpiresAt); err != nil {
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

	if w.notifier != nil {
		go w.notifier.Notify(event)
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
			slog.Info("restored ban", "reason", b.Reason, "ip", b.IP, "email", b.Email, "expires", b.ExpiresAt.Format(time.RFC3339))
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

			event := w.newUnbanEvent(b)

			slog.Info("unbanned",
				"reason", event.Reason,
				"ip", event.ClientIP,
				"email", event.RawUsername,
				"processed_username", event.ProcessedUsername,
			)
			if w.notifier != nil && w.cfg.WebhookNotifyUnban {
				go w.notifier.Notify(event)
			}
		}
	}
}

func (w *Watcher) newUnbanEvent(record storage.BanRecord) events.Event {
	processedUsername := w.cfg.ProcessWebhookUsername(record.Email)
	switch record.Reason {
	case events.ReasonTorrent:
		return events.NewTorrentUnbanEvent(record.Email, processedUsername, record.IP, w.cfg.LogFile, time.Now())
	default:
		return events.NewIPLimitUnbanEvent(record.Email, processedUsername, record.IP, w.cfg.LogFile, time.Now())
	}
}

func (w *Watcher) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		w.detector.Cleanup(time.Now())
	}
}
