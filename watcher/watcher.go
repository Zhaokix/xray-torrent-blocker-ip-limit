package watcher

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/nxadm/tail"
	"xray-ip-limit/config"
	"xray-ip-limit/detectors/iplimit"
	"xray-ip-limit/detectors/torrent"
	"xray-ip-limit/distribution"
	"xray-ip-limit/events"
	"xray-ip-limit/extractors"
	"xray-ip-limit/firewall"
	"xray-ip-limit/notifications/adminwebhook"
	"xray-ip-limit/notifications/webhook"
	"xray-ip-limit/storage"
)

type Watcher struct {
	cfg             *config.Config
	storage         *storage.Storage
	firewall        *firewall.Manager
	distributor     *distribution.Manager
	notifier        *webhook.Client
	adminNotifier   *adminwebhook.Client
	detector        *iplimit.Detector
	torrentDetector *torrent.Detector
	bypass          map[string]struct{}
	bypassEmails    map[string]struct{}
	bypassUsers     map[string]struct{}
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
	bypassUsers := make(map[string]struct{})
	for _, username := range cfg.BypassProcessedUsers {
		bypassUsers[username] = struct{}{}
	}

	var notifier *webhook.Client
	if cfg.SendWebhook && cfg.WebhookURL != "" {
		notifier = webhook.New(cfg)
	}
	var adminNotifier *adminwebhook.Client
	if cfg.AdminNotifications.Enabled && cfg.AdminNotifications.WebhookURL != "" {
		adminNotifier = adminwebhook.New(cfg)
	}
	return &Watcher{
		cfg:             cfg,
		storage:         st,
		firewall:        fw,
		distributor:     distribution.NewManager(cfg, fw),
		notifier:        notifier,
		adminNotifier:   adminNotifier,
		detector:        iplimit.New(cfg.IPLimit, cfg.Window),
		torrentDetector: torrent.New(cfg.TorrentTag),
		bypass:          bypass,
		bypassEmails:    bypassEmails,
		bypassUsers:     bypassUsers,
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
	if _, ok := w.bypassUsers[w.cfg.ProcessWebhookUsername(entry.Username)]; ok {
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
				w.cfg.BanDurationForReason(events.ReasonTorrent),
			)

			w.applyBan(event, adminwebhook.Data{
				Event:      event,
				ServerName: w.cfg.EffectiveWebhookServerName(),
				TorrentTag: torrentDecision.Tag,
			})
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
		w.cfg.BanDurationForReason(events.ReasonIPLimit),
	)

	w.applyBan(event, adminwebhook.Data{
		Event:      event,
		ServerName: w.cfg.EffectiveWebhookServerName(),
		UniqueIPs:  decision.UniqueIPs,
		Limit:      w.cfg.IPLimit,
		Window:     w.cfg.Window,
	})
}

func (w *Watcher) applyBan(event events.Event, adminData adminwebhook.Data) {
	result := w.distributor.Apply(event)
	if !result.AnyApplied() {
		slog.Error("ban failed", "reason", event.Reason, "ip", event.ClientIP, "local_error", result.LocalError, "remote_results", len(result.TargetResults))
		return
	}

	event.EnforcedAt = time.Now()
	adminData.Event = event
	adminData.DistributionScope = string(result.Scope)
	adminData.DistributionFullSuccess = result.FullySuccessful
	adminData.DistributionPartialFailure = result.PartiallyFailed
	if err := w.storage.AddBan(event); err != nil {
		slog.Error("storage add ban failed after firewall ban", "ip", event.ClientIP, "err", err)
		rollbackResult := w.distributor.Revoke(event)
		if rollbackResult.PartiallyFailed || !rollbackResult.AnyApplied() {
			slog.Error("ban rollback failed", "ip", event.ClientIP, "local_error", rollbackResult.LocalError, "remote_results", len(rollbackResult.TargetResults))
		}
		return
	}

	slog.Info("banned",
		"reason", event.Reason,
		"ip", event.ClientIP,
		"email", event.RawUsername,
		"processed_username", event.ProcessedUsername,
		"distribution_scope", result.Scope,
		"distribution_full_success", result.FullySuccessful,
		"distribution_partial_failure", result.PartiallyFailed,
		"expires", event.ExpiresAt.Format(time.RFC3339),
	)

	if w.notifier != nil && w.cfg.ShouldNotify(event.Reason) {
		go w.notifier.Notify(event)
	}
	if w.adminNotifier != nil {
		go w.adminNotifier.Notify(adminData)
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
			slog.Info("ban already present in firewall", "reason", b.Reason, "ip", b.IP, "email", b.Email, "processed_username", b.ProcessedUsername, "source", b.Source, "expires", b.ExpiresAt.Format(time.RFC3339))
			continue
		}

		restoreEvent := events.Event{
			Reason:            b.Reason,
			Action:            events.ActionBan,
			RawUsername:       b.Email,
			ProcessedUsername: b.ProcessedUsername,
			ClientIP:          b.IP,
			Source:            b.Source,
			DetectedAt:        b.DetectedAt,
			EnforcedAt:        b.EnforcedAt,
			ExpiresAt:         b.ExpiresAt,
		}
		result := w.distributor.Apply(restoreEvent)
		if !result.AnyApplied() {
			slog.Warn("restore ban failed", "ip", b.IP, "local_error", result.LocalError, "remote_results", len(result.TargetResults))
		} else {
			slog.Info("restored ban", "reason", b.Reason, "ip", b.IP, "email", b.Email, "processed_username", b.ProcessedUsername, "source", b.Source, "distribution_scope", result.Scope, "distribution_full_success", result.FullySuccessful, "distribution_partial_failure", result.PartiallyFailed, "expires", b.ExpiresAt.Format(time.RFC3339))
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
			event := w.newUnbanEvent(b)
			result := w.distributor.Revoke(event)
			if !result.AnyApplied() {
				slog.Warn("unban failed", "ip", b.IP, "local_error", result.LocalError, "remote_results", len(result.TargetResults))
				continue
			}

			if err := w.storage.RemoveBan(b.IP); err != nil {
				slog.Error("remove ban failed after firewall unban", "ip", b.IP, "err", err)
				continue
			}

			slog.Info("unbanned",
				"reason", event.Reason,
				"ip", event.ClientIP,
				"email", event.RawUsername,
				"processed_username", event.ProcessedUsername,
				"distribution_scope", result.Scope,
				"distribution_full_success", result.FullySuccessful,
				"distribution_partial_failure", result.PartiallyFailed,
			)
			if w.notifier != nil && w.cfg.WebhookNotifyUnban && w.cfg.ShouldNotify(event.Reason) {
				go w.notifier.Notify(event)
			}
			if w.adminNotifier != nil && w.cfg.AdminNotifications.NotifyUnban {
				go w.adminNotifier.Notify(adminwebhook.Data{
					Event:                      event,
					ServerName:                 w.cfg.EffectiveWebhookServerName(),
					DistributionScope:          string(result.Scope),
					DistributionFullSuccess:    result.FullySuccessful,
					DistributionPartialFailure: result.PartiallyFailed,
				})
			}
		}
	}
}

func (w *Watcher) newUnbanEvent(record storage.BanRecord) events.Event {
	processedUsername := record.ProcessedUsername
	if processedUsername == "" {
		processedUsername = w.cfg.ProcessWebhookUsername(record.Email)
	}
	switch record.Reason {
	case events.ReasonTorrent:
		return events.NewTorrentUnbanEvent(record.Email, processedUsername, record.IP, record.Source, time.Now())
	default:
		return events.NewIPLimitUnbanEvent(record.Email, processedUsername, record.IP, record.Source, time.Now())
	}
}

func (w *Watcher) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		w.detector.Cleanup(time.Now())
	}
}
