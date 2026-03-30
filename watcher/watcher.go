package watcher

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/nxadm/tail"
	"xray-ip-limit/config"
	"xray-ip-limit/firewall"
	"xray-ip-limit/storage"
)

type Watcher struct {
	cfg          *config.Config
	storage      *storage.Storage
	firewall     *firewall.Manager
	httpClient   *http.Client
	mu           sync.Mutex
	windows      map[string]map[string]time.Time
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
		windows:      make(map[string]map[string]time.Time),
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

// parseLine extracts the client IP and email from an Xray access log line.
// It expects a "from " token followed by host:port and returns an empty email when absent.
func parseLine(line string) (ip, email string, ok bool) {
	fromIdx := strings.Index(line, "from ")
	if fromIdx == -1 {
		return "", "", false
	}

	ipStart := fromIdx + len("from ")
	if ipStart >= len(line) {
		return "", "", false
	}

	addrToken, ok := extractAddressToken(line[ipStart:])
	if !ok {
		return "", "", false
	}

	ip, ok = parseClientIP(addrToken)
	if !ok {
		return "", "", false
	}

	emailIdx := strings.Index(line, "email: ")
	if emailIdx == -1 {
		return ip, "", true
	}

	emailStart := emailIdx + len("email: ")
	if emailStart >= len(line) {
		return ip, "", true
	}

	emailFields := strings.Fields(line[emailStart:])
	if len(emailFields) == 0 {
		return ip, "", true
	}

	return ip, emailFields[0], true
}

func (w *Watcher) processLine(line string) {
	ip, email, ok := parseLine(line)
	if !ok || email == "" {
		return
	}

	if _, ok := w.bypass[ip]; ok {
		return
	}
	if _, ok := w.bypassEmails[email]; ok {
		return
	}
	if w.storage.IsBanned(ip) {
		return
	}

	w.mu.Lock()
	now := time.Now()
	window := w.cfg.Window

	if w.windows[email] == nil {
		w.windows[email] = make(map[string]time.Time)
	}

	w.windows[email][ip] = now

	for existingIP, lastSeen := range w.windows[email] {
		if now.Sub(lastSeen) > window {
			delete(w.windows[email], existingIP)
		}
	}

	uniqueIPs := len(w.windows[email])
	if uniqueIPs <= w.cfg.IPLimit {
		w.mu.Unlock()
		return
	}

	delete(w.windows[email], ip)
	w.mu.Unlock()

	slog.Warn("ip limit exceeded",
		"email", email,
		"unique_ips", uniqueIPs,
		"limit", w.cfg.IPLimit,
		"banning_ip", ip,
	)

	expiresAt := now.Add(w.cfg.BanDuration)
	if err := w.firewall.Ban(ip); err != nil {
		slog.Error("ban failed", "ip", ip, "err", err)
		return
	}

	if err := w.storage.AddBan(ip, email, expiresAt); err != nil {
		slog.Error("storage add ban failed after firewall ban", "ip", ip, "err", err)
		if rollbackErr := w.firewall.Unban(ip); rollbackErr != nil {
			slog.Error("ban rollback failed", "ip", ip, "err", rollbackErr)
		}
		return
	}

	slog.Info("banned", "ip", ip, "email", email, "expires", expiresAt.Format(time.RFC3339))

	if w.cfg.SendWebhook && w.cfg.WebhookURL != "" {
		go w.sendWebhook(email, ip, "ban", w.cfg.BanDuration.String())
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

			slog.Info("unbanned", "ip", b.IP, "email", b.Email)
			if w.cfg.SendWebhook && w.cfg.WebhookURL != "" && w.cfg.WebhookNotifyUnban {
				go w.sendWebhook(b.Email, b.IP, "unban", "0s")
			}
		}
	}
}

func (w *Watcher) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		w.mu.Lock()
		now := time.Now()
		window := w.cfg.Window
		for email, ips := range w.windows {
			for ip, lastSeen := range ips {
				if now.Sub(lastSeen) > window {
					delete(ips, ip)
				}
			}
			if len(ips) == 0 {
				delete(w.windows, email)
			}
		}
		w.mu.Unlock()
	}
}

func (w *Watcher) sendWebhook(email, ip, action string, duration string) {
	body := fmt.Sprintf(w.cfg.WebhookTemplate, email, ip, action, duration)
	resp, err := w.httpClient.Post(w.cfg.WebhookURL, "application/json", bytes.NewBufferString(body))
	if err != nil {
		slog.Error("webhook failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		slog.Warn("webhook returned non-success status", "status", resp.StatusCode, "action", action)
		return
	}

	slog.Info("webhook sent", "status", resp.StatusCode, "action", action)
}

func extractAddressToken(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}

	token := fields[0]
	switch {
	case strings.HasPrefix(token, "tcp:"):
		return strings.TrimPrefix(token, "tcp:"), true
	case strings.HasPrefix(token, "udp:"):
		return strings.TrimPrefix(token, "udp:"), true
	default:
		return token, true
	}
}

func parseClientIP(token string) (string, bool) {
	if strings.HasSuffix(token, ":") {
		return "", false
	}

	host, _, err := net.SplitHostPort(token)
	if err != nil {
		addr, parseErr := netip.ParseAddr(token)
		if parseErr != nil {
			return "", false
		}
		return addr.Unmap().String(), true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}

	return addr.Unmap().String(), true
}
