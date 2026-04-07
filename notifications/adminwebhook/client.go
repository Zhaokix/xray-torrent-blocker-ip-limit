package adminwebhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/events"
)

type Data struct {
	Event                      events.Event
	ServerName                 string
	UniqueIPs                  int
	Limit                      int
	Window                     time.Duration
	TorrentTag                 string
	DistributionScope          string
	DistributionFullSuccess    bool
	DistributionPartialFailure bool
}

type Client struct {
	url             string
	fields          []string
	defaultTemplate string
	ipLimitTemplate string
	torrentTemplate string
	headers         map[string]string
	httpClient      *http.Client
}

func New(cfg *config.Config) *Client {
	headers := make(map[string]string, len(cfg.AdminNotifications.Headers))
	for key, value := range cfg.AdminNotifications.Headers {
		headers[key] = value
	}

	fields := make([]string, len(cfg.AdminNotifications.Fields))
	copy(fields, cfg.AdminNotifications.Fields)

	return &Client{
		url:             cfg.AdminNotifications.WebhookURL,
		fields:          fields,
		defaultTemplate: cfg.AdminNotifications.Template,
		ipLimitTemplate: cfg.AdminNotifications.TemplateIPLimit,
		torrentTemplate: cfg.AdminNotifications.TemplateTorrent,
		headers:         headers,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Notify(data Data) {
	body, err := c.buildBody(data)
	if err != nil {
		slog.Error("admin webhook payload build failed", "err", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewBuffer(body))
	if err != nil {
		slog.Error("admin webhook request creation failed", "err", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Error("admin webhook failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		slog.Warn(
			"admin webhook returned non-success status",
			"status", resp.StatusCode,
			"action", data.Event.Action,
			"reason", data.Event.Reason,
			"body", string(responseBody),
		)
		return
	}

	slog.Info(
		"admin webhook sent",
		"status", resp.StatusCode,
		"action", data.Event.Action,
		"reason", data.Event.Reason,
		"username", data.Event.RawUsername,
	)
}

func (c *Client) buildPayload(data Data) map[string]any {
	payload := make(map[string]any, len(c.fields))
	for _, field := range c.fields {
		switch field {
		case "reason":
			payload[field] = string(data.Event.Reason)
		case "action":
			payload[field] = string(data.Event.Action)
		case "username":
			payload[field] = data.Event.RawUsername
		case "processed_username":
			payload[field] = data.Event.ProcessedUsername
		case "client_ip":
			payload[field] = data.Event.ClientIP
		case "server":
			payload[field] = data.ServerName
		case "source":
			payload[field] = data.Event.Source
		case "ban_duration":
			payload[field] = data.Event.BanDuration.String()
		case "detected_at":
			payload[field] = data.Event.DetectedAt.Format(time.RFC3339)
		case "enforced_at":
			payload[field] = formatTime(data.Event.EnforcedAt)
		case "expires_at":
			payload[field] = formatTime(data.Event.ExpiresAt)
		case "unique_ips":
			if data.UniqueIPs > 0 {
				payload[field] = data.UniqueIPs
			}
		case "limit":
			if data.Limit > 0 {
				payload[field] = data.Limit
			}
		case "window":
			if data.Window > 0 {
				payload[field] = data.Window.String()
			}
		case "torrent_tag":
			if data.TorrentTag != "" {
				payload[field] = data.TorrentTag
			}
		case "distribution_scope":
			if data.DistributionScope != "" {
				payload[field] = data.DistributionScope
			}
		case "distribution_full_success":
			payload[field] = data.DistributionFullSuccess
		case "distribution_partial_failure":
			payload[field] = data.DistributionPartialFailure
		}
	}

	return payload
}

func (c *Client) buildBody(data Data) ([]byte, error) {
	template := c.templateForReason(data.Event.Reason)
	if strings.TrimSpace(template) != "" {
		return []byte(applyTemplate(template, data)), nil
	}

	payload := c.buildPayload(data)
	return json.Marshal(payload)
}

func (c *Client) templateForReason(reason events.Reason) string {
	switch reason {
	case events.ReasonIPLimit:
		if c.ipLimitTemplate != "" {
			return c.ipLimitTemplate
		}
	case events.ReasonTorrent:
		if c.torrentTemplate != "" {
			return c.torrentTemplate
		}
	}

	return c.defaultTemplate
}

func applyTemplate(template string, data Data) string {
	replacer := strings.NewReplacer(
		"{{reason}}", string(data.Event.Reason),
		"{{action}}", string(data.Event.Action),
		"{{username}}", data.Event.RawUsername,
		"{{processed_username}}", data.Event.ProcessedUsername,
		"{{client_ip}}", data.Event.ClientIP,
		"{{server}}", data.ServerName,
		"{{source}}", data.Event.Source,
		"{{ban_duration}}", data.Event.BanDuration.String(),
		"{{detected_at}}", formatTime(data.Event.DetectedAt),
		"{{enforced_at}}", formatTime(data.Event.EnforcedAt),
		"{{expires_at}}", formatTime(data.Event.ExpiresAt),
		"{{unique_ips}}", intString(data.UniqueIPs),
		"{{limit}}", intString(data.Limit),
		"{{window}}", durationString(data.Window),
		"{{torrent_tag}}", data.TorrentTag,
		"{{distribution_scope}}", data.DistributionScope,
		"{{distribution_full_success}}", fmt.Sprintf("%t", data.DistributionFullSuccess),
		"{{distribution_partial_failure}}", fmt.Sprintf("%t", data.DistributionPartialFailure),
	)

	return replacer.Replace(template)
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}

	return value.Format(time.RFC3339)
}

func intString(value int) string {
	if value <= 0 {
		return ""
	}

	return fmt.Sprintf("%d", value)
}

func durationString(value time.Duration) string {
	if value <= 0 {
		return ""
	}

	return value.String()
}
