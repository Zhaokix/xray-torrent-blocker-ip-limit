package webhook

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/events"
)

type Client struct {
	url             string
	defaultTemplate string
	ipLimitTemplate string
	torrentTemplate string
	serverName      string
	headers         map[string]string
	httpClient      *http.Client
}

func New(cfg *config.Config) *Client {
	headers := make(map[string]string, len(cfg.WebhookHeaders))
	for key, value := range cfg.WebhookHeaders {
		headers[key] = value
	}

	return &Client{
		url:             cfg.WebhookURL,
		defaultTemplate: cfg.WebhookTemplate,
		ipLimitTemplate: cfg.WebhookTemplateIPLimit,
		torrentTemplate: cfg.WebhookTemplateTorrent,
		serverName:      cfg.EffectiveWebhookServerName(),
		headers:         headers,
		httpClient:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Notify(event events.Event) {
	body := fmt.Sprintf(
		c.templateForReason(event.Reason),
		event.ProcessedUsername,
		event.ClientIP,
		c.serverName,
		string(event.Action),
		event.BanDuration.String(),
	)

	req, err := http.NewRequest(http.MethodPost, c.url, bytes.NewBufferString(body))
	if err != nil {
		slog.Error("webhook request creation failed", "err", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
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
