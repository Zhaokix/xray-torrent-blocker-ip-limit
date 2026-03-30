package webhook

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/events"
)

func TestNotifyUsesReasonSpecificTemplate(t *testing.T) {
	requestBody := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.WebhookURL = server.URL
	cfg.WebhookTemplate = `{"fallback":"%s"}`
	cfg.WebhookTemplateIPLimit = `{"type":"ip_limit","chat_id":"%s","ip":"%s","server":"%s","action":"%s","duration":"%s"}`
	cfg.WebhookTemplateTorrent = `{"type":"torrent","chat_id":"%s","ip":"%s","server":"%s","action":"%s","duration":"%s"}`
	cfg.WebhookHeaders = map[string]string{"X-Test": "1"}
	cfg.WebhookServerName = "edge-1"

	client := New(cfg)
	client.Notify(events.NewTorrentBanEvent(
		"37.123",
		"123",
		"203.0.113.10",
		"/var/log/xray/access.log",
		time.Now(),
		5*time.Minute,
	))

	select {
	case body := <-requestBody:
		expected := `{"type":"torrent","chat_id":"123","ip":"203.0.113.10","server":"edge-1","action":"ban","duration":"5m0s"}`
		if body != expected {
			t.Fatalf("expected body %q, got %q", expected, body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected webhook request to be received")
	}
}

func TestNotifyFallsBackToDefaultTemplate(t *testing.T) {
	requestBody := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.WebhookURL = server.URL
	cfg.WebhookTemplate = `{"chat_id":"%s","ip":"%s","server":"%s","action":"%s","duration":"%s"}`
	cfg.WebhookServerName = "edge-2"

	client := New(cfg)
	client.Notify(events.NewIPLimitBanEvent(
		"37.123",
		"123",
		"203.0.113.11",
		"/var/log/xray/access.log",
		time.Now(),
		2*time.Minute,
	))

	select {
	case body := <-requestBody:
		expected := `{"chat_id":"123","ip":"203.0.113.11","server":"edge-2","action":"ban","duration":"2m0s"}`
		if body != expected {
			t.Fatalf("expected body %q, got %q", expected, body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected webhook request to be received")
	}
}
