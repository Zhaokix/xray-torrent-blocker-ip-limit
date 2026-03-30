package adminwebhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"xray-ip-limit/config"
	"xray-ip-limit/events"
)

func TestNotifySendsSelectedAdminFields(t *testing.T) {
	requestBody := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		requestBody <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.AdminNotifications.Enabled = true
	cfg.AdminNotifications.WebhookURL = server.URL
	cfg.AdminNotifications.Fields = []string{"reason", "username", "server", "unique_ips", "limit", "window", "ban_duration"}

	client := New(cfg)
	client.Notify(Data{
		Event: events.NewIPLimitBanEvent(
			"user@example.com",
			"user@example.com",
			"203.0.113.10",
			"/var/log/xray/access.log",
			time.Now(),
			5*time.Minute,
		),
		ServerName: "edge-1",
		UniqueIPs:  10,
		Limit:      1,
		Window:     5 * time.Minute,
	})

	select {
	case payload := <-requestBody:
		if payload["reason"] != "ip_limit" {
			t.Fatalf("expected reason ip_limit, got %#v", payload["reason"])
		}
		if payload["username"] != "user@example.com" {
			t.Fatalf("expected username user@example.com, got %#v", payload["username"])
		}
		if payload["server"] != "edge-1" {
			t.Fatalf("expected server edge-1, got %#v", payload["server"])
		}
		if payload["ban_duration"] != "5m0s" {
			t.Fatalf("expected ban_duration 5m0s, got %#v", payload["ban_duration"])
		}
		if payload["window"] != "5m0s" {
			t.Fatalf("expected window 5m0s, got %#v", payload["window"])
		}
		if got, ok := payload["unique_ips"].(float64); !ok || got != 10 {
			t.Fatalf("expected unique_ips 10, got %#v", payload["unique_ips"])
		}
		if got, ok := payload["limit"].(float64); !ok || got != 1 {
			t.Fatalf("expected limit 1, got %#v", payload["limit"])
		}
		if _, exists := payload["client_ip"]; exists {
			t.Fatal("did not expect client_ip in admin payload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected admin webhook request to be received")
	}
}

func TestNotifyOmitsIrrelevantOptionalFields(t *testing.T) {
	requestBody := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		requestBody <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.AdminNotifications.Enabled = true
	cfg.AdminNotifications.WebhookURL = server.URL
	cfg.AdminNotifications.Fields = []string{"reason", "torrent_tag", "source"}

	client := New(cfg)
	client.Notify(Data{
		Event: events.NewTorrentUnbanEvent(
			"user@example.com",
			"user@example.com",
			"203.0.113.10",
			"/var/log/xray/access.log",
			time.Now(),
		),
		ServerName: "edge-1",
	})

	select {
	case payload := <-requestBody:
		if payload["reason"] != "torrent" {
			t.Fatalf("expected reason torrent, got %#v", payload["reason"])
		}
		if _, exists := payload["torrent_tag"]; exists {
			t.Fatal("did not expect empty torrent_tag in payload")
		}
		if payload["source"] != "/var/log/xray/access.log" {
			t.Fatalf("expected source to be present, got %#v", payload["source"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected admin webhook request to be received")
	}
}

func TestNotifyUsesReasonSpecificTemplateForTelegramStyleBody(t *testing.T) {
	requestBody := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requestBody <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.AdminNotifications.Enabled = true
	cfg.AdminNotifications.WebhookURL = server.URL
	cfg.AdminNotifications.TemplateIPLimit = `{"chat_id":"123456789","text":"Violation: {{reason}}\nUser: {{username}}\nServer: {{server}}\nUnique IPs: {{unique_ips}}\nLimit: {{limit}}\nWindow: {{window}}\nAction: {{action}}\nDuration: {{ban_duration}}"}`
	cfg.AdminNotifications.Fields = nil

	client := New(cfg)
	client.Notify(Data{
		Event: events.NewIPLimitBanEvent(
			"user@example.com",
			"user@example.com",
			"203.0.113.10",
			"/var/log/xray/access.log",
			time.Now(),
			15*time.Minute,
		),
		ServerName: "usa-edge-1",
		UniqueIPs:  10,
		Limit:      1,
		Window:     5 * time.Minute,
	})

	select {
	case body := <-requestBody:
		expected := "{\"chat_id\":\"123456789\",\"text\":\"Violation: ip_limit\\nUser: user@example.com\\nServer: usa-edge-1\\nUnique IPs: 10\\nLimit: 1\\nWindow: 5m0s\\nAction: ban\\nDuration: 15m0s\"}"
		if body != expected {
			t.Fatalf("expected body %q, got %q", expected, body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected admin webhook request to be received")
	}
}
