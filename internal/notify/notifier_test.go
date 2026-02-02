package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/girste/chihuaudit/internal/config"
)

func TestNewNotifier(t *testing.T) {
	cfg := &config.NotifyConfig{
		Enabled:      true,
		OnlyOnIssues: true,
		MinSeverity:  "high",
	}

	n := NewNotifier(cfg)
	if n == nil {
		t.Fatal("NewNotifier returned nil")
	}

	if n.config != cfg {
		t.Error("config not set correctly")
	}
}

func TestShouldNotify(t *testing.T) {
	tests := []struct {
		name       string
		cfg        config.NotifyConfig
		status     string
		hasIssues  bool
		wantNotify bool
	}{
		{
			name:       "disabled",
			cfg:        config.NotifyConfig{Enabled: false},
			status:     "critical",
			hasIssues:  true,
			wantNotify: false,
		},
		{
			name: "only_on_issues_with_issues",
			cfg: config.NotifyConfig{
				Enabled:      true,
				OnlyOnIssues: true,
				Discord:      config.DiscordConfig{Enabled: true, WebhookURL: "http://test"},
			},
			status:     "high",
			hasIssues:  true,
			wantNotify: true,
		},
		{
			name: "only_on_issues_without_issues",
			cfg: config.NotifyConfig{
				Enabled:      true,
				OnlyOnIssues: true,
				Discord:      config.DiscordConfig{Enabled: true, WebhookURL: "http://test"},
			},
			status:     "ok",
			hasIssues:  false,
			wantNotify: false,
		},
		{
			name: "always_notify",
			cfg: config.NotifyConfig{
				Enabled:      true,
				OnlyOnIssues: false,
				Discord:      config.DiscordConfig{Enabled: true, WebhookURL: "http://test"},
			},
			status:     "ok",
			hasIssues:  false,
			wantNotify: true,
		},
		{
			name: "no_providers_enabled",
			cfg: config.NotifyConfig{
				Enabled:      true,
				OnlyOnIssues: false,
			},
			status:     "critical",
			hasIssues:  true,
			wantNotify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNotifier(&tt.cfg)
			got := n.ShouldNotify(tt.status, tt.hasIssues)
			if got != tt.wantNotify {
				t.Errorf("ShouldNotify() = %v, want %v", got, tt.wantNotify)
			}
		})
	}
}

func TestMeetsSeverityThreshold(t *testing.T) {
	tests := []struct {
		name        string
		minSeverity string
		status      string
		want        bool
	}{
		{"critical_meets_critical", "critical", "critical", true},
		{"high_meets_critical", "critical", "high", false},
		{"critical_meets_high", "high", "critical", true},
		{"high_meets_high", "high", "high", true},
		{"medium_meets_high", "high", "medium", false},
		{"low_meets_low", "low", "low", true},
		{"medium_meets_low", "low", "medium", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.NotifyConfig{MinSeverity: tt.minSeverity}
			n := NewNotifier(cfg)
			got := n.meetsSeverityThreshold(tt.status)
			if got != tt.want {
				t.Errorf("meetsSeverityThreshold(%s) with min=%s = %v, want %v",
					tt.status, tt.minSeverity, got, tt.want)
			}
		})
	}
}

func TestSendDiscord(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json")
		}
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.NotifyConfig{
		Discord: config.DiscordConfig{
			Enabled:    true,
			WebhookURL: server.URL,
			Username:   "Test Bot",
		},
	}

	n := NewNotifier(cfg)
	alert := &AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "test-host",
		Status:    "critical",
		Score:     45,
		Title:     "Test Alert",
		Summary:   "This is a test",
		Issues: []AlertIssue{
			{Severity: "critical", Message: "Test issue"},
		},
		Positives: []string{"Test positive"},
	}

	err := n.sendDiscord(context.Background(), alert)
	if err != nil {
		t.Fatalf("sendDiscord error: %v", err)
	}

	// Verify payload structure
	var payload discordPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if payload.Username != "Test Bot" {
		t.Errorf("Username = %s, want Test Bot", payload.Username)
	}

	if len(payload.Embeds) != 1 {
		t.Fatalf("Expected 1 embed, got %d", len(payload.Embeds))
	}

	// Discord generates standard titles based on severity
	if payload.Embeds[0].Title != "CRITICAL SECURITY ISSUES DETECTED" {
		t.Errorf("Embed title = %s, want CRITICAL SECURITY ISSUES DETECTED", payload.Embeds[0].Title)
	}

	// Discord standard red color #ED4245
	if payload.Embeds[0].Color != 0xED4245 {
		t.Errorf("Embed color = %x, want %x (Discord red)", payload.Embeds[0].Color, 0xED4245)
	}
}

func TestSendSlack(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.NotifyConfig{
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: server.URL,
			Username:   "Test Bot",
			Channel:    "#security",
		},
	}

	n := NewNotifier(cfg)
	alert := &AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "test-host",
		Status:    "high",
		Score:     65,
		Title:     "Test Alert",
		Summary:   "This is a test",
	}

	err := n.sendSlack(context.Background(), alert)
	if err != nil {
		t.Fatalf("sendSlack error: %v", err)
	}

	var payload slackPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if payload.Channel != "#security" {
		t.Errorf("Channel = %s, want #security", payload.Channel)
	}

	if payload.Username != "Test Bot" {
		t.Errorf("Username = %s, want Test Bot", payload.Username)
	}
}

func TestSendGenericWebhook(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.NotifyConfig{
		GenericWebhook: config.WebhookConfig{
			Enabled: true,
			URL:     server.URL,
			Method:  "POST",
			Headers: map[string]string{
				"X-Custom-Header": "test-value",
			},
		},
	}

	n := NewNotifier(cfg)
	alert := &AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "test-host",
		Status:    "ok",
		Score:     95,
		Title:     "Test Alert",
	}

	err := n.sendGenericWebhook(context.Background(), alert)
	if err != nil {
		t.Fatalf("sendGenericWebhook error: %v", err)
	}

	// Verify custom header
	if receivedHeaders.Get("X-Custom-Header") != "test-value" {
		t.Errorf("Custom header not received")
	}

	// Verify payload
	var payload AlertPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if payload.Score != 95 {
		t.Errorf("Score = %d, want 95", payload.Score)
	}
}

func TestSend_MultipleProviders(t *testing.T) {
	discordCalled := false
	slackCalled := false

	discordServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discordCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer discordServer.Close()

	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := &config.NotifyConfig{
		Enabled:     true,
		MinSeverity: "low",
		Discord: config.DiscordConfig{
			Enabled:    true,
			WebhookURL: discordServer.URL,
		},
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: slackServer.URL,
		},
	}

	n := NewNotifier(cfg)
	alert := &AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "test-host",
		Status:    "high",
		Score:     60,
		Title:     "Test",
	}

	result := n.Send(context.Background(), alert)

	if !discordCalled {
		t.Error("Discord webhook was not called")
	}

	if !slackCalled {
		t.Error("Slack webhook was not called")
	}

	if !result.Success {
		t.Error("Send should have succeeded")
	}

	if len(result.Sent) != 2 {
		t.Errorf("Expected 2 sent, got %d", len(result.Sent))
	}
}

func TestSend_WebhookFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &config.NotifyConfig{
		Enabled:     true,
		MinSeverity: "low",
		Discord: config.DiscordConfig{
			Enabled:    true,
			WebhookURL: server.URL,
		},
	}

	n := NewNotifier(cfg)
	alert := &AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "test-host",
		Status:    "high",
		Title:     "Test",
	}

	result := n.Send(context.Background(), alert)

	if result.Success {
		t.Error("Send should have failed")
	}

	if len(result.Failed) != 1 {
		t.Errorf("Expected 1 failure, got %d", len(result.Failed))
	}

	if !strings.Contains(result.Failed[0].Error, "500") {
		t.Errorf("Error should mention status code, got: %s", result.Failed[0].Error)
	}
}

func TestTestWebhook(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.NotifyConfig{
		Discord: config.DiscordConfig{
			Enabled:    true,
			WebhookURL: server.URL,
		},
	}

	n := NewNotifier(cfg)
	err := n.TestWebhook(context.Background(), "discord")

	if err != nil {
		t.Fatalf("TestWebhook error: %v", err)
	}

	if !called {
		t.Error("Webhook was not called")
	}
}

func TestTestWebhook_UnknownProvider(t *testing.T) {
	cfg := &config.NotifyConfig{}
	n := NewNotifier(cfg)

	err := n.TestWebhook(context.Background(), "unknown")
	if err == nil {
		t.Error("Expected error for unknown provider")
	}
}
