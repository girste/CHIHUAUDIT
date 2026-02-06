package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// SendWebhook posts the list of changes to the configured webhook URL.
// Supports Discord, Slack, and generic JSON webhooks.
func SendWebhook(webhookURL, hostName string, changes []Change) error {
	if webhookURL == "" || len(changes) == 0 {
		return nil
	}

	var body []byte
	var err error

	switch {
	case strings.Contains(webhookURL, "discord.com/api/webhooks"):
		body, err = buildDiscordPayload(hostName, changes)
	case strings.Contains(webhookURL, "hooks.slack.com"):
		body, err = buildSlackPayload(hostName, changes)
	default:
		body, err = buildGenericPayload(hostName, changes)
	}
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	log.Printf("webhook sent for host %q: %d changes", hostName, len(changes))
	return nil
}

func buildDiscordPayload(hostName string, changes []Change) ([]byte, error) {
	var lines []string
	for _, c := range changes {
		lines = append(lines, fmt.Sprintf("**%s** — %s", c.Key, c.Description))
	}

	payload := map[string]any{
		"content": fmt.Sprintf("🚨 **Chihuaudit Alert — %s**\n%s", hostName, strings.Join(lines, "\n")),
	}
	return json.Marshal(payload)
}

func buildSlackPayload(hostName string, changes []Change) ([]byte, error) {
	var lines []string
	for _, c := range changes {
		lines = append(lines, fmt.Sprintf("*%s* — %s", c.Key, c.Description))
	}

	payload := map[string]any{
		"text": fmt.Sprintf(":rotating_light: *Chihuaudit Alert — %s*\n%s", hostName, strings.Join(lines, "\n")),
	}
	return json.Marshal(payload)
}

func buildGenericPayload(hostName string, changes []Change) ([]byte, error) {
	payload := map[string]any{
		"host":      hostName,
		"changes":   changes,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	return json.Marshal(payload)
}

// SendTestWebhook sends a test notification to verify webhook configuration.
func SendTestWebhook(webhookURL, hostName string) error {
	if webhookURL == "" {
		return fmt.Errorf("webhook URL is empty")
	}

	testChanges := []Change{
		{
			Key:         "test",
			Description: fmt.Sprintf("Test notification from Chihuaudit Cloud for host %s", hostName),
			OldValue:    nil,
			NewValue:    "test",
		},
	}

	return SendWebhook(webhookURL, hostName+" (TEST)", testChanges)
}

// SendPersistentAlertWebhook sends a webhook for a metric that has been breached for an extended period.
func SendPersistentAlertWebhook(webhookURL, hostName, metric string, threshold, value float64, since time.Time) error {
	if webhookURL == "" {
		return nil
	}

	duration := time.Since(since).Truncate(time.Hour)
	changes := []Change{
		{
			Key:         metric,
			Description: fmt.Sprintf("%s above %.0f%% (currently %.1f%%) for %s", metric, threshold, value, duration),
			OldValue:    threshold,
			NewValue:    value,
		},
	}

	return SendWebhook(webhookURL, hostName+" (PERSISTENT)", changes)
}
