package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/girste/mcp-cybersec-watchdog/internal/config"
)

const (
	webhookTimeout = 10 * time.Second
)

// Severity levels for filtering
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// AlertPayload is the standardized alert data
type AlertPayload struct {
	Timestamp   string                 `json:"timestamp"`
	Hostname    string                 `json:"hostname"`
	Status      string                 `json:"status"` // critical, warning, ok
	Score       int                    `json:"score"`
	Title       string                 `json:"title"`
	Summary     string                 `json:"summary"`
	Issues      []AlertIssue           `json:"issues,omitempty"`
	Positives   []string               `json:"positives,omitempty"`
	AnomalyFile string                 `json:"anomaly_file,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// AlertIssue represents a single security issue
type AlertIssue struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Category string `json:"category,omitempty"`
}

// NotifyResult contains the result of notification attempts
type NotifyResult struct {
	Success  bool              `json:"success"`
	Sent     []string          `json:"sent"`
	Failed   []NotifyError     `json:"failed,omitempty"`
	Skipped  string            `json:"skipped,omitempty"`
}

type NotifyError struct {
	Provider string `json:"provider"`
	Error    string `json:"error"`
}

// Notifier handles sending alerts to various webhook destinations
type Notifier struct {
	config *config.NotifyConfig
	client *http.Client
}

// NewNotifier creates a new notifier instance
func NewNotifier(cfg *config.NotifyConfig) *Notifier {
	return &Notifier{
		config: cfg,
		client: &http.Client{Timeout: webhookTimeout},
	}
}

// ShouldNotify checks if notification should be sent based on config
func (n *Notifier) ShouldNotify(status string, hasIssues bool) bool {
	if !n.config.Enabled {
		return false
	}

	// Check if we should only notify on issues
	if n.config.OnlyOnIssues && !hasIssues {
		return false
	}

	return n.config.Discord.Enabled || n.config.Slack.Enabled || n.config.GenericWebhook.Enabled
}

// Send sends an alert to all configured webhooks
func (n *Notifier) Send(ctx context.Context, alert *AlertPayload) *NotifyResult {
	result := &NotifyResult{
		Success: true,
		Sent:    []string{},
		Failed:  []NotifyError{},
	}

	if !n.config.Enabled {
		result.Skipped = "notifications disabled"
		return result
	}

	// Check severity filter
	if !n.meetsSeverityThreshold(alert.Status) {
		result.Skipped = fmt.Sprintf("severity %s below threshold %s", alert.Status, n.config.MinSeverity)
		return result
	}

	// Send to Discord
	if n.config.Discord.Enabled && n.config.Discord.WebhookURL != "" {
		if err := n.sendDiscord(ctx, alert); err != nil {
			result.Failed = append(result.Failed, NotifyError{Provider: "discord", Error: err.Error()})
			result.Success = false
		} else {
			result.Sent = append(result.Sent, "discord")
		}
	}

	// Send to Slack
	if n.config.Slack.Enabled && n.config.Slack.WebhookURL != "" {
		if err := n.sendSlack(ctx, alert); err != nil {
			result.Failed = append(result.Failed, NotifyError{Provider: "slack", Error: err.Error()})
			result.Success = false
		} else {
			result.Sent = append(result.Sent, "slack")
		}
	}

	// Send to generic webhook
	if n.config.GenericWebhook.Enabled && n.config.GenericWebhook.URL != "" {
		if err := n.sendGenericWebhook(ctx, alert); err != nil {
			result.Failed = append(result.Failed, NotifyError{Provider: "webhook", Error: err.Error()})
			result.Success = false
		} else {
			result.Sent = append(result.Sent, "webhook")
		}
	}

	return result
}

func (n *Notifier) meetsSeverityThreshold(status string) bool {
	severityOrder := map[string]int{
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}

	statusLevel := severityOrder[strings.ToLower(status)]
	thresholdLevel := severityOrder[strings.ToLower(n.config.MinSeverity)]

	// "ok" status should not trigger notifications if onlyOnIssues is true
	if statusLevel == 0 {
		return !n.config.OnlyOnIssues
	}

	return statusLevel >= thresholdLevel
}

// Discord webhook payload
type discordPayload struct {
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Content   string         `json:"content,omitempty"`
	Embeds    []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Timestamp   string         `json:"timestamp,omitempty"`
	Fields      []discordField `json:"fields,omitempty"`
	Footer      *discordFooter `json:"footer,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func (n *Notifier) sendDiscord(ctx context.Context, alert *AlertPayload) error {
	// Color based on status
	color := 0x2ECC71 // Green
	emoji := ":white_check_mark:"
	switch strings.ToLower(alert.Status) {
	case SeverityCritical:
		color = 0xE74C3C // Red
		emoji = ":red_circle:"
	case SeverityHigh:
		color = 0xE67E22 // Orange
		emoji = ":orange_circle:"
	case SeverityMedium:
		color = 0xF1C40F // Yellow
		emoji = ":yellow_circle:"
	}

	// Build description
	description := alert.Summary
	if len(alert.Issues) > 0 {
		description += "\n\n**Issues Found:**"
		for i, issue := range alert.Issues {
			if i >= 5 { // Limit to 5 issues in Discord
				description += fmt.Sprintf("\n... and %d more", len(alert.Issues)-5)
				break
			}
			description += fmt.Sprintf("\n• [%s] %s", strings.ToUpper(issue.Severity), issue.Message)
		}
	}

	// Build fields
	fields := []discordField{
		{Name: "Status", Value: fmt.Sprintf("%s %s", emoji, strings.ToUpper(alert.Status)), Inline: true},
		{Name: "Score", Value: fmt.Sprintf("%d/100", alert.Score), Inline: true},
		{Name: "Host", Value: alert.Hostname, Inline: true},
	}

	if len(alert.Positives) > 0 {
		posText := ""
		for i, p := range alert.Positives {
			if i >= 3 {
				posText += fmt.Sprintf("\n... and %d more", len(alert.Positives)-3)
				break
			}
			posText += fmt.Sprintf(":white_check_mark: %s\n", p)
		}
		fields = append(fields, discordField{Name: "Positives", Value: posText, Inline: false})
	}

	payload := discordPayload{
		Username:  n.config.Discord.Username,
		AvatarURL: n.config.Discord.AvatarURL,
		Embeds: []discordEmbed{
			{
				Title:       alert.Title,
				Description: description,
				Color:       color,
				Timestamp:   alert.Timestamp,
				Fields:      fields,
				Footer:      &discordFooter{Text: "MCP Cybersec Watchdog"},
			},
		},
	}

	return n.postJSON(ctx, n.config.Discord.WebhookURL, payload)
}

// Slack webhook payload
type slackPayload struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color      string       `json:"color"`
	Title      string       `json:"title"`
	Text       string       `json:"text"`
	Fields     []slackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	FooterIcon string       `json:"footer_icon,omitempty"`
	Ts         int64        `json:"ts,omitempty"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (n *Notifier) sendSlack(ctx context.Context, alert *AlertPayload) error {
	// Color based on status
	color := "good" // Green
	emoji := ":white_check_mark:"
	switch strings.ToLower(alert.Status) {
	case SeverityCritical:
		color = "danger" // Red
		emoji = ":red_circle:"
	case SeverityHigh:
		color = "warning" // Orange
		emoji = ":large_orange_circle:"
	case SeverityMedium:
		color = "warning"
		emoji = ":large_yellow_circle:"
	}

	// Build text
	text := alert.Summary
	if len(alert.Issues) > 0 {
		text += "\n\n*Issues Found:*"
		for i, issue := range alert.Issues {
			if i >= 5 {
				text += fmt.Sprintf("\n... and %d more", len(alert.Issues)-5)
				break
			}
			text += fmt.Sprintf("\n• [%s] %s", strings.ToUpper(issue.Severity), issue.Message)
		}
	}

	fields := []slackField{
		{Title: "Status", Value: fmt.Sprintf("%s %s", emoji, strings.ToUpper(alert.Status)), Short: true},
		{Title: "Score", Value: fmt.Sprintf("%d/100", alert.Score), Short: true},
		{Title: "Host", Value: alert.Hostname, Short: true},
	}

	payload := slackPayload{
		Channel:   n.config.Slack.Channel,
		Username:  n.config.Slack.Username,
		IconEmoji: ":shield:",
		Text:      fmt.Sprintf("*%s*", alert.Title),
		Attachments: []slackAttachment{
			{
				Color:  color,
				Title:  alert.Title,
				Text:   text,
				Fields: fields,
				Footer: "MCP Cybersec Watchdog",
			},
		},
	}

	return n.postJSON(ctx, n.config.Slack.WebhookURL, payload)
}

func (n *Notifier) sendGenericWebhook(ctx context.Context, alert *AlertPayload) error {
	method := n.config.GenericWebhook.Method
	if method == "" {
		method = "POST"
	}

	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, n.config.GenericWebhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.config.GenericWebhook.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (n *Notifier) postJSON(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// TestWebhook sends a test notification
func (n *Notifier) TestWebhook(ctx context.Context, provider string) error {
	testAlert := &AlertPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  "test-host",
		Status:    "ok",
		Score:     95,
		Title:     "Test Notification",
		Summary:   "This is a test notification from MCP Cybersec Watchdog to verify webhook configuration.",
		Positives: []string{"Webhook configuration verified", "Connection successful"},
	}

	switch provider {
	case "discord":
		return n.sendDiscord(ctx, testAlert)
	case "slack":
		return n.sendSlack(ctx, testAlert)
	case "webhook":
		return n.sendGenericWebhook(ctx, testAlert)
	default:
		return fmt.Errorf("unknown provider: %s", provider)
	}
}
