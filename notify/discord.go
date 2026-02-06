package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"chihuaudit/checks"
	"chihuaudit/config"
	"chihuaudit/state"
)

type DiscordMessage struct {
	Content string  `json:"content"`
	Embeds  []Embed `json:"embeds,omitempty"`
}

type Embed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Timestamp   string `json:"timestamp"`
}

func SendDiscord(cfg *config.Config, change state.Change) {
	if cfg.DiscordWebhook == "" {
		return
	}

	// Determine color based on severity
	var color int
	switch change.Key {
	case "disk_health", "failed_services":
		color = 0xFF0000 // Red for critical
	case "cpu_usage", "memory_usage", "disk_usage":
		color = 0xFFFF00 // Yellow for thresholds
	default:
		color = 0xFFA500 // Orange for warnings
	}

	message := DiscordMessage{
		Embeds: []Embed{
			{
				Title:       "Chihuaudit Alert",
				Description: change.Description,
				Color:       color,
				Timestamp:   time.Now().Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	resp, err := http.Post(cfg.DiscordWebhook, "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Failed to send Discord notification: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		fmt.Printf("Discord notification failed with status: %d\n", resp.StatusCode)
	}
}

// SendAuditSummary sends a full audit report summary to Discord
func SendAuditSummary(cfg *config.Config, results *checks.AuditResults) {
	if cfg.DiscordWebhook == "" {
		return
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("**Host:** %s", results.Hostname))
	lines = append(lines, fmt.Sprintf("**OS:** %s (%s)", results.OS, results.Kernel))
	lines = append(lines, fmt.Sprintf("**Firewall:** %s", results.Security.Firewall))
	lines = append(lines, fmt.Sprintf("**Services:** %d running, %d failed", results.Services.TotalRunning, results.Services.Failed))

	if results.Resources.MemTotal > 0 {
		lines = append(lines, fmt.Sprintf("**Memory:** %.0f%%", results.Resources.MemPercent))
	}
	for _, mount := range results.Resources.DiskMounts {
		lines = append(lines, fmt.Sprintf("**Disk %s:** %.0f%%", mount.Path, mount.Percent))
	}

	if results.System.PendingUpdates > 0 {
		lines = append(lines, fmt.Sprintf("**Pending Updates:** %d (%d security)", results.System.PendingUpdates, results.System.SecurityUpdates))
	}

	lines = append(lines, fmt.Sprintf("**Total Checks:** %d", results.TotalChecks))

	message := DiscordMessage{
		Embeds: []Embed{
			{
				Title:       fmt.Sprintf("Chihuaudit Report — %s", results.Hostname),
				Description: strings.Join(lines, "\n"),
				Color:       0x00CC99,
				Timestamp:   results.Timestamp.Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	resp, err := http.Post(cfg.DiscordWebhook, "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Failed to send Discord audit summary: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		fmt.Printf("Discord audit summary failed with status: %d\n", resp.StatusCode)
	}
}
