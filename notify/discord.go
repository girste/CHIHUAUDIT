package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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
	color := 0xFFA500 // Orange for warnings
	if change.Key == "disk_health" || change.Key == "failed_services" {
		color = 0xFF0000 // Red for critical
	} else if change.Key == "cpu_usage" || change.Key == "memory_usage" || change.Key == "disk_usage" {
		color = 0xFFFF00 // Yellow for thresholds
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		fmt.Printf("Discord notification failed with status: %d\n", resp.StatusCode)
	}
}
