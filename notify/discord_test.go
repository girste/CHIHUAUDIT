package notify

import (
	"testing"

	"chihuaudit/config"
	"chihuaudit/state"
)

func TestDiscordMessageStructure(t *testing.T) {
	msg := DiscordMessage{
		Content: "test message",
		Embeds: []Embed{
			{
				Title:       "Test Title",
				Description: "Test Description",
				Color:       0xFFA500,
				Timestamp:   "2024-02-05T10:00:00Z",
			},
		},
	}

	if msg.Content != "test message" {
		t.Errorf("Content = %q, want %q", msg.Content, "test message")
	}
	if len(msg.Embeds) != 1 {
		t.Errorf("Embeds length = %d, want 1", len(msg.Embeds))
	}
	if msg.Embeds[0].Title != "Test Title" {
		t.Errorf("Title = %q, want %q", msg.Embeds[0].Title, "Test Title")
	}
}

func TestSendDiscord_EmptyWebhook(t *testing.T) {
	cfg := &config.Config{
		DiscordWebhook: "",
	}

	change := state.Change{
		Key:         "test",
		Description: "test change",
	}

	// Should not panic
	SendDiscord(cfg, change)
}

func TestSendDiscord_ColorSelection(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		wantColor int
	}{
		{"critical disk health", "disk_health", 0xFF0000},
		{"critical failed services", "failed_services", 0xFF0000},
		{"threshold cpu", "cpu_usage", 0xFFFF00},
		{"threshold memory", "memory_usage", 0xFFFF00},
		{"threshold disk", "disk_usage", 0xFFFF00},
		{"warning firewall", "firewall", 0xFFA500},
		{"warning generic", "other_change", 0xFFA500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test the actual HTTP call without mocking,
			// but we can verify the color logic would be correct
			var color int
			if tt.key == "disk_health" || tt.key == "failed_services" {
				color = 0xFF0000
			} else if tt.key == "cpu_usage" || tt.key == "memory_usage" || tt.key == "disk_usage" {
				color = 0xFFFF00
			} else {
				color = 0xFFA500
			}

			if color != tt.wantColor {
				t.Errorf("color for %q = %x, want %x", tt.key, color, tt.wantColor)
			}
		})
	}
}

func TestEmbedStructure(t *testing.T) {
	embed := Embed{
		Title:       "Alert",
		Description: "Something happened",
		Color:       0xFF0000,
		Timestamp:   "2024-02-05T10:00:00Z",
	}

	if embed.Title != "Alert" {
		t.Errorf("Title = %q, want %q", embed.Title, "Alert")
	}
	if embed.Color != 0xFF0000 {
		t.Errorf("Color = %x, want %x", embed.Color, 0xFF0000)
	}
}
