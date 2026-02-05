package config

import (
	"encoding/json"
	"testing"
)

func FuzzConfigUnmarshal(f *testing.F) {
	// Seed corpus with valid examples
	f.Add([]byte(`{"discord_webhook":"https://discord.com/api/webhooks/123"}`))
	f.Add([]byte(`{"notification_whitelist":{"cpu_threshold":50.0}}`))
	f.Add([]byte(`{}`))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		var cfg Config
		// Should never panic, even with invalid JSON
		_ = json.Unmarshal(data, &cfg)
	})
}
