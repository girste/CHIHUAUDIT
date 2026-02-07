package cloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// SendAudit sends audit results to the cloud dashboard (if configured)
func SendAudit(cloudURL, apiKey string, results any) error {
	if cloudURL == "" || apiKey == "" {
		return nil // Cloud not configured, skip silently
	}

	// Normalize URL
	cloudURL = strings.TrimRight(cloudURL, "/")
	endpoint := cloudURL + "/api/audits"

	data, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("marshal audit: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	log.Printf("Audit sent to cloud: %s", cloudURL)
	return nil
}
