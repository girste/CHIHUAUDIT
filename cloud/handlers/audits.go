package handlers

import (
	"chihuaudit/cloud/alerting"
	"chihuaudit/cloud/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- Rate limiter: in-memory per API key hash, 60 req/min sliding window ---

type rateBucket struct {
	mu     sync.Mutex
	times  []time.Time
	limit  int
	window time.Duration
}

func (b *rateBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-b.window)
	start := 0
	for start < len(b.times) && b.times[start].Before(cutoff) {
		start++
	}
	b.times = b.times[start:]
	if len(b.times) >= b.limit {
		return false
	}
	b.times = append(b.times, now)
	return true
}

var (
	rateMu      sync.Mutex
	rateBuckets = make(map[string]*rateBucket)
)

func getRateBucket(keyHash string) *rateBucket {
	rateMu.Lock()
	defer rateMu.Unlock()
	b, ok := rateBuckets[keyHash]
	if !ok {
		b = &rateBucket{limit: 60, window: time.Minute}
		rateBuckets[keyHash] = b
	}
	return b
}

func init() {
	go func() {
		for range time.Tick(5 * time.Minute) {
			rateMu.Lock()
			now := time.Now()
			for k, b := range rateBuckets {
				b.mu.Lock()
				if len(b.times) == 0 || now.Sub(b.times[len(b.times)-1]) > 2*time.Minute {
					delete(rateBuckets, k)
				}
				b.mu.Unlock()
			}
			rateMu.Unlock()
		}
	}()
}

// --- Validation ---

var knownSections = map[string]bool{
	"security": true, "services": true, "resources": true,
	"system": true, "hostname": true, "storage": true,
	"docker": true, "network": true, "logs": true,
	"backups": true, "tuning": true, "database": true,
}

func validateAuditBody(data json.RawMessage) error {
	if len(data) == 0 {
		return fmt.Errorf("empty body")
	}
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("body must be a JSON object")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("invalid JSON object")
	}
	if len(obj) == 0 {
		return fmt.Errorf("empty JSON object")
	}
	for k := range obj {
		if knownSections[strings.ToLower(k)] {
			return nil
		}
	}
	return fmt.Errorf("no recognized audit sections")
}

// normalizeJSONKeys recursively lowercases and converts PascalCase/camelCase keys to snake_case.
func normalizeJSONKeys(data json.RawMessage) json.RawMessage {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return data
	}
	normalized := normalizeValue(raw)
	out, err := json.Marshal(normalized)
	if err != nil {
		return data
	}
	return out
}

func normalizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(val))
		for k, v := range val {
			m[toSnakeCase(k)] = normalizeValue(v)
		}
		return m
	case []any:
		for i, item := range val {
			val[i] = normalizeValue(item)
		}
		return val
	default:
		return v
	}
}

func toSnakeCase(s string) string {
	var result []byte
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				prev := s[i-1]
				if prev >= 'a' && prev <= 'z' || prev >= '0' && prev <= '9' {
					result = append(result, '_')
				}
			}
			result = append(result, byte(c)+32) // toLower
		} else {
			result = append(result, byte(c))
		}
	}
	return string(result)
}

func HandlePushAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Body size limit: 2MB
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)

	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		http.Error(w, `{"error":"missing api key"}`, http.StatusUnauthorized)
		return
	}

	keyHash := models.HashAPIKey(apiKey)
	if !getRateBucket(keyHash).allow() {
		http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
		return
	}

	host, err := models.GetHostByAPIKey(apiKey)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}
		log.Printf("audit auth error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	var results json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&results); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	// Normalize keys to lowercase (agent sends PascalCase)
	results = normalizeJSONKeys(results)

	if err := validateAuditBody(results); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	audit, err := models.CreateAudit(host.ID, results)
	if err != nil {
		log.Printf("create audit error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if err := models.UpdateHostLastSeen(host.ID); err != nil {
		log.Printf("update last_seen error: %v", err)
	}

	go runAlerting(host.ID, host.Name, results)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(audit)
}

func runAlerting(hostID int, hostName string, currentResults json.RawMessage) {
	hostCfg, err := models.GetHostConfig(hostID)
	if err != nil {
		log.Printf("alerting: get host config: %v", err)
		return
	}

	cfg := &alerting.Config{
		WebhookURL:      hostCfg.WebhookURL,
		CPUThreshold:    hostCfg.CPUThreshold,
		MemoryThreshold: hostCfg.MemoryThreshold,
		DiskThreshold:   hostCfg.DiskThreshold,
		IgnoreChanges:   hostCfg.IgnoreChanges,
	}

	metrics := alerting.ExtractMetricValues(currentResults)
	for _, m := range metrics {
		var threshold float64
		switch {
		case m.Name == "cpu_percent":
			threshold = cfg.CPUThreshold
		case m.Name == "mem_percent":
			threshold = cfg.MemoryThreshold
		case strings.HasPrefix(m.Name, "disk:"):
			threshold = cfg.DiskThreshold
		default:
			continue
		}

		if m.Value > threshold {
			if err := models.UpsertThresholdBreach(hostID, m.Name, threshold, m.Value); err != nil {
				log.Printf("alerting: upsert breach: %v", err)
			}
		} else {
			if err := models.ResolveThresholdBreach(hostID, m.Name); err != nil {
				log.Printf("alerting: resolve breach: %v", err)
			}
		}
	}

	prevResults, err := models.GetPreviousAuditResults(hostID)
	if err != nil {
		log.Printf("alerting: get previous audit: %v", err)
		return
	}
	if prevResults == nil {
		return
	}

	changes := alerting.Compare(prevResults, currentResults, cfg)
	if len(changes) == 0 {
		return
	}

	log.Printf("alerting: %d changes detected for host %q", len(changes), hostName)

	if cfg.WebhookURL != "" {
		if err := alerting.SendWebhook(cfg.WebhookURL, hostName, changes); err != nil {
			log.Printf("alerting: webhook error for host %q: %v", hostName, err)
		}
	}
}

func HandleListAudits(w http.ResponseWriter, r *http.Request) {
	id, err := extractHostID(r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"invalid host id"}`, http.StatusBadRequest)
		return
	}

	audits, err := models.ListAuditsByHost(id, 50)
	if err != nil {
		log.Printf("list audits error: %v", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if audits == nil {
		audits = []models.Audit{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(audits)
}
