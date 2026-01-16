package monitoring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Baseline represents a security state snapshot
type Baseline struct {
	Timestamp string                 `json:"timestamp"`
	Snapshot  map[string]interface{} `json:"snapshot"`
}

// BaselineManager handles baseline persistence and comparison
type BaselineManager struct {
	baselinePath string
	baseline     *Baseline
}

// NewBaselineManager creates a new baseline manager
func NewBaselineManager(baselinePath string) *BaselineManager {
	// Ensure parent directory exists
	dir := filepath.Dir(baselinePath)
	os.MkdirAll(dir, 0700)

	return &BaselineManager{
		baselinePath: baselinePath,
	}
}

// Load reads the baseline from disk
func (m *BaselineManager) Load() (*Baseline, error) {
	data, err := os.ReadFile(m.baselinePath)
	if err != nil {
		return nil, err
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}

	m.baseline = &baseline
	return m.baseline, nil
}

// Save writes an audit report as the new baseline
func (m *BaselineManager) Save(report map[string]interface{}) error {
	baseline := &Baseline{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Snapshot:  m.ExtractComparableData(report),
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(m.baselinePath, data, 0600); err != nil {
		return err
	}

	m.baseline = baseline
	return nil
}

// GetBaseline returns the current baseline, loading if needed
func (m *BaselineManager) GetBaseline() *Baseline {
	if m.baseline == nil {
		m.Load()
	}
	return m.baseline
}

// GetPath returns the baseline file path
func (m *BaselineManager) GetPath() string {
	return m.baselinePath
}

// ExtractComparableData extracts security-relevant data for comparison
func (m *BaselineManager) ExtractComparableData(report map[string]interface{}) map[string]interface{} {
	comparable := make(map[string]interface{})

	// Firewall state
	if fw, ok := report["firewall"].(map[string]interface{}); ok {
		fwData := make(map[string]interface{})
		fwData["active"] = fw["active"]
		fwData["rulesCount"] = fw["rulesCount"]

		if ports, ok := fw["openPorts"].([]int); ok {
			sorted := make([]int, len(ports))
			copy(sorted, ports)
			sort.Ints(sorted)
			fwData["openPorts"] = sorted
		}
		comparable["firewall"] = fwData
	}

	// SSH config
	if ssh, ok := report["ssh"].(map[string]interface{}); ok {
		comparable["ssh"] = map[string]interface{}{
			"port":            ssh["port"],
			"permitRootLogin": ssh["permitRootLogin"],
			"passwordAuth":    ssh["passwordAuth"],
		}
	}

	// Services
	if svc, ok := report["services"].(map[string]interface{}); ok {
		svcData := make(map[string]interface{})
		svcData["exposedCount"] = svc["exposedCount"]

		if ports, ok := svc["listeningPorts"].([]int); ok {
			sorted := make([]int, len(ports))
			copy(sorted, ports)
			sort.Ints(sorted)
			svcData["listeningPorts"] = sorted
		}
		comparable["services"] = svcData
	}

	// Fail2ban
	if f2b, ok := report["fail2ban"].(map[string]interface{}); ok {
		comparable["fail2ban"] = map[string]interface{}{
			"active":      f2b["active"],
			"totalBanned": f2b["totalBanned"],
		}
	}

	// Threats
	if threats, ok := report["threats"].(map[string]interface{}); ok {
		comparable["threats"] = map[string]interface{}{
			"totalAttempts": threats["totalAttempts"],
			"uniqueIPs":     threats["uniqueIPs"],
		}
	}

	// Docker
	if docker, ok := report["docker"].(map[string]interface{}); ok {
		if installed, ok := docker["installed"].(bool); ok && installed {
			comparable["docker"] = map[string]interface{}{
				"runningContainers": docker["runningContainers"],
				"privilegedCount":   docker["privilegedCount"],
			}
		}
	}

	// Updates
	if upd, ok := report["updates"].(map[string]interface{}); ok {
		comparable["updates"] = map[string]interface{}{
			"securityUpdates": upd["securityUpdates"],
		}
	}

	return comparable
}
