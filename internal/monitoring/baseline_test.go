package monitoring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewBaselineManager(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "nested", "dir", "baseline.json")

	bm := NewBaselineManager(baselinePath)

	if bm == nil {
		t.Fatal("NewBaselineManager returned nil")
	}

	if bm.baselinePath != baselinePath {
		t.Errorf("Expected path %s, got %s", baselinePath, bm.baselinePath)
	}

	// Check that parent directory was created
	parentDir := filepath.Dir(baselinePath)
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		t.Error("Parent directory was not created")
	}
}

func TestBaselineManager_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	bm := NewBaselineManager(baselinePath)

	// Create a test report
	report := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active":     true,
			"rulesCount": 5,
			"openPorts":  []int{80, 443, 22},
		},
		"ssh": map[string]interface{}{
			"port":            22,
			"permitRootLogin": "no",
			"passwordAuth":    false,
		},
	}

	// Save baseline
	if err := bm.Save(report); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		t.Error("Baseline file was not created")
	}

	// Load baseline
	loaded, err := bm.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}

	if loaded.Snapshot == nil {
		t.Fatal("Snapshot should not be nil")
	}

	// Verify data
	if fw, ok := loaded.Snapshot["firewall"].(map[string]interface{}); ok {
		if fw["active"] != true {
			t.Error("Firewall active should be true")
		}
	} else {
		t.Error("Firewall data not found in snapshot")
	}
}

func TestBaselineManager_GetBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")

	bm := NewBaselineManager(baselinePath)

	// GetBaseline without loading should return nil (no file exists)
	baseline := bm.GetBaseline()
	if baseline != nil {
		t.Error("Expected nil baseline when no file exists")
	}

	// Save a baseline
	report := map[string]interface{}{"test": "data"}
	if err := bm.Save(report); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// GetBaseline should return the saved baseline
	baseline = bm.GetBaseline()
	if baseline == nil {
		t.Fatal("Expected non-nil baseline after save")
	}

	if baseline.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestBaselineManager_GetPath(t *testing.T) {
	path := "/tmp/test/baseline.json"
	bm := NewBaselineManager(path)

	if bm.GetPath() != path {
		t.Errorf("Expected path %s, got %s", path, bm.GetPath())
	}
}

func TestBaselineManager_ExtractComparableData(t *testing.T) {
	bm := NewBaselineManager("/tmp/test.json")

	report := map[string]interface{}{
		"firewall": map[string]interface{}{
			"active":     true,
			"rulesCount": 10,
			"openPorts":  []int{443, 80, 22}, // Unsorted
		},
		"ssh": map[string]interface{}{
			"port":            2222,
			"permitRootLogin": "no",
			"passwordAuth":    false,
		},
		"services": map[string]interface{}{
			"exposedCount":    3,
			"listeningPorts":  []int{3000, 8080, 5432}, // Unsorted
		},
		"fail2ban": map[string]interface{}{
			"active":      true,
			"totalBanned": 42,
		},
		"threats": map[string]interface{}{
			"totalAttempts": 1337,
			"uniqueIPs":     25,
		},
		"docker": map[string]interface{}{
			"installed":         true,
			"runningContainers": 5,
			"privilegedCount":   1,
		},
		"updates": map[string]interface{}{
			"securityUpdates": 3,
		},
	}

	comparable := bm.ExtractComparableData(report)

	if comparable == nil {
		t.Fatal("ExtractComparableData returned nil")
	}

	// Check firewall
	if fw, ok := comparable["firewall"].(map[string]interface{}); ok {
		if fw["active"] != true {
			t.Error("Firewall active should be true")
		}
		if fw["rulesCount"] != 10 {
			t.Errorf("Expected rulesCount 10, got %v", fw["rulesCount"])
		}
		// Check ports are sorted
		if ports, ok := fw["openPorts"].([]int); ok {
			if len(ports) != 3 {
				t.Errorf("Expected 3 ports, got %d", len(ports))
			}
			// Verify sorted order
			if len(ports) == 3 && (ports[0] != 22 || ports[1] != 80 || ports[2] != 443) {
				t.Errorf("Ports not sorted correctly: %v", ports)
			}
		} else {
			t.Error("openPorts not found or wrong type")
		}
	} else {
		t.Error("Firewall data not extracted")
	}

	// Check SSH
	if ssh, ok := comparable["ssh"].(map[string]interface{}); ok {
		if ssh["port"] != 2222 {
			t.Errorf("Expected SSH port 2222, got %v", ssh["port"])
		}
		if ssh["passwordAuth"] != false {
			t.Error("Expected passwordAuth false")
		}
	} else {
		t.Error("SSH data not extracted")
	}

	// Check services
	if svc, ok := comparable["services"].(map[string]interface{}); ok {
		if ports, ok := svc["listeningPorts"].([]int); ok {
			// Verify sorted
			if len(ports) == 3 && (ports[0] != 3000 || ports[1] != 5432 || ports[2] != 8080) {
				t.Errorf("Service ports not sorted correctly: %v", ports)
			}
		}
	} else {
		t.Error("Services data not extracted")
	}

	// Check fail2ban
	if f2b, ok := comparable["fail2ban"].(map[string]interface{}); ok {
		if f2b["totalBanned"] != 42 {
			t.Errorf("Expected totalBanned 42, got %v", f2b["totalBanned"])
		}
	} else {
		t.Error("Fail2ban data not extracted")
	}

	// Check threats
	if threats, ok := comparable["threats"].(map[string]interface{}); ok {
		if threats["uniqueIPs"] != 25 {
			t.Errorf("Expected uniqueIPs 25, got %v", threats["uniqueIPs"])
		}
	} else {
		t.Error("Threats data not extracted")
	}

	// Check docker
	if docker, ok := comparable["docker"].(map[string]interface{}); ok {
		if docker["runningContainers"] != 5 {
			t.Errorf("Expected runningContainers 5, got %v", docker["runningContainers"])
		}
		if docker["privilegedCount"] != 1 {
			t.Errorf("Expected privilegedCount 1, got %v", docker["privilegedCount"])
		}
	} else {
		t.Error("Docker data not extracted")
	}

	// Check updates
	if upd, ok := comparable["updates"].(map[string]interface{}); ok {
		if upd["securityUpdates"] != 3 {
			t.Errorf("Expected securityUpdates 3, got %v", upd["securityUpdates"])
		}
	} else {
		t.Error("Updates data not extracted")
	}
}

func TestBaselineManager_ExtractComparableData_DockerNotInstalled(t *testing.T) {
	bm := NewBaselineManager("/tmp/test.json")

	report := map[string]interface{}{
		"docker": map[string]interface{}{
			"installed": false,
		},
	}

	comparable := bm.ExtractComparableData(report)

	// Docker should not be in comparable when not installed
	if _, ok := comparable["docker"]; ok {
		t.Error("Docker should not be in comparable data when not installed")
	}
}

func TestBaseline_Struct(t *testing.T) {
	baseline := Baseline{
		Timestamp: "2024-01-01T00:00:00Z",
		Snapshot: map[string]interface{}{
			"test": "data",
		},
	}

	if baseline.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if baseline.Snapshot == nil {
		t.Error("Snapshot should not be nil")
	}
}
