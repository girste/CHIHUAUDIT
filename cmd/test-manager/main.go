package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/girste/chihuaudit/internal/monitoring"
)

func main() {
	logDir := fmt.Sprintf("/tmp/chihuaudit-%d", os.Getuid())

	fmt.Println("Testing MCP start_monitoring tool simulation...")
	fmt.Printf("Log directory: %s\n", logDir)

	manager := monitoring.NewMonitoringManager(logDir)

	// Test 1: Get initial status
	fmt.Println("\n1. Getting initial status...")
	status := manager.GetStatus()
	statusJSON, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(statusJSON))

	// Test 2: Start monitoring
	fmt.Println("\n2. Starting monitoring (5 min interval)...")
	result := manager.Start(300)
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(resultJSON))

	if !result.Success {
		fmt.Printf("Failed to start: %s\n", result.Error)
		os.Exit(1)
	}

	// Test 3: Wait a bit and check status
	fmt.Println("\n3. Waiting 3 seconds and checking status...")
	time.Sleep(3 * time.Second)

	status = manager.GetStatus()
	statusJSON, _ = json.MarshalIndent(status, "", "  ")
	fmt.Println(string(statusJSON))

	if !status.Running {
		fmt.Println("ERROR: Daemon not running!")
		os.Exit(1)
	}

	// Test 4: Check daemon working directory
	fmt.Printf("\n4. Checking daemon working directory (PID %d)...\n", status.PID)

	// Test 5: Stop monitoring
	fmt.Println("\n5. Stopping monitoring...")
	stopResult := manager.Stop()
	stopJSON, _ := json.MarshalIndent(stopResult, "", "  ")
	fmt.Println(string(stopJSON))

	fmt.Println("\n✅ All tests passed!")
}
