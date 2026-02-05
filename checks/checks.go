package checks

import (
	"sync"
	"time"
)

// AuditResults contains all check results
type AuditResults struct {
	Timestamp time.Time
	Hostname  string
	OS        string
	Kernel    string
	Uptime    string

	Security  Security
	Services  Services
	Resources Resources
	Storage   Storage
	Database  Database
	Docker    Docker
	System    System
	Logs      Logs
	Network   Network
	Backups   Backups

	TotalChecks int
	Skipped     []string
	Notes       []string
}

// RunAll executes all checks in parallel
func RunAll() *AuditResults {
	results := &AuditResults{
		Timestamp: time.Now(),
	}

	var wg sync.WaitGroup

	// System info (must run first)
	results.Hostname, results.OS, results.Kernel, results.Uptime = GetSystemInfo()

	// Run all checks in parallel
	wg.Add(10)

	go func() {
		defer wg.Done()
		results.Security = CheckSecurity()
	}()

	go func() {
		defer wg.Done()
		results.Services = CheckServices()
	}()

	go func() {
		defer wg.Done()
		results.Resources = CheckResources()
	}()

	go func() {
		defer wg.Done()
		results.Storage = CheckStorage()
	}()

	go func() {
		defer wg.Done()
		results.Database = CheckDatabase()
	}()

	go func() {
		defer wg.Done()
		results.Docker = CheckDocker()
	}()

	go func() {
		defer wg.Done()
		results.System = CheckSystem()
	}()

	go func() {
		defer wg.Done()
		results.Logs = CheckLogs()
	}()

	go func() {
		defer wg.Done()
		results.Network = CheckNetwork()
	}()

	go func() {
		defer wg.Done()
		results.Backups = CheckBackups()
	}()

	wg.Wait()

	// Calculate totals
	results.calculateTotals()

	return results
}

func (r *AuditResults) calculateTotals() {
	r.TotalChecks = 87 // Total possible checks
	
	// Track skipped checks based on permission issues
	if r.Security.SSHPasswordAuth == "skipped" || r.Security.SSHRootLogin == "skipped" {
		if !r.Security.SSHConfigReadable {
			r.Skipped = append(r.Skipped, "SSH config (requires sudo)")
		}
	}
	
	// Add recommendation note if running without sudo
	if len(r.Skipped) > 0 {
		r.Notes = append(r.Notes, "⚠️  Run with sudo for complete security audit")
	}
}
