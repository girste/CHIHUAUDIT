package checks

import (
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckStorage() Storage {
	s := Storage{}

	s.DiskHealth, s.DisksChecked = checkDiskHealth()
	s.InodeUsage = getInodeUsage()
	s.IOWait = getIOWait()
	s.FilesystemErrors = getFilesystemErrors()

	return s
}

func checkDiskHealth() (health string, checked int) {
	if !detect.CommandExists("smartctl") {
		return "smartctl not available", 0
	}

	// List block devices
	out, err := exec.Command("lsblk", "-ndo", "NAME", "-e", "7,11").Output()
	if err != nil {
		return "unable to list disks", 0
	}

	disks := strings.Split(strings.TrimSpace(string(out)), "\n")
	passed := 0

	for _, disk := range disks {
		if disk == "" {
			continue
		}

		out, err := exec.Command("smartctl", "-H", "/dev/"+disk).Output()
		if err != nil {
			continue
		}

		checked++
		if strings.Contains(string(out), "PASSED") {
			passed++
		}
	}

	if checked == 0 {
		return "no disks checked", 0
	}

	if passed == checked {
		return "all PASSED", checked
	}

	return "some FAILED", checked
}

func getInodeUsage() []InodeInfo {
	var inodes []InodeInfo

	out, err := exec.Command("df", "-i").Output()
	if err != nil {
		return inodes
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		mount := fields[5]
		percentStr := strings.TrimSuffix(fields[4], "%")
		percent, err := strconv.ParseFloat(percentStr, 64)
		if err != nil {
			continue
		}

		inodes = append(inodes, InodeInfo{
			Mount:   mount,
			Percent: percent,
		})
	}

	return inodes
}

func getIOWait() float64 {
	if !detect.CommandExists("iostat") {
		return 0
	}

	out, err := exec.Command("iostat", "-c", "1", "2").Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		fields := strings.Fields(lines[i])
		if len(fields) >= 4 {
			// iowait is typically 4th field
			if wait, err := strconv.ParseFloat(fields[3], 64); err == nil {
				return wait
			}
		}
	}

	return 0
}

func getFilesystemErrors() int {
	if !detect.FileExists("/var/log/kern.log") && !detect.FileExists("/var/log/messages") {
		return 0
	}

	logPath := detect.TryPaths("/var/log/kern.log", "/var/log/messages")
	if logPath == "" {
		return 0
	}

	out, err := exec.Command("grep", "-c", "-i", "filesystem error", logPath).Output()
	if err != nil {
		return 0
	}

	count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return count
}
