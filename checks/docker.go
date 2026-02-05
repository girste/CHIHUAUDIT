package checks

import (
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckDocker() Docker {
	d := Docker{}

	if !detect.CommandExists("docker") {
		return d
	}

	d.Available = true
	d.Running, d.Stopped = getContainerCounts()
	d.Images, d.ImagesSize = getImageStats()
	d.Volumes, d.VolumesSize = getVolumeStats()
	d.TopContainers = getTopContainers(3)

	return d
}

func getContainerCounts() (running, stopped int) {
	// Get running containers
	out, err := exec.Command("docker", "ps", "-q").Output()
	if err == nil {
		result := strings.TrimSpace(string(out))
		if result != "" {
			running = len(strings.Split(result, "\n"))
		}
	}

	// Get all containers
	out, err = exec.Command("docker", "ps", "-a", "-q").Output()
	if err == nil {
		result := strings.TrimSpace(string(out))
		if result != "" {
			total := len(strings.Split(result, "\n"))
			stopped = total - running
		}
	}

	return
}

func getImageStats() (count int, size string) {
	out, err := exec.Command("docker", "images", "-q").Output()
	if err != nil {
		return
	}

	result := strings.TrimSpace(string(out))
	if result != "" {
		count = len(strings.Split(result, "\n"))
	}

	// Get total size
	out, err = exec.Command("docker", "system", "df", "--format", "{{.Size}}").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 0 {
			size = lines[0]
		}
	}

	return
}

func getVolumeStats() (count int, size string) {
	out, err := exec.Command("docker", "volume", "ls", "-q").Output()
	if err != nil {
		return
	}

	result := strings.TrimSpace(string(out))
	if result != "" {
		count = len(strings.Split(result, "\n"))
	}

	size = "unknown"
	return
}

func getTopContainers(limit int) []Container {
	var containers []Container

	out, err := exec.Command("docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}").Output()
	if err != nil {
		return containers
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i >= limit {
			break
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}

		cpuStr := strings.TrimSuffix(fields[1], "%")
		cpu, _ := strconv.ParseFloat(cpuStr, 64)

		// Memory is in format "1.5GiB / 8GiB"
		memParts := strings.Split(fields[2], "/")
		memory := strings.TrimSpace(memParts[0])

		containers = append(containers, Container{
			Name:       fields[0],
			CPUPercent: cpu,
			Memory:     memory,
		})
	}

	return containers
}
