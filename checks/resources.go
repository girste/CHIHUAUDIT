package checks

import (
	"bufio"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func CheckResources() Resources {
	r := Resources{}

	r.CPULoad1, r.CPULoad5, r.CPULoad15 = getCPULoad()
	r.CPUPercent = getCPUPercent()
	r.MemTotal, r.MemUsed, r.MemPercent = getMemory()
	r.SwapTotal, r.SwapUsed, r.SwapPercent = getSwap()
	r.DiskMounts = getDiskUsage()
	r.TopProcesses = getTopProcesses(5)
	r.LargeLogs = getLargeLogs()

	return r
}

func getCPULoad() (load1, load5, load15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		load1, _ = strconv.ParseFloat(fields[0], 64)
		load5, _ = strconv.ParseFloat(fields[1], 64)
		load15, _ = strconv.ParseFloat(fields[2], 64)
	}

	return
}

func getCPUPercent() float64 {
	// Read /proc/stat for CPU usage
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0
	}

	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}

	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 { // idle is 4th field
			idle = val
		}
	}

	if total == 0 {
		return 0
	}

	return float64(total-idle) / float64(total) * 100
}

func getMemory() (total, used uint64, percent float64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	var memFree, buffers, cached uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		value *= 1024 // Convert KB to bytes

		switch key {
		case "MemTotal":
			total = value
		case "MemFree":
			memFree = value
		case "Buffers":
			buffers = value
		case "Cached":
			cached = value
		}
	}

	used = total - memFree - buffers - cached
	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}

	return
}

func getSwap() (total, used uint64, percent float64) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	var swapFree uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		value *= 1024

		switch key {
		case "SwapTotal":
			total = value
		case "SwapFree":
			swapFree = value
		}
	}

	used = total - swapFree
	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}

	return
}

func getDiskUsage() []DiskMount {
	var mounts []DiskMount

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return mounts
	}
	defer func() { _ = file.Close() }()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		mountPoint := fields[1]

		// Skip virtual filesystems
		if strings.HasPrefix(mountPoint, "/proc") ||
			strings.HasPrefix(mountPoint, "/sys") ||
			strings.HasPrefix(mountPoint, "/dev") ||
			strings.HasPrefix(mountPoint, "/run") ||
			seen[mountPoint] {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		used := total - free

		if total == 0 {
			continue
		}

		mounts = append(mounts, DiskMount{
			Path:    mountPoint,
			Total:   total,
			Used:    used,
			Percent: float64(used) / float64(total) * 100,
		})

		seen[mountPoint] = true
	}

	return mounts
}

func getTopProcesses(limit int) []Process {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	var processes []Process

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		// Read process name
		nameData, err := os.ReadFile("/proc/" + pid + "/comm")
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(nameData))

		// Read memory usage
		statusData, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil {
			continue
		}

		var memory uint64
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					mem, _ := strconv.ParseUint(fields[1], 10, 64)
					memory = mem * 1024 // KB to bytes
					break
				}
			}
		}

		if memory > 0 {
			processes = append(processes, Process{
				Name:   name,
				Memory: memory,
			})
		}
	}

	// Sort by memory and take top N
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Memory > processes[j].Memory
	})

	if len(processes) > limit {
		processes = processes[:limit]
	}

	return processes
}

func getLargeLogs() []LogFile {
	var logs []LogFile

	if _, err := os.Stat("/var/log"); err != nil {
		return logs
	}

	out, err := exec.Command("find", "/var/log", "-type", "f", "-size", "+10M").Output()
	if err != nil {
		return logs
	}

	for _, path := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if path == "" {
			continue
		}

		stat, err := os.Stat(path)
		if err != nil {
			continue
		}

		logs = append(logs, LogFile{
			Path: path,
			Size: uint64(stat.Size()),
		})
	}

	return logs
}
