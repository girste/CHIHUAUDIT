package checks

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"chihuaudit/detect"
)

func CheckNetwork() Network {
	n := Network{}

	n.DNSResolution, n.DNSLatency = testDNS()
	n.PingLatency, n.PacketLoss = testPing()
	n.Interfaces = getNetworkInterfaces()
	n.TopIPs = getTopConnectedIPs(5)

	return n
}

func testDNS() (status, latency string) {
	start := time.Now()
	out, err := exec.Command("nslookup", "google.com", "8.8.8.8").Output()
	duration := time.Since(start)

	if err != nil {
		return "failed", "N/A"
	}

	if strings.Contains(string(out), "Address") {
		return "OK", duration.Round(time.Millisecond).String()
	}

	return "failed", "N/A"
}

func testPing() (latency string, loss float64) {
	if !detect.CommandExists("ping") {
		return "N/A", 0
	}

	out, err := exec.Command("ping", "-c", "4", "-W", "2", "8.8.8.8").Output()
	if err != nil {
		return "failed", 100.0
	}

	output := string(out)

	// Parse packet loss
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "packet loss") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if strings.HasSuffix(field, "%") && i > 0 {
					lossStr := strings.TrimSuffix(field, "%")
					loss, _ = strconv.ParseFloat(lossStr, 64)
				}
			}
		}

		// Parse average latency
		if strings.Contains(line, "avg") || strings.Contains(line, "rtt") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "=" && i+1 < len(fields) {
					times := strings.Split(fields[i+1], "/")
					if len(times) >= 2 {
						latency = times[1] + "ms"
						return
					}
				}
			}
		}
	}

	return
}

func getNetworkInterfaces() []NetInterface {
	var interfaces []NetInterface

	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return interfaces
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 { // Skip header
			continue
		}

		line := scanner.Text()
		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])

		// Skip loopback and virtual interfaces for main list
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") {
			continue
		}

		// Get IP address
		ip := getInterfaceIP(name)
		status := "up"

		if ip == "" {
			status = "down"
			ip = "N/A"
		}

		interfaces = append(interfaces, NetInterface{
			Name:   name,
			IP:     ip,
			Status: status,
		})
	}

	return interfaces
}

func getInterfaceIP(name string) string {
	if !detect.CommandExists("ip") {
		return ""
	}

	out, err := exec.Command("ip", "-4", "addr", "show", name).Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Remove CIDR notation
				ip := strings.Split(fields[1], "/")[0]
				return ip
			}
		}
	}

	return ""
}

func getTopConnectedIPs(limit int) []IPConnection {
	var ips []IPConnection

	var out []byte
	var err error

	if detect.CommandExists("ss") {
		out, err = exec.Command("ss", "-tun").Output()
	} else if detect.CommandExists("netstat") {
		out, err = exec.Command("netstat", "-tun").Output()
	}

	if err != nil {
		return ips
	}

	ipCount := make(map[string]int)

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "ESTAB") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// Foreign address is typically 5th field
		addr := fields[5]
		if idx := strings.LastIndex(addr, ":"); idx != -1 {
			ip := addr[:idx]

			// Skip local IPs
			if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
				continue
			}

			ipCount[ip]++
		}
	}

	// Convert to slice and sort
	for ip, count := range ipCount {
		ips = append(ips, IPConnection{IP: ip, Count: count})
	}

	// Simple sort by count
	for i := 0; i < len(ips)-1; i++ {
		for j := i + 1; j < len(ips); j++ {
			if ips[j].Count > ips[i].Count {
				ips[i], ips[j] = ips[j], ips[i]
			}
		}
	}

	if len(ips) > limit {
		ips = ips[:limit]
	}

	return ips
}
