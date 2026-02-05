package checks

import (
	"os/exec"
	"strconv"
	"strings"

	"chihuaudit/detect"
)

func CheckDatabase() Database {
	d := Database{}

	if detect.CommandExists("psql") {
		d.PostgreSQL = checkPostgreSQL()
	}

	if detect.CommandExists("mysql") {
		d.MySQL = checkMySQL()
	}

	if detect.CommandExists("redis-cli") {
		d.Redis = checkRedis()
	}

	return d
}

func checkPostgreSQL() PostgreSQLInfo {
	info := PostgreSQLInfo{Available: true}

	// Try to connect and get stats - exclude template databases
	out, err := exec.Command("sudo", "-u", "postgres", "psql", "-t", "-c", "SELECT count(*) FROM pg_database WHERE datistemplate = false;").Output()
	if err != nil {
		// Try without sudo
		out, err = exec.Command("psql", "-U", "postgres", "-t", "-c", "SELECT count(*) FROM pg_database WHERE datistemplate = false;").Output()
		if err != nil {
			return info
		}
	}

	count, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	info.Databases = count

	// Get total size - exclude template databases
	out, err = exec.Command("sudo", "-u", "postgres", "psql", "-t", "-c", "SELECT pg_size_pretty(sum(pg_database_size(datname))) FROM pg_database WHERE datistemplate = false;").Output()
	if err == nil {
		info.TotalSize = strings.TrimSpace(string(out))
	}

	// Get connections
	out, err = exec.Command("sudo", "-u", "postgres", "psql", "-t", "-c", "SELECT count(*) FROM pg_stat_activity;").Output()
	if err == nil {
		conn, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		info.Connections = conn
	}

	// Get connection limit
	out, err = exec.Command("sudo", "-u", "postgres", "psql", "-t", "-c", "SHOW max_connections;").Output()
	if err == nil {
		limit, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		info.ConnLimit = limit
	}

	return info
}

func checkMySQL() MySQLInfo {
	info := MySQLInfo{Available: true}

	// Try to get database count
	out, err := exec.Command("mysql", "-e", "SELECT COUNT(*) FROM information_schema.schemata;").Output()
	if err != nil {
		return info
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 1 {
		count, _ := strconv.Atoi(strings.TrimSpace(lines[1]))
		info.Databases = count
	}

	// Get connections
	out, err = exec.Command("mysql", "-e", "SHOW PROCESSLIST;").Output()
	if err == nil {
		info.Connections = len(strings.Split(strings.TrimSpace(string(out)), "\n")) - 1
	}

	return info
}

func checkRedis() RedisInfo {
	info := RedisInfo{Available: true}

	// Get memory usage
	out, err := exec.Command("redis-cli", "INFO", "memory").Output()
	if err != nil {
		return info
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "used_memory_human:") {
			info.Memory = strings.TrimSpace(strings.TrimPrefix(line, "used_memory_human:"))
		}
	}

	// Get connected clients
	out, err = exec.Command("redis-cli", "INFO", "clients").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "connected_clients:") {
				clients, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "connected_clients:")))
				info.Clients = clients
			}
		}
	}

	return info
}
