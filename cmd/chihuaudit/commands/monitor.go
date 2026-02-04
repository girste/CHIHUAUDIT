package commands

import (
	"fmt"
	"os"
	"strconv"

	"github.com/girste/chihuaudit/internal/monitoring"
	"github.com/girste/chihuaudit/internal/util"
)

// RunMonitor handles the monitor command (foreground mode)
func RunMonitor() {
	interval := 3600
	logDir := util.GetLogDir()
	verbose := true
	once := false

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "--interval", "-i":
			if i+1 < len(os.Args) {
				if v, err := strconv.Atoi(os.Args[i+1]); err == nil {
					interval = v
				}
				i++
			}
		case "--log-dir", "-d":
			if i+1 < len(os.Args) {
				logDir = os.Args[i+1]
				i++
			}
		case "--quiet", "-q":
			verbose = false
		case "--once":
			once = true
		}
	}

	if interval < 10 {
		fmt.Fprintf(os.Stderr, "Error: Minimum interval is 10 seconds\n")
		os.Exit(1)
	}
	if interval > 86400 {
		fmt.Fprintf(os.Stderr, "Error: Maximum interval is 86400 seconds (24 hours)\n")
		os.Exit(1)
	}

	monitor := monitoring.NewSecurityMonitor(interval, logDir, verbose)

	if once {
		result, err := monitor.RunOnce()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Monitor check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nCheck result: %s\n", result.Status)
		if result.AnomalyFile != "" {
			fmt.Printf("Anomaly file: %s\n", result.AnomalyFile)
		}
	} else {
		monitor.Run()
	}
}
