package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/girste/chihuaudit/internal/config"
	"gopkg.in/yaml.v3"
)

// RunWhitelist handles the whitelist command
func RunWhitelist() {
	if len(os.Args) < 3 {
		PrintWhitelistHelp()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "add":
		RunWhitelistAdd()
	case "remove":
		RunWhitelistRemove()
	case "list":
		RunWhitelistList()
	case "help", "--help", "-h":
		PrintWhitelistHelp()
	default:
		fmt.Printf("Unknown whitelist subcommand: %s\n", subcommand)
		PrintWhitelistHelp()
		os.Exit(1)
	}
}

// RunWhitelistAdd adds an alert code to the whitelist
func RunWhitelistAdd() {
	if len(os.Args) < 4 {
		fmt.Println("Error: Alert code required")
		fmt.Println("Usage: chihuaudit whitelist add <ALERT_CODE>")
		os.Exit(1)
	}

	alertCode := os.Args[3]
	whitelistPath := getWhitelistPath()
	wl := loadOrCreateWhitelist(whitelistPath)

	if wl.IsAlertWhitelisted(alertCode) {
		fmt.Printf("Alert code %s is already whitelisted\n", alertCode)
		return
	}

	wl.AddAlertCode(alertCode)

	if err := config.SaveWhitelist(wl, whitelistPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save whitelist: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Alert code %s added to whitelist\n", alertCode)
	fmt.Printf("  File: %s\n", whitelistPath)
}

// RunWhitelistRemove removes an alert code from the whitelist
func RunWhitelistRemove() {
	if len(os.Args) < 4 {
		fmt.Println("Error: Alert code required")
		fmt.Println("Usage: chihuaudit whitelist remove <ALERT_CODE>")
		os.Exit(1)
	}

	alertCode := os.Args[3]
	whitelistPath := getWhitelistPath()
	wl := loadOrCreateWhitelist(whitelistPath)

	if wl.RemoveAlertCode(alertCode) {
		if err := config.SaveWhitelist(wl, whitelistPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save whitelist: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Alert code %s removed from whitelist\n", alertCode)
	} else {
		fmt.Printf("Alert code %s not found in whitelist\n", alertCode)
		os.Exit(1)
	}
}

// RunWhitelistList lists all whitelisted alert codes
func RunWhitelistList() {
	whitelistPath := getWhitelistPath()
	wl := loadOrCreateWhitelist(whitelistPath)

	codes := wl.GetWhitelistedAlertCodes()

	if len(codes) == 0 {
		fmt.Println("No alert codes whitelisted")
		fmt.Printf("  File: %s\n", whitelistPath)
		return
	}

	fmt.Printf("Whitelisted Alert Codes (%d):\n", len(codes))
	fmt.Println("──────────────────────────────")
	for _, code := range codes {
		fmt.Printf("  %s\n", code)
	}
	fmt.Printf("\nWhitelist file: %s\n", whitelistPath)
}

func getWhitelistPath() string {
	if _, err := os.Stat(".chihuaudit-whitelist.yaml"); err == nil {
		return ".chihuaudit-whitelist.yaml"
	}

	homeDir, err := os.UserHomeDir()
	if err == nil {
		homePath := filepath.Join(homeDir, ".chihuaudit-whitelist.yaml")
		if _, err := os.Stat(homePath); err == nil {
			return homePath
		}
	}

	return ".chihuaudit-whitelist.yaml"
}

func loadOrCreateWhitelist(path string) *config.Whitelist {
	data, err := os.ReadFile(path)
	if err != nil {
		return &config.Whitelist{
			Version:    "1.0",
			AlertCodes: []string{},
		}
	}

	var wl config.Whitelist
	if err := yaml.Unmarshal(data, &wl); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse whitelist: %v\n", err)
		os.Exit(1)
	}

	return &wl
}

// PrintWhitelistHelp displays help for whitelist command
func PrintWhitelistHelp() {
	help := `chihuaudit whitelist - Manage alert code whitelist

USAGE:
    chihuaudit whitelist <SUBCOMMAND>

SUBCOMMANDS:
    add <CODE>      Add alert code to whitelist
    remove <CODE>   Remove alert code from whitelist
    list            List all whitelisted alert codes

EXAMPLES:
    # Whitelist a known-good drift
    chihuaudit whitelist add FW-001

    # Remove from whitelist
    chihuaudit whitelist remove FW-001

    # List all whitelisted codes
    chihuaudit whitelist list

ALERT CODES:
    FW-XXX     Firewall configuration changes
    SSH-XXX    SSH daemon configuration changes
    SVC-XXX    Services and listening ports changes
    USR-XXX    User accounts and permissions changes
    DOC-XXX    Docker configuration changes
    F2B-XXX    Fail2ban configuration changes
    UPD-XXX    System updates changes
    KRN-XXX    Kernel parameters changes
    DSK-XXX    Disk configuration changes
    MAC-XXX    MAC (AppArmor/SELinux) changes
    SSL-XXX    SSL/TLS certificate changes
    THR-XXX    Threat detection changes
    CVE-XXX    CVE/vulnerability changes

WHITELIST FILE:
    Location: .chihuaudit-whitelist.yaml (current dir or ~/.chihuaudit-whitelist.yaml)
    Format: YAML

    Example content:
    version: "1.0"
    alertCodes:
      - "SVC-012"  # Dev server on port 8080
      - "FW-003"   # Expected firewall rule change

WORKFLOW:
    1. Run baseline diff and review alerts
    2. For legitimate changes, add alert code to whitelist
    3. Future occurrences of whitelisted codes will be suppressed
    4. Update baseline when configuration intentionally changes
`
	fmt.Print(help)
}
