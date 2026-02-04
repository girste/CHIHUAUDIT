package commands

import (
	"context"
	"fmt"

	"github.com/girste/chihuaudit/internal/system"
)

// RunVerify checks prerequisites and configuration
func RunVerify() {
	fmt.Println("Verifying security audit prerequisites...")

	ctx := context.Background()

	osInfo := system.GetOSInfo(ctx)
	fmt.Printf("  OS detected: %s (%s)\n", osInfo.System, osInfo.Distro)
	fmt.Printf("  Kernel: %s\n", osInfo.Kernel)

	commands := []string{"ufw", "iptables", "ss", "systemctl", "docker"}
	fmt.Println("\nChecking commands:")
	for _, cmd := range commands {
		if system.CommandExists(cmd) {
			fmt.Printf("  [OK] %s\n", cmd)
		} else {
			fmt.Printf("  [--] %s (not found)\n", cmd)
		}
	}

	fmt.Println("\nChecking sudo access:")
	result, _ := system.RunCommandSudo(ctx, system.TimeoutShort, "echo", "test")
	if result != nil && result.Success {
		fmt.Println("  [OK] Sudo access configured")
	} else {
		fmt.Println("  [!!] Sudo access not configured")
		fmt.Println("\nRun setup-sudo.sh to configure passwordless sudo for security checks")
	}

	fmt.Println("\nVerification complete!")
}
