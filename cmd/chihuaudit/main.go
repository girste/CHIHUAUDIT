package main

import (
	"fmt"
	"os"

	"github.com/girste/chihuaudit/cmd/chihuaudit/commands"
	"github.com/girste/chihuaudit/internal/util"
)

func main() {
	if len(os.Args) > 1 {
		command := os.Args[1]

		switch command {
		case "version", "--version", "-v":
			fmt.Printf("chihuaudit version %s\n", util.Version)
			os.Exit(0)

		case "audit":
			exitCode := commands.RunAudit()
			os.Exit(exitCode)

		case "monitor":
			commands.RunMonitor()
			os.Exit(0)

		case "baseline":
			commands.RunBaseline()
			os.Exit(0)

		case "whitelist":
			commands.RunWhitelist()
			os.Exit(0)

		case "serve":
			commands.RunServe()
			os.Exit(0)

		case "verify":
			commands.RunVerify()
			os.Exit(0)

		case "help", "--help", "-h":
			commands.PrintHelp()
			os.Exit(0)

		default:
			fmt.Printf("Unknown command: %s\n", command)
			commands.PrintHelp()
			os.Exit(1)
		}
	}

	// Default: run as MCP server
	commands.RunServe()
}
