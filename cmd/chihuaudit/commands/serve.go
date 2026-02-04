package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/girste/chihuaudit/internal/mcp"
)

// RunServe starts MCP server (merges serve and server functionality)
func RunServe() {
	noSudo := false
	inputFile := ""

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "--no-sudo":
			noSudo = true
		case strings.HasPrefix(arg, "--input="):
			inputFile = strings.TrimPrefix(arg, "--input=")
			noSudo = true
		case arg == "--input":
			if i+1 < len(os.Args) {
				inputFile = os.Args[i+1]
				noSudo = true
				i++
			}
		case arg == "--help" || arg == "-h":
			PrintServeHelp()
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	var server *mcp.Server
	var err error

	if noSudo {
		var reportData []byte

		if inputFile != "" && inputFile != "-" {
			reportData, err = os.ReadFile(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read input file: %v\n", err)
				os.Exit(1)
			}
		} else {
			reportData, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read from stdin: %v\n", err)
				os.Exit(1)
			}
		}

		var rawReport map[string]interface{}
		if err := json.Unmarshal(reportData, &rawReport); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse JSON: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Starting MCP server with pre-loaded audit data (no sudo required)...\n")

		server, err = mcp.NewServerWithData(rawReport)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
			os.Exit(1)
		}
	} else {
		server, err = mcp.NewServer()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create MCP server: %v\n", err)
			os.Exit(1)
		}
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve()
	}()

	select {
	case sig := <-sigChan:
		fmt.Fprintf(os.Stderr, "\nReceived %s signal, shutting down gracefully...\n", sig)
		_ = ctx
		cancel()
		os.Exit(0)

	case err := <-errChan:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			_ = ctx
			cancel()
			os.Exit(1)
		}
		cancel()
	}
}

// PrintServeHelp displays help for serve command
func PrintServeHelp() {
	help := `chihuaudit serve - Start MCP server

USAGE:
    chihuaudit serve [OPTIONS]

DESCRIPTION:
    Starts MCP server. Can run with sudo (live audits) or without sudo
    (pre-loaded data for privilege separation).

OPTIONS:
    --input=FILE     Read audit data from file (use '-' for stdin)
                     Enables no-sudo mode automatically
    --no-sudo        Run without sudo (requires pre-loaded data)

EXAMPLES:
    # Default mode (requires sudo for live audits)
    sudo chihuaudit serve

    # Privilege separation mode (from file, no sudo)
    sudo chihuaudit audit --format=json --output /tmp/audit.json
    chihuaudit serve --input /tmp/audit.json

    # Pipe mode (real-time privilege separation)
    sudo chihuaudit audit --format=json | chihuaudit serve

PRIVILEGE SEPARATION:
    This command provides security through OS-level process separation:

    Process 1 (with sudo):     sudo chihuaudit audit
                               - Collects system data
                               - Analyzes security posture
                               - Writes JSON output
                               - Exits (sudo ends)

    Process 2 (no sudo):       chihuaudit serve
                               - Reads JSON data
                               - Serves MCP protocol
                               - No system access
                               - Never had sudo

    If MCP server is compromised, attacker has NO sudo access.
`
	fmt.Print(help)
}
