package report

import (
	"encoding/json"
	"fmt"
	"os"

	"chihuaudit/checks"
)

func PrintJSON(results *checks.AuditResults) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
	}
}
