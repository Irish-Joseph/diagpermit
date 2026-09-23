// Command diagx is the reference implementation of the DiagX
// consent-driven diagnostic exchange protocol (V0.1).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/pkg/protocol"
)

// CLI version. Independent from the protocol version (spec section 29).
const CLIVersion = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "diagx",
	Short: "Consent-driven software diagnostics",
	Long: `DiagX is an open protocol and CLI for consent-driven software diagnostics.

A requester declares what troubleshooting information it needs.
The user reviews and approves those capabilities.
Collection and privacy transformations happen locally.
The resulting diagnostic artifact contains a disclosure receipt
describing what was requested, approved, collected and transformed.

Nothing is ever uploaded by diagx. Sharing is always a separate,
deliberate action outside this tool.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func versionString() string {
	return fmt.Sprintf("diagx CLI %s (protocol %s)", CLIVersion, protocol.ProtocolVersion)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
