// Command diagx is the reference implementation of the DiagX
// consent-driven diagnostic exchange protocol (V0.1).
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/pkg/protocol"
)

// CLIVersion is independent from the protocol version (spec section 29).
// Release builds override it with -ldflags "-X main.CLIVersion=<version>".
var CLIVersion = "0.1.0-dev"

var rootCmd = &cobra.Command{
	Use:     "diagx",
	Short:   "Consent-driven software diagnostics",
	Version: versionString(),
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

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
