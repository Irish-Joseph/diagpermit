package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const initTemplate = `# DiagX project configuration (V0.1)
# Human authoring format: YAML. Canonical representation: JSON.
# Validate with: diagx validate diagx.yaml

protocolVersion: "0.1"

request:
  id: CASE-LOCAL

requester:
  organization: ""
  name: My Project Support

purpose:
  code: general-troubleshooting
  description: Diagnose a local problem with this project

# expiresAt: 2026-10-10T00:00:00Z

# The requester declares exactly which diagnostic capabilities it needs.
# requirement: required_for_case | optional | forbidden | not_requested
capabilities:

  system.os:
    requirement: required_for_case

  runtime.python.version:
    requirement: optional

  application.logs:
    requirement: optional
    constraints:
      maxLines: 500

  docker.container_state:
    requirement: optional

  environment.values:
    requirement: forbidden

  filesystem.source_code:
    requirement: forbidden

policy:
  networkAccess: false
  arbitraryShellExecution: false
  maximumTotalBytes: 26214400
  maximumDurationSeconds: 60

# retentionNotice:
#   text: Diagnostic information is expected to be retained for up to 30 days.

local:
  applicationLogPath: ./logs/app.log
  outputDir: .
  # privacy:
  #   extraDetectors:
  #     - name: internal-order-id
  #       pattern: "ORD-[0-9]{8}"
  #       action: mask
`

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a diagx.yaml project configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(configDefault()); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite", configDefault())
		}
		if err := os.WriteFile(configDefault(), []byte(initTemplate), 0o600); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Created "+configDefault())
		fmt.Fprintln(cmd.OutOrStdout(), "Edit it to declare the capabilities your support case needs, then run:")
		fmt.Fprintln(cmd.OutOrStdout(), "  diagx validate diagx.yaml")
		fmt.Fprintln(cmd.OutOrStdout(), "  diagx plan")
		fmt.Fprintln(cmd.OutOrStdout(), "  diagx collect")
		return nil
	},
}

func configDefault() string { return "diagx.yaml" }

func init() { rootCmd.AddCommand(initCmd) }
