package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Irish-Joseph/diagpermit/internal/config"
)

var validateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a diagnostic request / project configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := config.DefaultFile
		if len(args) == 1 {
			path = args[0]
		}
		req, err := config.Load(path)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s is a valid DiagPermit %s request\n", path, req.ProtocolVersion)
		fmt.Fprintf(w, "  request:     %s\n", req.Request.ID)
		fmt.Fprintf(w, "  requester:   %s\n", req.Requester.Name)
		fmt.Fprintf(w, "  purpose:     %s\n", req.Purpose.Description)
		count := 0
		for range req.Capabilities {
			count++
		}
		fmt.Fprintf(w, "  capabilities: %d declared\n", count)
		fmt.Fprintf(w, "  network:     %v   shell: %v\n", req.Policy.NetworkAccess, req.Policy.ArbitraryShellExecution)
		return nil
	},
}

func init() { rootCmd.AddCommand(validateCmd) }
