package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/internal/verification"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <artifact.diagnostic>",
	Short: "Check integrity and schemas of a diagnostic artifact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		rep, err := verification.Verify(path)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		section(w, "Integrity verification")
		fmt.Fprintf(w, "Artifact: %s\n\n", path)
		for _, c := range rep.Checks {
			mark := "ok  "
			if !c.OK {
				mark = "FAIL"
			}
			fmt.Fprintf(w, "  [%s] %-22s %s\n", mark, c.Name, c.Detail)
		}
		fmt.Fprintf(w, "\n%s\n\n", rep.Verdict())
		fmt.Fprintln(w, verification.PrivacyDisclaimer)
		if rep.Verdict() != "INTEGRITY VERIFIED" {
			return fmt.Errorf("integrity verification failed")
		}
		return nil
	},
}

func init() { rootCmd.AddCommand(verifyCmd) }
