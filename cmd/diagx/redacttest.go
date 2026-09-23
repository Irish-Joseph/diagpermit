package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/internal/pipeline"
	"github.com/diagx/diagx/internal/transform"
)

var redactTestCmd = &cobra.Command{
	Use:   "redact-test [file]",
	Short: "Show privacy transformation behaviour on a file (or stdin)",
	Long: `Runs the configured transformation ruleset over a file and shows the
result. This lets developers see redaction behaviour safely without
producing an artifact.

The engine is fail-closed: if a mandatory transformation fails, the
command reports the failure and exits non-zero.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var src string
		if len(args) == 1 {
			src = args[0]
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			data = b
		} else {
			src = "<stdin>"
			b, err := readAll(os.Stdin)
			if err != nil {
				return err
			}
			data = b
		}

		// Build the ruleset: defaults plus extra detectors from the
		// request file, when present and valid.
		ruleset := transform.DefaultRuleset()
		if req, err := loadRequest(cmd); err == nil && req.Local != nil && req.Local.Privacy != nil {
			for _, e := range req.Local.Privacy.ExtraDetectors {
				ruleset.Rules = append(ruleset.Rules, transform.Rule{
					Detector:    "custom:" + e.Name,
					Pattern:     e.Pattern,
					Action:      transform.Action(e.Action),
					ReplaceWith: e.ReplaceWith,
					TruncateTo:  e.TruncateTo,
					Required:    true,
				})
			}
		}

		salt := make([]byte, 32)
		_, err := readRandom(salt)
		if err != nil {
			return err
		}
		engine, err := transform.NewEngine(ruleset, salt)
		if err != nil {
			// Fail closed: configuration problems block the run.
			fmt.Fprintln(cmd.ErrOrStderr(), "error:", err)
			return err
		}

		out, report, err := engine.Apply(data)
		if err != nil {
			pipeline.PrintFailClosed(cmd.ErrOrStderr(), err)
			return fmt.Errorf("fail-closed: transformation failed")
		}

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Source: %s (%d bytes)\nRuleset: %s\n\n--- transformed output ---\n%s\n--- report (no original values) ---\n",
			src, len(data), ruleset.ID, string(out))
		for _, d := range report {
			if d.Matches == 0 {
				continue
			}
			fmt.Fprintf(w, "  %-30s %-14s %d\n", d.Category, d.Transformer, d.Matches)
		}
		fmt.Fprintf(w, "Total transformations: %d\n", engine.TotalTransformations())
		return nil
	},
}

func init() {
	addCommonFlags(redactTestCmd)
	rootCmd.AddCommand(redactTestCmd)
}
