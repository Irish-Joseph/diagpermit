package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/internal/pipeline"
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect diagnostics under explicit consent and produce a local artifact",
	Long: `Runs: request → consent → plan → collection → transformation → package.

The result is a local .diagnostic file. Nothing is uploaded.
Sharing the artifact is always a separate, deliberate action.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		req, err := loadRequest(cmd)
		if err != nil {
			return err
		}
		mode, prompter, consentData, err := consentMode(cmd, req)
		if err != nil {
			return err
		}
		out, err := pipeline.Run(cmd.Context(), req, mode, prompter, consentData, flagOutput, cmd.OutOrStdout())
		if err != nil {
			// Fail-closed transformation failures get the mandated message.
			_ = pipeline.PrintFailClosed(cmd.OutOrStdout(), err)
			return err
		}
		printCollectSummary(cmd, out)
		return nil
	},
}

func printCollectSummary(cmd *cobra.Command, out *pipeline.Output) {
	w := cmd.OutOrStdout()
	fmt.Fprint(w, "\nCollection complete\n")

	fmt.Fprintln(w, "Collectors")
	fmt.Fprintln(w, "──────────────")
	fmt.Fprintf(w, "%d successful\n", out.Success)
	fmt.Fprintf(w, "%d partial\n", out.Partial)
	fmt.Fprintf(w, "%d declined\n", out.Declined)
	if out.Forbidden > 0 {
		fmt.Fprintf(w, "%d forbidden by request\n", out.Forbidden)
	}
	if out.Failed > 0 {
		fmt.Fprintf(w, "%d failed (see reports in artifact)\n", out.Failed)
	}

	fmt.Fprintln(w, "\nTransformations")
	fmt.Fprintln(w, "──────────────")
	fmt.Fprintf(w, "%d values transformed by %d detectors (%s)\n",
		out.Transform.TransformationsApplied, out.Transform.DetectorsExecuted, out.Transform.Ruleset)

	if len(out.Findings) > 0 {
		fmt.Fprintln(w, "\nFindings")
		fmt.Fprintln(w, "──────────────")
		for _, f := range out.Findings {
			fmt.Fprintf(w, "[%s] %s: %s\n", f.Severity, f.ID, f.Summary)
		}
	}

	fmt.Fprintln(w, "\nPackage")
	fmt.Fprintln(w, "──────────────")
	fmt.Fprintf(w, "%s\n", out.ArtifactPath)
	fmt.Fprintln(w, "Integrity manifest: created")
	fmt.Fprintln(w, "Disclosure receipt: created")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Nothing has been uploaded.")
	fmt.Fprintf(w, "Next: diagx inspect %s\n", out.ArtifactPath)
}

func init() {
	addCommonFlags(collectCmd)
	collectCmd.Flags().BoolVarP(&flagYes, "yes", "y", false, "approve all required and optional capabilities (non-interactive)")
	collectCmd.Flags().StringVarP(&flagConsent, "consent", "c", "", "path to a consent decisions JSON file ({\"approved\":[...],\"denied\":[...]})")
	collectCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output artifact path (default: support-<request-id>.diagnostic)")
	rootCmd.AddCommand(collectCmd)
}
