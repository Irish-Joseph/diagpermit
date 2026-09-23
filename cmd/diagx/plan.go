package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/internal/config"
	"github.com/diagx/diagx/internal/consent"
	"github.com/diagx/diagx/pkg/protocol"
)

var (
	flagRequest string
	flagYes     bool
	flagConsent string
	flagOutput  string
)

func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagRequest, "request", "r", config.DefaultFile, "path to the diagnostic request file (diagx.yaml)")
}

func loadRequest(cmd *cobra.Command) (*protocol.DiagnosticRequest, error) {
	req, err := config.Load(flagRequest)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// consentMode resolves how consent will be obtained.
func consentMode(cmd *cobra.Command, req *protocol.DiagnosticRequest) (string, *consent.Prompter, []byte, error) {
	if req.ExpiresAt != "" {
		if err := checkExpiry(req.ExpiresAt); err != nil {
			return "", nil, nil, err
		}
	}
	if flagConsent != "" {
		// #nosec G304 -- flagConsent is explicitly selected by the local CLI user.
		data, err := os.ReadFile(flagConsent)
		if err != nil {
			return "", nil, nil, fmt.Errorf("consent file: %w", err)
		}
		return consent.ModeFile, nil, data, nil
	}
	if flagYes {
		return consent.ModeAssumed, nil, nil, nil
	}
	if !stdinIsTerminal() {
		return "", nil, nil, fmt.Errorf("non-interactive environment: use --yes or --consent <file>")
	}
	return consent.ModeInteractive, consent.NewPrompter(os.Stdin, os.Stdout), nil, nil
}

func checkExpiry(expiresAt string) error {
	t, err := parseTime(time.RFC3339, expiresAt)
	if err != nil {
		return err
	}
	if t.Before(now()) {
		return fmt.Errorf("diagnostic request has expired (expiresAt %s)", expiresAt)
	}
	return nil
}

// planCmd shows exactly what would happen without collecting data.
var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show exactly what would be collected, without collecting anything",
	RunE: func(cmd *cobra.Command, args []string) error {
		req, err := loadRequest(cmd)
		if err != nil {
			return err
		}
		printPlan(cmd.OutOrStdout(), req)
		fmt.Fprintln(cmd.OutOrStdout(), "\nPlan only. No data was collected and no artifact was created.")
		return nil
	},
}

func printPlan(w io.Writer, req *protocol.DiagnosticRequest) {
	section(w, "Diagnostic request")
	fmt.Fprintf(w, "Request ID:  %s\n", req.Request.ID)
	fmt.Fprintf(w, "Requester:   %s", req.Requester.Name)
	if req.Requester.Organization != "" {
		fmt.Fprintf(w, " (%s)", req.Requester.Organization)
	}
	fmt.Fprintf(w, "\nAuthenticity: NOT VERIFIED (unsigned request)\n")
	fmt.Fprintf(w, "Purpose:     %s\n\n", req.Purpose.Description)

	rev := consent.ReviewFor(req)
	if len(rev.Required) > 0 {
		fmt.Fprintln(w, "REQUIRED FOR CASE (you may still decline):")
		for _, id := range rev.Required {
			fmt.Fprintf(w, "  \u2713 %s\n", consent.Describe(id, req))
		}
		fmt.Fprintln(w)
	}
	if len(rev.Optional) > 0 {
		fmt.Fprintln(w, "OPTIONAL (you choose):")
		for _, id := range rev.Optional {
			fmt.Fprintf(w, "  [ ] %s\n", consent.Describe(id, req))
		}
		fmt.Fprintln(w)
	}
	if len(rev.Forbidden) > 0 {
		fmt.Fprintln(w, "PROHIBITED BY REQUEST (never collected):")
		for _, id := range rev.Forbidden {
			fmt.Fprintf(w, "  \u2717 %s\n", id)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Collection network access: %s\n", onOff(req.Policy.NetworkAccess, "DISABLED", "ENABLED"))
	fmt.Fprintf(w, "Arbitrary shell execution: %s\n", onOff(req.Policy.ArbitraryShellExecution, "DISABLED", "ENABLED"))
	fmt.Fprintf(w, "Maximum package: %s\n", humanBytes(int64(req.Policy.MaximumTotalBytes)))
	if req.Policy.MaximumDurationSeconds > 0 {
		fmt.Fprintf(w, "Maximum duration: %ds\n", req.Policy.MaximumDurationSeconds)
	}
	if req.RetentionNotice != nil {
		fmt.Fprintf(w, "Retention notice: %s\n", req.RetentionNotice.Text)
	}
}

func onOff(b bool, off, on string) string {
	if b {
		return on
	}
	return off
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "default (25 MB)"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func init() {
	addCommonFlags(planCmd)
	rootCmd.AddCommand(planCmd)
}
