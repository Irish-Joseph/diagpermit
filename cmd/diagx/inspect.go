package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/diagx/diagx/internal/safezip"
	"github.com/diagx/diagx/pkg/protocol"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <artifact.diagnostic>",
	Short: "Show a terminal-friendly summary of a diagnostic artifact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		zr, err := safezip.Open(path, safezip.DefaultLimits())
		if err != nil {
			return err
		}
		defer zr.Close()
		w := cmd.OutOrStdout()

		readJSON := func(name string, v any) error {
			b, err := zr.ReadEntry(name)
			if err != nil {
				return err
			}
			return json.Unmarshal(b, v)
		}

		var req protocol.DiagnosticRequest
		if err := readJSON(protocol.FileRequest, &req); err != nil {
			return fmt.Errorf("cannot read request: %w", err)
		}
		var plan protocol.EffectiveDisclosurePlan
		if err := readJSON(protocol.FileDisclosure, &plan); err != nil {
			return fmt.Errorf("cannot read disclosure plan: %w", err)
		}
		var coll protocol.CollectionReport
		if err := readJSON(protocol.FileCollection, &coll); err != nil {
			return fmt.Errorf("cannot read collection report: %w", err)
		}
		var tr protocol.TransformationReport
		if err := readJSON(protocol.FileTransformations, &tr); err != nil {
			return fmt.Errorf("cannot read transformation report: %w", err)
		}
		var receipt protocol.DisclosureReceipt
		if err := readJSON(protocol.FileDisclosureReceipt, &receipt); err != nil {
			return fmt.Errorf("cannot read disclosure receipt: %w", err)
		}
		var manifest protocol.Manifest
		if err := readJSON(protocol.FileManifest, &manifest); err != nil {
			return fmt.Errorf("cannot read manifest: %w", err)
		}

		section(w, "Diagnostic artifact")
		fmt.Fprintf(w, "File:            %s\n", path)
		fmt.Fprintf(w, "Protocol:        %s\n", req.ProtocolVersion)
		fmt.Fprintf(w, "Request ID:      %s\n", req.Request.ID)
		fmt.Fprintf(w, "Requester:       %s", req.Requester.Name)
		if req.Requester.Organization != "" {
			fmt.Fprintf(w, " (%s)", req.Requester.Organization)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Purpose:         %s\n", req.Purpose.Description)
		fmt.Fprintln(w, "Authenticity:    NOT VERIFIED (unsigned request)")
		if req.RetentionNotice != nil {
			fmt.Fprintf(w, "Retention:       %s\n", req.RetentionNotice.Text)
		}

		section(w, "Consent")
		fmt.Fprintf(w, "Approved  (%d): %s\n", len(plan.Approved), orNone(plan.Approved))
		fmt.Fprintf(w, "Denied    (%d): %s\n", len(plan.Denied), orNone(plan.Denied))
		fmt.Fprintf(w, "Forbidden (%d): %s\n", len(plan.Forbidden), orNone(plan.Forbidden))
		fmt.Fprintf(w, "Network access: %s   Shell execution: %s\n",
			onOff(plan.NetworkAccess, "DISABLED", "ENABLED"),
			onOff(plan.ShellExecution, "DISABLED", "ENABLED"))

		section(w, "Collection")
		for _, r := range coll.Results {
			msg := ""
			if r.Message != "" {
				msg = " — " + r.Message
			}
			fmt.Fprintf(w, "  %-32s %s%s\n", r.Capability, r.Status, msg)
		}

		section(w, "Privacy transformations")
		fmt.Fprintf(w, "Ruleset: %s\n", tr.Ruleset)
		fmt.Fprintf(w, "Detectors executed: %d   Transformations applied: %d\n\n", tr.DetectorsExecuted, tr.TransformationsApplied)
		for _, d := range tr.Detectors {
			if !d.Executed {
				continue
			}
			fmt.Fprintf(w, "  %-28s %-14s %d\n", d.Category, d.Transformer, d.Matches)
		}
		fmt.Fprintln(w, "\nNote: the transformation report never contains original values.")

		if fnd := zr.Find(protocol.FileFindings); fnd != nil {
			var fr protocol.FindingsReport
			if b, err := zr.ReadEntry(protocol.FileFindings); err == nil {
				_ = json.Unmarshal(b, &fr)
				if len(fr.Findings) > 0 {
					section(w, "Findings")
					for _, f := range fr.Findings {
						fmt.Fprintf(w, "  [%s] %s: %s\n", f.Severity, f.ID, f.Summary)
						for _, e := range f.Evidence {
							fmt.Fprintf(w, "      evidence: %s\n", e)
						}
					}
				}
			}
		}

		section(w, "Files")
		for _, e := range manifest.Entries {
			tf := ""
			if e.Transformed {
				tf = " (transformed)"
			}
			if e.Truncated {
				tf += " (truncated)"
			}
			fmt.Fprintf(w, "  %-40s %10d bytes  %s%s\n", e.Path, e.Size, e.Collector, tf)
		}

		section(w, "Integrity")
		fmt.Fprintf(w, "Request hash:         %s\n", receipt.Request.Hash)
		fmt.Fprintf(w, "Disclosure plan hash: %s\n", receipt.DisclosurePlanHash)
		fmt.Fprintf(w, "Manifest hash:        %s\n", receipt.Artifact.ManifestHash)
		fmt.Fprintln(w, "\nRun `diagx verify "+path+"` to check integrity.")
		return nil
	},
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}

func init() { rootCmd.AddCommand(inspectCmd) }
