// Package consent implements the capability review and user consent step
// it turns a DiagnosticRequest plus the user's
// decisions into a ConsentDecision and an immutable EffectiveDisclosurePlan.
package consent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// Mode records how the consent decisions were obtained.
const (
	ModeInteractive = "interactive"
	ModeAssumed     = "assumed"      // --yes: approve all non-forbidden
	ModeFile        = "file"         // --consent consent.json
	ModePlan        = "plan-preview" // diagpermit plan (no collection)
)

// Review holds the grouped capabilities for display and prompting.
type Review struct {
	Required     []string
	Optional     []string
	Forbidden    []string
	NotRequested []string
}

// ReviewFor groups a request's capabilities by requirement.
func ReviewFor(req *protocol.DiagnosticRequest) Review {
	var r Review
	for id, cap := range req.Capabilities {
		switch cap.Requirement {
		case protocol.RequirementRequiredForCase:
			r.Required = append(r.Required, id)
		case protocol.RequirementOptional:
			r.Optional = append(r.Optional, id)
		case protocol.RequirementForbidden:
			r.Forbidden = append(r.Forbidden, id)
		default:
			r.NotRequested = append(r.NotRequested, id)
		}
	}
	sort.Strings(r.Required)
	sort.Strings(r.Optional)
	sort.Strings(r.Forbidden)
	sort.Strings(r.NotRequested)
	return r
}

// Prompter asks the user questions. The default implementation reads
// from in and writes to out.
type Prompter struct {
	In     io.Reader
	Out    io.Writer
	reader *bufio.Reader
}

// NewPrompter over in/out streams.
func NewPrompter(in io.Reader, out io.Writer) *Prompter {
	return &Prompter{In: in, Out: out, reader: bufio.NewReader(in)}
}

func (p *Prompter) writeln(format string, args ...any) {
	fmt.Fprintf(p.Out, format+"\n", args...)
}

// Confirm asks a yes/no question; default is used when the user just
// presses Enter.
func (p *Prompter) Confirm(question string, defaultYes bool) (bool, error) {
	suffix := "[Y/n] "
	if !defaultYes {
		suffix = "[y/N] "
	}
	if _, err := p.Out.Write([]byte(question + " " + suffix)); err != nil {
		return false, err
	}
	if p.reader == nil {
		p.reader = bufio.NewReader(p.In)
	}
	line, err := p.reader.ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defaultYes, nil
	}
	if line == "y" || line == "yes" {
		return true, nil
	}
	return false, nil
}

// Decision is one user choice.
type Decision struct {
	Capability string
	Approved   bool
}

// Build runs the consent flow:
//
//   - mode Assumed: every required and optional capability is approved.
//   - mode File: decisions come from a JSON file {"approved":[...],
//     "denied":[...]}; capabilities not listed are denied (consent is
//     fail-closed).
//   - mode Interactive: required capabilities default to approve (the
//     user may deny); optional capabilities are asked one by one and
//     default to deny.
//
// It returns the ConsentDecision, the EffectiveDisclosurePlan and a
// human-readable warning when the user denied a required capability.
func Build(ctx context.Context, req *protocol.DiagnosticRequest, mode string, p *Prompter, fileData []byte) (*protocol.ConsentDecision, *protocol.EffectiveDisclosurePlan, []string, error) {
	_ = ctx
	rev := ReviewFor(req)
	var decisions map[string]protocol.Decision
	warnings := []string{}
	decision := &protocol.ConsentDecision{
		ProtocolVersion: protocol.ProtocolVersion,
		RequestID:       req.RequestID(),
		DecidedAt:       time.Now().UTC(),
		Mode:            mode,
		Decisions:       map[string]protocol.Decision{},
	}

	var err error
	switch mode {
	case ModeAssumed:
		for _, id := range rev.Required {
			decision.Decisions[id] = protocol.Decision{State: protocol.ConsentApproved}
		}
		for _, id := range rev.Optional {
			decision.Decisions[id] = protocol.Decision{State: protocol.ConsentApproved}
		}
	case ModeFile:
		var f struct {
			Approved []string `json:"approved"`
			Denied   []string `json:"denied"`
		}
		if err = json.Unmarshal(fileData, &f); err != nil {
			return nil, nil, nil, fmt.Errorf("consent file: %w", err)
		}
		approved := map[string]bool{}
		for _, id := range f.Approved {
			approved[id] = true
		}
		// Only capabilities actually declared in the request are
		// honoured; extra IDs in the consent file are ignored.
		declared := map[string]bool{}
		for id := range req.Capabilities {
			declared[id] = true
		}
		for _, id := range f.Denied {
			if declared[id] {
				approved[id] = false
			}
		}
		for id := range declared {
			if req.Capabilities[id].Requirement == protocol.RequirementForbidden {
				approved[id] = false
				continue
			}
			if approved[id] {
				decision.Decisions[id] = protocol.Decision{State: protocol.ConsentApproved}
			} else {
				decision.Decisions[id] = protocol.Decision{State: protocol.ConsentDenied}
			}
		}
	case ModeInteractive:
		if p == nil {
			return nil, nil, nil, fmt.Errorf("interactive consent requires a prompter (use --yes for non-interactive runs)")
		}
		p.writeln("")
		p.writeln("Diagnostic request from: %s%s", req.Requester.Name, retentionSuffix(req))
		p.writeln("")
		for _, id := range rev.Required {
			ok, err := p.Confirm("Required for this support case — "+Describe(id, req)+": approve?", true)
			if err != nil {
				return nil, nil, nil, err
			}
			if ok {
				decision.Decisions[id] = protocol.Decision{State: protocol.ConsentApproved}
			} else {
				decision.Decisions[id] = protocol.Decision{State: protocol.ConsentDenied}
			}
		}
		for _, id := range rev.Optional {
			ok, err := p.Confirm("Optional — "+Describe(id, req)+": approve?", false)
			if err != nil {
				return nil, nil, nil, err
			}
			if ok {
				decision.Decisions[id] = protocol.Decision{State: protocol.ConsentApproved}
			} else {
				decision.Decisions[id] = protocol.Decision{State: protocol.ConsentDenied}
			}
		}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported consent mode %q", mode)
	}
	decisions = decision.Decisions

	plan := &protocol.EffectiveDisclosurePlan{
		ProtocolVersion: protocol.ProtocolVersion,
		RequestID:       req.RequestID(),
		NetworkAccess:   req.Policy.NetworkAccess,
		ShellExecution:  req.Policy.ArbitraryShellExecution,
	}
	for id, d := range decisions {
		switch d.State {
		case protocol.ConsentApproved:
			plan.Approved = append(plan.Approved, id)
		case protocol.ConsentDenied:
			plan.Denied = append(plan.Denied, id)
		}
	}
	plan.Forbidden = append(plan.Forbidden, rev.Forbidden...)
	plan.NotRequested = append(plan.NotRequested, rev.NotRequested...)
	sort.Strings(plan.Approved)
	sort.Strings(plan.Denied)
	sort.Strings(plan.Forbidden)
	sort.Strings(plan.NotRequested)

	// Denying a capability the requester marked required must be
	// recorded, regardless of consent mode.
	for _, id := range plan.Denied {
		if cap, ok := req.Capabilities[id]; ok && cap.Requirement == protocol.RequirementRequiredForCase {
			warnings = append(warnings, requiredDeniedWarning(id))
		}
	}

	return decision, plan, warnings, err
}

// requiredDeniedWarning is the spec-mandated wording when the user denies
// a capability the requester marked required.
func requiredDeniedWarning(id string) string {
	return fmt.Sprintf(`You declined information marked "required for this support case" (%s).
The diagnostic package can still be created, but the requester may not have enough information to diagnose the issue.`, id)
}

func retentionSuffix(req *protocol.DiagnosticRequest) string {
	if req.RetentionNotice != nil && req.RetentionNotice.Text != "" {
		return " (retention: " + req.RetentionNotice.Text + ")"
	}
	return ""
}

// Describe renders a capability ID with its constraint hint.
func Describe(id string, req *protocol.DiagnosticRequest) string {
	cap := req.Capabilities[id]
	s := id
	if cap.Constraints != nil {
		var hints []string
		if cap.Constraints.MaxLines > 0 {
			hints = append(hints, fmt.Sprintf("max %d lines", cap.Constraints.MaxLines))
		}
		if cap.Constraints.MaxBytes > 0 {
			hints = append(hints, fmt.Sprintf("max %d bytes", cap.Constraints.MaxBytes))
		}
		if len(hints) > 0 {
			s += " (" + strings.Join(hints, ", ") + ")"
		}
	}
	return s
}
