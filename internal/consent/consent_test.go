package consent

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func TestPrompterPreservesBufferedAnswers(t *testing.T) {
	var output bytes.Buffer
	p := NewPrompter(strings.NewReader("yes\nno\n"), &output)

	first, err := p.Confirm("first?", false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Confirm("second?", true)
	if err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Fatalf("unexpected answers: first=%v second=%v", first, second)
	}
}

// testRequest builds a request with one required, one optional and one
// forbidden capability.
func testRequest() *protocol.DiagnosticRequest {
	req := &protocol.DiagnosticRequest{
		ProtocolVersion: protocol.ProtocolVersion,
		Capabilities: map[string]protocol.Capability{
			"system.os":            {Requirement: protocol.RequirementRequiredForCase},
			"runtime.node.version": {Requirement: protocol.RequirementOptional},
			"environment.values":   {Requirement: protocol.RequirementForbidden},
		},
	}
	req.Request.ID = "BYPASS-1"
	req.Requester.Name = "Test Requester"
	req.Purpose.Code = "test"
	req.Purpose.Description = "consent bypass tests"
	return req
}

func TestFileModeFailClosed(t *testing.T) {
	// Only the required capability is approved; the optional one must
	// end up denied, not silently approved.
	_, plan, _, err := Build(context.Background(), testRequest(), ModeFile, nil,
		[]byte(`{"approved":["system.os"],"denied":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Approved) != 1 || plan.Approved[0] != "system.os" {
		t.Fatalf("approved = %v, want [system.os]", plan.Approved)
	}
	if len(plan.Denied) != 1 || plan.Denied[0] != "runtime.node.version" {
		t.Fatalf("denied = %v, want [runtime.node.version]", plan.Denied)
	}
}

func TestFileModeForbiddenNeverApproved(t *testing.T) {
	// A consent file that tries to approve a forbidden capability must
	// be ignored for that capability.
	_, plan, _, err := Build(context.Background(), testRequest(), ModeFile, nil,
		[]byte(`{"approved":["system.os","runtime.node.version","environment.values"],"denied":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Approved) != 2 {
		t.Fatalf("approved = %v, want the two non-forbidden capabilities", plan.Approved)
	}
	if len(plan.Forbidden) != 1 || plan.Forbidden[0] != "environment.values" {
		t.Fatalf("forbidden = %v, want [environment.values]", plan.Forbidden)
	}
}

func TestFileModeUndeclaredCapabilitiesIgnored(t *testing.T) {
	// Capabilities that the request never declared must not enter the plan.
	_, plan, _, err := Build(context.Background(), testRequest(), ModeFile, nil,
		[]byte(`{"approved":["system.os","filesystem.source_code"],"denied":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range plan.Approved {
		if id == "filesystem.source_code" {
			t.Fatalf("undeclared capability %q entered the plan: %v", id, plan.Approved)
		}
	}
}

func TestFileModeDeniedOverridesApproved(t *testing.T) {
	// Listing a capability in both approved and denied must deny it.
	_, plan, _, err := Build(context.Background(), testRequest(), ModeFile, nil,
		[]byte(`{"approved":["system.os"],"denied":["system.os"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range plan.Approved {
		if id == "system.os" {
			t.Fatalf("system.os is approved despite being denied: %v", plan.Approved)
		}
	}
	found := false
	for _, id := range plan.Denied {
		if id == "system.os" {
			found = true
		}
	}
	if !found {
		t.Fatalf("system.os not recorded as denied: %v", plan.Denied)
	}
}

func TestAssumedModeNeverApprovesForbidden(t *testing.T) {
	_, plan, _, err := Build(context.Background(), testRequest(), ModeAssumed, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Approved) != 2 {
		t.Fatalf("approved = %v, want both required and optional", plan.Approved)
	}
	if len(plan.Forbidden) != 1 || plan.Forbidden[0] != "environment.values" {
		t.Fatalf("forbidden = %v, want [environment.values]", plan.Forbidden)
	}
}

func TestInteractiveDenyRequiredIsRecorded(t *testing.T) {
	// The user declines a required-for-case capability: the denial must
	// be recorded and a warning produced.
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("no\nyes\n"), &out)
	decision, plan, warnings, err := Build(context.Background(), testRequest(), ModeInteractive, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decisions["system.os"].State != protocol.ConsentDenied {
		t.Fatalf("required capability denial not recorded: %+v", decision.Decisions)
	}
	if len(plan.Denied) != 1 || plan.Denied[0] != "system.os" {
		t.Fatalf("denied = %v, want [system.os]", plan.Denied)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "system.os") {
		t.Fatalf("warnings = %v, want one warning naming system.os", warnings)
	}
}

func TestUnsupportedModeRejected(t *testing.T) {
	if _, _, _, err := Build(context.Background(), testRequest(), "telepathy", nil, nil); err == nil {
		t.Fatal("unsupported consent mode was accepted")
	}
}

func TestPlanOnlyContainsDeclaredCapabilities(t *testing.T) {
	_, plan, _, err := Build(context.Background(), testRequest(), ModeFile, nil,
		[]byte(`{"approved":["system.os"],"denied":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for id := range testRequest().Capabilities {
		declared[id] = true
	}
	for _, id := range append(append(append([]string{}, plan.Approved...), plan.Denied...), plan.Forbidden...) {
		if !declared[id] {
			t.Fatalf("plan contains undeclared capability %q", id)
		}
	}
}
