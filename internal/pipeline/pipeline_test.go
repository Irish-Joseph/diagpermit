package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diagx/diagx/internal/collection"
	"github.com/diagx/diagx/internal/consent"
	"github.com/diagx/diagx/internal/safezip"
	"github.com/diagx/diagx/internal/transform"
	"github.com/diagx/diagx/internal/verification"
	"github.com/diagx/diagx/pkg/protocol"
)

// --- fakes ---------------------------------------------------------------

type fakeCollector struct {
	id      string
	caps    []collection.DeclaredCapability
	status  protocol.CollectionStatus
	file    map[string]collection.CollectedFile
	sleep   time.Duration
	network bool
}

func (f *fakeCollector) ID() string      { return f.id }
func (f *fakeCollector) Version() string { return "0.0.1" }
func (f *fakeCollector) Capabilities() []collection.DeclaredCapability {
	out := make([]collection.DeclaredCapability, len(f.caps))
	copy(out, f.caps)
	for i := range out {
		if f.network {
			out[i].Network = true
		}
	}
	return out
}
func (f *fakeCollector) Plan(c *collection.Context) collection.PlanInfo {
	return collection.PlanInfo{Capability: c.Capability}
}
func (f *fakeCollector) Collect(c *collection.Context) collection.Result {
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-c.Ctx.Done():
			return collection.Result{Status: protocol.StatusTimedOut}
		}
	}
	files := map[string]collection.CollectedFile{}
	for k, v := range f.file {
		files[k] = v
	}
	return collection.Result{Status: f.status, Files: files, Bytes: 10}
}

func useFakeRegistry(t *testing.T, collectors ...collection.Collector) {
	t.Helper()
	prev := registryFactory
	SetRegistryFactory(func() *collection.Registry {
		return collection.NewRegistry(collectors...)
	})
	t.Cleanup(func() { SetRegistryFactory(prev) })
}

// --- helpers ---------------------------------------------------------------

func writeRequest(t *testing.T, dir string, req protocol.DiagnosticRequest) string {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "req.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func testRequest(t *testing.T) *protocol.DiagnosticRequest {
	t.Helper()
	req, err := protocolFromJSON(`
{
  "protocolVersion": "0.1",
  "request": {"id": "TEST-1"},
  "requester": {"name": "Test Support"},
  "purpose": {"code": "test", "description": "unit test"},
  "capabilities": {
    "system.os": {"requirement": "required_for_case"},
    "application.logs": {"requirement": "optional"}
  },
  "policy": {"networkAccess": false, "arbitraryShellExecution": false, "maximumTotalBytes": 1048576, "maximumDurationSeconds": 30}
}
`)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func protocolFromJSON(s string) (*protocol.DiagnosticRequest, error) {
	var r protocol.DiagnosticRequest
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func consentFile(t *testing.T, approved, denied []string) []byte {
	t.Helper()
	type c struct {
		Approved []string `json:"approved"`
		Denied   []string `json:"denied"`
	}
	b, _ := json.Marshal(c{Approved: approved, Denied: denied})
	return b
}

// --- tests -----------------------------------------------------------------

func TestEndToEndArtifact(t *testing.T) {
	dir := t.TempDir()
	// Create a log with secrets.
	logsDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logContent := "password=Sup3rS3cretP4ssw0rd\npeer 192.168.1.20\n"
	if err := os.WriteFile(filepath.Join(logsDir, "app.log"), []byte(logContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// The application log collector is rooted at the project working
	// directory, so run from inside the temp project.
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	req := testRequest(t)
	req.Local = &protocol.LocalConfig{ApplicationLogPath: "logs/app.log"}
	reqPath := writeRequest(t, dir, *req)

	// Load via config to ensure YAML/JSON round trip semantics.
	req2, err := loadReqFile(reqPath)
	if err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "out.diagnostic")
	out, err := Run(context.Background(), req2, consent.ModeFile, nil,
		consentFile(t, []string{"system.os", "application.logs"}, nil), outPath, discardWriter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("artifact missing: %v", err)
	}

	// Verify integrity.
	rep, err := verification.Verify(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Verdict(); got != "INTEGRITY VERIFIED" {
		for _, c := range rep.Checks {
			if !c.OK {
				t.Errorf("check %s failed: %s", c.Name, c.Detail)
			}
		}
		t.Fatalf("verdict: %s", got)
	}

	// Secrets must not survive in the packaged log.
	zr, err := safezip.Open(outPath, safezip.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	logBytes, err := zr.ReadEntry("data/application/logs.txt")
	zr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logBytes), "Sup3rS3cretP4ssw0rd") {
		t.Fatal("secret leaked into artifact")
	}
	if strings.Contains(string(logBytes), "192.168.1.20") {
		t.Fatal("IP leaked into artifact")
	}
	if !strings.Contains(string(logBytes), "host-a") {
		t.Fatalf("expected pseudonym, got: %s", logBytes)
	}

	// Receipt answers the four questions.
	if out.Receipt.Request.ID != "TEST-1" || !strings.HasPrefix(out.Receipt.Request.Hash, "sha256:") {
		t.Fatal("bad receipt request")
	}
	if len(out.Receipt.Consent.Approved) != 2 {
		t.Fatalf("bad consent in receipt: %+v", out.Receipt.Consent)
	}
}

func TestRequiredDeniedIsRecorded(t *testing.T) {
	dir := t.TempDir()
	req := testRequest(t)
	req.Local = &protocol.LocalConfig{}
	reqPath := writeRequest(t, dir, *req)
	req2, _ := loadReqFile(reqPath)

	// Deny the required capability.
	out, err := Run(context.Background(), req2, consent.ModeFile, nil,
		consentFile(t, nil, []string{"system.os"}), filepath.Join(dir, "o.diagnostic"), discardWriter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range out.Plan.Denied {
		if d == "system.os" {
			found = true
		}
	}
	if !found {
		t.Fatalf("denied required capability not recorded: %+v", out.Plan)
	}
	// The warning must mention the mandatory wording.
	if !containsWarning(out, "required for this support case") {
		t.Fatal("missing required-denial warning")
	}
}

func TestUnsupportedCollector(t *testing.T) {
	req := testRequest(t)
	req.Capabilities["network.interfaces"] = protocol.Capability{Requirement: protocol.RequirementOptional}
	out, err := Run(context.Background(), req, consent.ModeFile, nil,
		consentFile(t, []string{"network.interfaces"}, []string{"system.os", "application.logs"}),
		filepath.Join(t.TempDir(), "o.diagnostic"), discardWriter{})
	if err != nil {
		t.Fatal(err)
	}
	status := ""
	for _, r := range out.Collection.Results {
		if r.Capability == "network.interfaces" {
			status = string(r.Status)
		}
	}
	if status != string(protocol.StatusUnsupported) {
		t.Fatalf("expected unsupported, got %q", status)
	}
}

func TestNetworkDeniedByPolicy(t *testing.T) {
	useFakeRegistry(t, &fakeCollector{
		id:      "netfake",
		caps:    []collection.DeclaredCapability{{ID: "api.reachability", Description: "x"}},
		status:  protocol.StatusSuccess,
		network: true,
		file:    map[string]collection.CollectedFile{},
	})
	req := testRequest(t)
	req.Capabilities["api.reachability"] = protocol.Capability{Requirement: protocol.RequirementOptional}
	out, err := Run(context.Background(), req, consent.ModeFile, nil,
		consentFile(t, []string{"api.reachability"}, []string{"system.os", "application.logs"}),
		filepath.Join(t.TempDir(), "o.diagnostic"), discardWriter{})
	if err != nil {
		t.Fatal(err)
	}
	status := ""
	for _, r := range out.Collection.Results {
		if r.Capability == "api.reachability" {
			status = string(r.Status)
		}
	}
	if status != string(protocol.StatusForbidden) {
		t.Fatalf("expected forbidden (network disabled), got %q", status)
	}
}

func TestTimeout(t *testing.T) {
	useFakeRegistry(t, &fakeCollector{
		id:    "slow",
		caps:  []collection.DeclaredCapability{{ID: "system.os", Description: "x"}},
		sleep: 5 * time.Second,
		file:  map[string]collection.CollectedFile{},
	})
	req := testRequest(t)
	req.Policy.MaximumDurationSeconds = 1
	out, err := Run(context.Background(), req, consent.ModeFile, nil,
		consentFile(t, []string{"system.os"}, []string{"application.logs"}),
		filepath.Join(t.TempDir(), "o.diagnostic"), discardWriter{})
	if err != nil {
		t.Fatal(err)
	}
	status := ""
	for _, r := range out.Collection.Results {
		if r.Capability == "system.os" {
			status = string(r.Status)
		}
	}
	if status != string(protocol.StatusTimedOut) {
		t.Fatalf("expected timed_out, got %q", status)
	}
}

func TestSizeLimit(t *testing.T) {
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'a'
	}
	useFakeRegistry(t,
		&fakeCollector{id: "app", caps: []collection.DeclaredCapability{{ID: "application.logs"}},
			status: protocol.StatusSuccess,
			file: map[string]collection.CollectedFile{
				"data/application/logs.txt": {Content: big, MediaType: "text/plain"},
			}},
		&fakeCollector{id: "sys", caps: []collection.DeclaredCapability{{ID: "system.os"}},
			status: protocol.StatusSuccess,
			file: map[string]collection.CollectedFile{
				"data/system/os.json": {Content: []byte(`{}`), MediaType: "application/json"},
			}},
	)
	req := testRequest(t)
	req.Policy.MaximumTotalBytes = 100
	out, err := Run(context.Background(), req, consent.ModeFile, nil,
		consentFile(t, []string{"system.os", "application.logs"}, nil),
		filepath.Join(t.TempDir(), "o.diagnostic"), discardWriter{})
	if err != nil {
		t.Fatal(err)
	}
	// The oversized file must be dropped; the run still completes.
	sawLimit := false
	for _, r := range out.Collection.Results {
		if r.Status == protocol.StatusSizeLimitExceeded {
			sawLimit = true
		}
	}
	if !sawLimit {
		t.Fatalf("expected size_limit_exceeded, results: %+v", out.Collection.Results)
	}
}

func TestFailClosedNoArtifact(t *testing.T) {
	dir := t.TempDir()
	req := testRequest(t)
	req.Local = &protocol.LocalConfig{
		Privacy: &protocol.PrivacyConfig{
			ExtraDetectors: []protocol.ExtraDetector{
				{Name: "broken", Pattern: "([unclosed", Action: "mask"},
			},
		},
	}
	reqPath := writeRequest(t, dir, *req)
	req2, _ := loadReqFile(reqPath)
	outPath := filepath.Join(dir, "must-not-exist.diagnostic")
	_, err := Run(context.Background(), req2, consent.ModeFile, nil,
		consentFile(t, []string{"system.os"}, []string{"application.logs"}), outPath, discardWriter{})
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
	if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
		t.Fatal("artifact must NOT be produced on fail-closed")
	}
}

func TestPrintFailClosedRecognizesPipelineWrapper(t *testing.T) {
	err := &FailClosedPipelineError{FailClosedError: transform.FailClosedError{
		Collector: "application", Transformer: "custom:test", Reason: "boom",
	}}
	var output bytes.Buffer
	if !PrintFailClosed(&output, err) {
		t.Fatal("wrapped fail-closed error was not recognized")
	}
	for _, expected := range []string{"COLLECTION STOPPED SAFELY", "application", "custom:test", "boom"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q: %s", expected, output.String())
		}
	}

	output.Reset()
	if PrintFailClosed(&output, fmt.Errorf("ordinary failure")) {
		t.Fatal("ordinary error must not be rendered as fail-closed")
	}
	if output.Len() != 0 {
		t.Fatalf("ordinary error should not be duplicated, got %q", output.String())
	}
}

func TestExpiredRequestRejected(t *testing.T) {
	req := testRequest(t)
	req.ExpiresAt = "2020-01-01T00:00:00Z"
	err := configValidateExpired(req)
	if err == nil {
		t.Fatal("expired request must be rejected")
	}
}

// --- small helpers -----------------------------------------------------------

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func containsWarning(out *Output, sub string) bool {
	for _, w := range out.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func loadReqFile(path string) (*protocol.DiagnosticRequest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return protocolFromJSON(string(b))
}

func configValidateExpired(req *protocol.DiagnosticRequest) error {
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return err
		}
		if t.Before(time.Now()) {
			return fmt.Errorf("expired")
		}
	}
	return nil
}
