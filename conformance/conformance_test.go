// Package conformance implements the DiagPermit V0.1 conformance suite
// Each numbered directory holds:
//
//	input files        (request, consent, sample data)
//	expected-*.json    (expected normalized results)
//
// Future independent implementations should be able to run the same
// vectors. The runner here executes them against the reference
// implementation via `go test ./conformance/`.
package conformance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/internal/consent"
	"github.com/Irish-Joseph/diagpermit/internal/pipeline"
	"github.com/Irish-Joseph/diagpermit/internal/transform"
	"github.com/Irish-Joseph/diagpermit/internal/verification"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// --- shared helpers ---------------------------------------------------------

type expectedPlan struct {
	Approved       []boolOrStr `json:"approved"`
	Denied         []boolOrStr `json:"denied"`
	Forbidden      []boolOrStr `json:"forbidden"`
	NetworkAccess  bool        `json:"networkAccess"`
	ShellExecution bool        `json:"shellExecution"`
}

// boolOrStr allows expected files to use either strings or null.
type boolOrStr string

func loadJSONFile(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func requestFromFile(t *testing.T, dir string) *protocol.DiagnosticRequest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var req protocol.DiagnosticRequest
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("vector request invalid: %v", err)
	}
	return &req
}

func consentData(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "consent.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func statusOf(out *pipeline.Output, cap string) protocol.CollectionStatus {
	for _, r := range out.Collection.Results {
		if r.Capability == cap {
			return r.Status
		}
	}
	return ""
}

func runVector(t *testing.T, dir string) (*pipeline.Output, string) {
	t.Helper()
	req := requestFromFile(t, dir)
	consentBytes := consentData(t, dir) // read before chdir
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	out, err := pipeline.Run(context.Background(), req, consent.ModeFile, nil,
		consentBytes, "vector-output.diagnostic", ioDiscard{})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	return out, "vector-output.diagnostic"
}

// vecDir resolves a vector directory to an absolute path.
func vecDir(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, name)
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func planEquals(t *testing.T, dir string, out *pipeline.Output) {
	t.Helper()
	var exp expectedPlan
	loadJSONFile(t, dir, "expected-plan.json", &exp)
	match := func(got, want []string, name string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("plan.%s: got %v want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("plan.%s[%d]: got %q want %q", name, i, got[i], want[i])
			}
		}
	}
	match(out.Plan.Approved, strs(exp.Approved), "approved")
	match(out.Plan.Denied, strs(exp.Denied), "denied")
	match(out.Plan.Forbidden, strs(exp.Forbidden), "forbidden")
	if out.Plan.NetworkAccess != exp.NetworkAccess {
		t.Fatalf("plan.networkAccess mismatch")
	}
	if out.Plan.ShellExecution != exp.ShellExecution {
		t.Fatalf("plan.shellExecution mismatch")
	}
}

func strs(in []boolOrStr) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, string(s))
	}
	return out
}

func checkStatus(t *testing.T, dir string, out *pipeline.Output) {
	t.Helper()
	var exp map[string]string
	loadJSONFile(t, dir, "expected-status.json", &exp)
	for cap, want := range exp {
		got := statusOf(out, cap)
		if string(got) != want {
			t.Errorf("capability %s: status %q, want %q", cap, got, want)
		}
	}
}

func checkVerdict(t *testing.T, path, dir string) {
	t.Helper()
	var exp struct {
		Verdict      string `json:"verdict"`
		FailingCheck string `json:"failingCheck"`
	}
	loadJSONFile(t, dir, "expected-verdict.json", &exp)
	rep, err := verification.Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict() != exp.Verdict {
		t.Errorf("verdict %q, want %q", rep.Verdict(), exp.Verdict)
	}
	if exp.FailingCheck != "" {
		found := false
		for _, c := range rep.Checks {
			if c.Name == exp.FailingCheck && !c.OK {
				found = true
			}
		}
		if !found {
			t.Errorf("expected failing check %q not found", exp.FailingCheck)
		}
	}
}

// --- vectors ----------------------------------------------------------------

func TestVector01BasicRequest(t *testing.T) {
	dir := vecDir(t, "01-basic-request")
	out, artifact := runVector(t, dir)
	planEquals(t, dir, out)
	checkVerdict(t, artifact, dir)
}

func TestVector02OptionalDenied(t *testing.T) {
	dir := vecDir(t, "02-optional-denied")
	out, _ := runVector(t, dir)
	planEquals(t, dir, out)
	checkStatus(t, dir, out)
}

func TestVector03RequiredDenied(t *testing.T) {
	dir := vecDir(t, "03-required-denied")
	out, _ := runVector(t, dir)
	planEquals(t, dir, out)
	var exp struct {
		WarningContains string `json:"warningContains"`
	}
	loadJSONFile(t, dir, "expected-warning-substring.json", &exp)
	found := false
	for _, w := range out.Warnings {
		if strings.Contains(w, exp.WarningContains) {
			found = true
		}
	}
	if !found {
		t.Errorf("warning %q not recorded; warnings: %v", exp.WarningContains, out.Warnings)
	}
}

func TestVector04Transformations(t *testing.T) {
	dir := vecDir(t, "04-transformations")
	sample, err := os.ReadFile(filepath.Join(dir, "sample.log"))
	if err != nil {
		t.Fatal(err)
	}
	wantOut, err := os.ReadFile(filepath.Join(dir, "expected-output.log"))
	if err != nil {
		t.Fatal(err)
	}
	// Pseudonyms are assigned by first-occurrence order, so the output
	// is deterministic even though the salt is random.
	e, err := transform.NewEngine(transform.DefaultRuleset(), []byte("conformance-salt-01"))
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := e.Apply(sample)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(wantOut)) {
		t.Errorf("transformed output mismatch:\ngot:\n%s\nwant:\n%s", got, wantOut)
	}
	var exp struct {
		TransformationsApplied int `json:"transformationsApplied"`
	}
	loadJSONFile(t, dir, "expected-report.json", &exp)
	if e.TotalTransformations() != exp.TransformationsApplied {
		t.Errorf("transformations %d, want %d", e.TotalTransformations(), exp.TransformationsApplied)
	}
}

func TestVector05CorruptedManifest(t *testing.T) {
	dir := vecDir(t, "05-corrupted-manifest")
	// Build a valid artifact from vector 01's request, then rewrite a
	// data file's bytes inside the archive so the manifest hash no longer
	// matches (deterministic corruption).
	base := vecDir(t, "01-basic-request")
	_, artifact := runVector(t, base)
	tampered := rewriteArchiveEntry(t, artifact, "data/system/os.json",
		`{"os":"tampered","manifest-mismatch":true}`)
	checkVerdict(t, tampered, dir)
}

func TestVector06InvalidPath(t *testing.T) {
	dir := vecDir(t, "06-invalid-path")
	// Ensure a "secret" exists outside the root to prove it is not read.
	secret, err := filepath.Abs(filepath.Join(filepath.Dir(dir), "secret-outside-root.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("SECRET-MARKER"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })
	out, _ := runVector(t, dir)
	checkStatus(t, dir, out)
	if b, err := os.ReadFile(filepath.Join(dir, "vector-output.diagnostic")); err == nil {
		// The artifact (if produced) must not contain the secret marker.
		if strings.Contains(string(b), "SECRET-MARKER") {
			t.Fatal("out-of-root secret leaked into artifact")
		}
	}
}

func TestVector07OversizedFile(t *testing.T) {
	dir := vecDir(t, "07-oversized-file")
	// Provide a log bigger than the 64-byte budget.
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "big.log"),
		[]byte(strings.Repeat("line-of-output ", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	req, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r protocol.DiagnosticRequest
	_ = json.Unmarshal(req, &r)
	r.Local = &protocol.LocalConfig{ApplicationLogPath: "logs/big.log"}
	rb, _ := json.Marshal(&r)
	if err := os.WriteFile(filepath.Join(dir, "request.json"), rb, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := runVector(t, dir)
	checkStatus(t, dir, out)
}

// fakeNetCollector declares a network requirement for the test.
type fakeNetCollector struct{}

func (fakeNetCollector) ID() string      { return "api-reachability" }
func (fakeNetCollector) Version() string { return "0.0.1" }
func (fakeNetCollector) Capabilities() []collection.DeclaredCapability {
	return []collection.DeclaredCapability{{
		ID: "api.reachability", Description: "tests a connection", Network: true,
	}}
}
func (fakeNetCollector) Plan(c *collection.Context) collection.PlanInfo {
	return collection.PlanInfo{Capability: c.Capability, Network: "status.example.com:443"}
}
func (fakeNetCollector) Collect(c *collection.Context) collection.Result {
	return collection.Result{Status: protocol.StatusSuccess}
}

func TestVector08NetworkDenied(t *testing.T) {
	dir := vecDir(t, "08-network-denied")
	restore := setRegistryForTest(t, []collection.Collector{fakeNetCollector{}})
	defer restore()

	// The vector's request is constructed in-code so the fake collector's
	// capability is registered.
	req := &protocol.DiagnosticRequest{}
	_ = json.Unmarshal([]byte(`{
		"protocolVersion": "0.1",
		"request": {"id": "CONF-08"},
		"requester": {"name": "Conformance Support"},
		"purpose": {"code": "network-denied", "description": "Network collector blocked"},
		"capabilities": {"api.reachability": {"requirement": "optional"}},
		"policy": {"networkAccess": false, "arbitraryShellExecution": false}
	}`), req)
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := pipeline.Run(context.Background(), req, consent.ModeFile, nil,
		[]byte(`{"approved":["api.reachability"],"denied":[]}`),
		filepath.Join(t.TempDir(), "o.diagnostic"), ioDiscard{})
	if err != nil {
		t.Fatal(err)
	}
	checkStatus(t, dir, out)
}

func TestVector09UnsupportedCollector(t *testing.T) {
	dir := vecDir(t, "09-unsupported-collector")
	out, _ := runVector(t, dir)
	checkStatus(t, dir, out)
}

func TestVector10HashMismatch(t *testing.T) {
	dir := vecDir(t, "10-hash-mismatch")
	// Build from vector 01, then rewrite request.json inside the archive
	// so the receipt's request hash no longer matches.
	base := vecDir(t, "01-basic-request")
	_, artifact := runVector(t, base)
	tampered := rewriteArchiveEntry(t, artifact, protocol.FileRequest,
		`{"protocolVersion":"0.1","request":{"id":"EVIL-1"},"requester":{"name":"Evil"},"purpose":{"code":"x","description":"y"},"capabilities":{"system.os":{"requirement":"required_for_case"}},"policy":{"networkAccess":false,"arbitraryShellExecution":false}}`)
	checkVerdict(t, tampered, dir)
}
