// Package schemas validates the DiagPermit protocol documents against the
// published JSON schemas (spec/schemas/*.json).
package schemas

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Irish-Joseph/diagpermit/internal/config"
	"github.com/Irish-Joseph/diagpermit/internal/consent"
	"github.com/Irish-Joseph/diagpermit/internal/pipeline"
)

var schemaFiles = []string{
	"capability-0.1.json",
	"diagnostic-request-0.1.json",
	"consent-decision-0.1.json",
	"effective-disclosure-plan-0.1.json",
	"collector-result-0.1.json",
	"collection-report-0.1.json",
	"transformation-report-0.1.json",
	"manifest-0.1.json",
	"disclosure-receipt-0.1.json",
	"finding-0.1.json",
}

func loadSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	for _, name := range schemaFiles {
		// #nosec G304 -- name is a fixed, compile-time constant file list.
		data, err := os.ReadFile(filepath.Join("..", "..", "spec", "schemas", name))
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse schema %s: %v", name, err)
		}
		if err := compiler.AddResource(name, doc); err != nil {
			t.Fatalf("add schema %s: %v", name, err)
		}
	}
	out := map[string]*jsonschema.Schema{}
	for _, name := range schemaFiles {
		s, err := compiler.Compile(name)
		if err != nil {
			t.Fatalf("compile schema %s: %v", name, err)
		}
		out[name[:len(name)-len(".json")]] = s
	}
	return out
}

func mustJSON(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	return v
}

func check(t *testing.T, s *jsonschema.Schema, v any, label string) {
	t.Helper()
	if err := s.Validate(v); err != nil {
		t.Errorf("%s does not validate: %v", label, err)
	}
}

// TestSchemasValidateConformanceRequest validates the published conformance
// request fixture against the DiagnosticRequest schema.
func TestSchemasValidateConformanceRequest(t *testing.T) {
	s := loadSchemas(t)
	// #nosec G304 -- fixed conformance fixture path.
	data, err := os.ReadFile(filepath.Join("..", "..", "conformance", "01-basic-request", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	check(t, s["diagnostic-request-0.1"], mustJSON(t, data), "conformance request")
}

// TestSchemasValidatePipelineArtifact runs the real pipeline and validates
// every protocol document inside the produced artifact against its schema.
func TestSchemasValidatePipelineArtifact(t *testing.T) {
	s := loadSchemas(t)

	// #nosec G304 -- fixed conformance fixture paths.
	req, err := config.Load(filepath.Join("..", "..", "conformance", "01-basic-request", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	consentData, err := os.ReadFile(filepath.Join("..", "..", "conformance", "01-basic-request", "consent.json"))
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(t.TempDir(), "schema-check.diagnostic")
	// #nosec G304 -- outPath is a test-created temp path.
	if _, err := pipeline.Run(context.Background(), req, consent.ModeFile, nil, consentData, outPath, io.Discard); err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	// #nosec G304 -- outPath was created by this test.
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]bool{}
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		entries[zf.Name] = true
		switch zf.Name {
		case "request.json":
			check(t, s["diagnostic-request-0.1"], mustJSON(t, data), zf.Name)
		case "disclosure.json":
			check(t, s["effective-disclosure-plan-0.1"], mustJSON(t, data), zf.Name)
		case "collection.json":
			check(t, s["collection-report-0.1"], mustJSON(t, data), zf.Name)
		case "manifest.json":
			check(t, s["manifest-0.1"], mustJSON(t, data), zf.Name)
		case "reports/transformations.json":
			check(t, s["transformation-report-0.1"], mustJSON(t, data), zf.Name)
		case "attestations/disclosure-receipt.json":
			check(t, s["disclosure-receipt-0.1"], mustJSON(t, data), zf.Name)
		case "reports/findings.json":
			var fr struct {
				Findings []any `json:"findings"`
			}
			if err := json.Unmarshal(data, &fr); err != nil {
				t.Fatalf("%s: %v", zf.Name, err)
			}
			for i, f := range fr.Findings {
				check(t, s["finding-0.1"], f, "findings.json["+string(rune('0'+i))+"]")
			}
		}
	}
	for _, required := range []string{"request.json", "disclosure.json", "collection.json", "manifest.json", "reports/transformations.json", "attestations/disclosure-receipt.json"} {
		if !entries[required] {
			t.Errorf("artifact is missing %s", required)
		}
	}
}

// TestSchemasRejectInvalidDocuments makes sure the schemas actually reject
// malformed protocol documents (they must not be vacuously permissive).
func TestSchemasRejectInvalidDocuments(t *testing.T) {
	s := loadSchemas(t)
	zeroHash := "sha256:" + repeat("0", 64)
	oneHash := "sha256:" + repeat("1", 64)
	// #nosec G304 -- fixed conformance fixture path.
	data, err := os.ReadFile(filepath.Join("..", "..", "conformance", "01-basic-request", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	req := mustJSON(t, data).(map[string]any)

	delete(req, "purpose")
	if err := s["diagnostic-request-0.1"].Validate(req); err == nil {
		t.Error("request without purpose was accepted")
	}

	req["purpose"] = map[string]any{"code": "x"} // missing description
	if err := s["diagnostic-request-0.1"].Validate(req); err == nil {
		t.Error("purpose without description was accepted")
	}

	req["capabilities"] = map[string]any{
		"system.os": map[string]any{"requirement": "demand"},
	}
	if err := s["diagnostic-request-0.1"].Validate(req); err == nil {
		t.Error("unknown capability requirement was accepted")
	}

	req["capabilities"] = map[string]any{} // at least one capability required
	if err := s["diagnostic-request-0.1"].Validate(req); err == nil {
		t.Error("request without capabilities was accepted")
	}

	plan := map[string]any{
		"protocolVersion": "0.1",
		"requestId":       "X",
		"approved":        []string{},
		"denied":          []string{},
		"forbidden":       []string{},
		"networkAccess":   false,
	} // missing shellExecution
	if err := s["effective-disclosure-plan-0.1"].Validate(plan); err == nil {
		t.Error("plan without shellExecution was accepted")
	}

	receipt := map[string]any{
		"protocolVersion":    "0.1",
		"request":            map[string]any{"id": "X", "hash": "sha256:abc"}, // bad hash format
		"disclosurePlanHash": zeroHash,
		"consent":            map[string]any{"approved": []string{}, "denied": []string{}},
		"collection": map[string]any{
			"networkAccess": false, "arbitraryShellExecution": false,
			"startedAt": "2026-01-01T00:00:00Z", "completedAt": "2026-01-01T00:00:01Z",
		},
		"transformations": map[string]any{"ruleset": "r", "detectorsExecuted": 0, "transformationsApplied": 0},
		"artifact":        map[string]any{"manifestHash": oneHash},
	}
	if err := s["disclosure-receipt-0.1"].Validate(receipt); err == nil {
		t.Error("receipt with malformed request hash was accepted")
	}
}

func repeat(c string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(c)
	}
	return b.String()
}
