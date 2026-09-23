package protocol

import (
	"strings"
	"testing"
)

func TestCanonicalJSONStableAcrossKeyOrder(t *testing.T) {
	a := `{"b":1,"a":{"d":2,"c":3}}`
	b := `{"a":{"c":3,"d":2},"b":1}`
	ca, err := CanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("canonical forms differ:\n%s\n%s", ca, cb)
	}
	want := `{"a":{"c":3,"d":2},"b":1}`
	if string(ca) != want {
		t.Fatalf("unexpected canonical form: %s", ca)
	}
}

func TestCanonicalJSONWhitespace(t *testing.T) {
	a := `{ "x" : [ 1 , 2 , 3 ] }`
	b := `{"x":[1,2,3]}`
	ca, _ := CanonicalJSON(a)
	cb, _ := CanonicalJSON(b)
	if string(ca) != string(cb) {
		t.Fatalf("whitespace changed the canonical form: %s vs %s", ca, cb)
	}
}

func TestCanonicalJSONTrailingDataRejected(t *testing.T) {
	if _, err := CanonicalJSON(`{"a":1} extra`); err == nil {
		t.Fatal("expected error for trailing data")
	}
	if _, err := CanonicalJSON(`{"a":1}{"b":2}`); err == nil {
		t.Fatal("expected error for second document")
	}
}

func TestHashDocumentDeterministic(t *testing.T) {
	h1, err := HashDocument(map[string]any{"k1": []any{float64(1), "two"}, "k2": true})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashDocument(`{"k2":true,"k1":[1,"two"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("same document, different hashes: %s vs %s", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") || len(h1) != len("sha256:")+64 {
		t.Fatalf("bad hash format: %s", h1)
	}
}

func TestRequestValidation(t *testing.T) {
	valid := `
protocolVersion: "0.1"
request: {id: CASE-1}
requester: {name: Support}
purpose: {code: x, description: y}
capabilities:
  system.os: {requirement: required_for_case}
policy: {networkAccess: false, arbitraryShellExecution: false}
`
	req, err := loadYAML(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	badShell := strings.Replace(valid, "arbitraryShellExecution: false", "arbitraryShellExecution: true", 1)
	req, _ = loadYAML(badShell)
	if err := req.Validate(); err == nil {
		t.Fatal("arbitrary shell execution must be rejected in V0.1")
	}

	badVersion := strings.Replace(valid, `"0.1"`, `"9.9"`, 1)
	req, _ = loadYAML(badVersion)
	if err := req.Validate(); err == nil {
		t.Fatal("unknown protocol version must be rejected")
	}

	badReq := strings.Replace(valid, "system.os: {requirement: required_for_case}", "system.os: {requirement: maybe}", 1)
	req, _ = loadYAML(badReq)
	if err := req.Validate(); err == nil {
		t.Fatal("invalid requirement must be rejected")
	}
}
