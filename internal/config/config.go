// Package config loads DiagPermit project configuration (diagpermit.yaml).
// YAML is the human authoring format; the canonical representation is
// JSON.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// DefaultFile is the conventional project configuration name.
const DefaultFile = "diagpermit.yaml"

// Load reads a request/project document from YAML or JSON.
func Load(path string) (*protocol.DiagnosticRequest, error) {
	// #nosec G304 -- path is explicitly selected by the local CLI user.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var req protocol.DiagnosticRequest
	// YAML is a superset of JSON, so JSON files work too. KnownFields
	// prevents misspelled security or limit settings from being ignored.
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parsing %s: multiple YAML documents are not allowed", path)
		}
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

// LoadJSON decodes a request document from JSON bytes (used for tests
// and conformance vectors).
func LoadJSON(b []byte) (*protocol.DiagnosticRequest, error) {
	var req protocol.DiagnosticRequest
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values are not allowed")
		}
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}
