// Package config loads DiagX project configuration (diagx.yaml).
// YAML is the human authoring format; the canonical representation is
// JSON (spec section 38).
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/diagx/diagx/pkg/protocol"
)

// DefaultFile is the conventional project configuration name.
const DefaultFile = "diagx.yaml"

// Load reads a request/project document from YAML or JSON.
func Load(path string) (*protocol.DiagnosticRequest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var req protocol.DiagnosticRequest
	// Try YAML first; YAML is a superset of JSON, so JSON files work too.
	if err := yaml.Unmarshal(b, &req); err != nil {
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
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}
