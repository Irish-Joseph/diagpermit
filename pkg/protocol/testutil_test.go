package protocol

import (
	"gopkg.in/yaml.v3"
)

// loadYAML decodes YAML for tests (YAML is the human authoring format).
func loadYAML(s string) (*DiagnosticRequest, error) {
	var req DiagnosticRequest
	if err := yaml.Unmarshal([]byte(s), &req); err != nil {
		return nil, err
	}
	return &req, nil
}
