package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validRequest = `
protocolVersion: "0.1"
request: {id: CASE-1}
requester: {name: Support}
purpose: {code: test, description: Test request}
capabilities:
  system.os: {requirement: optional}
policy:
  networkAccess: false
  arbitraryShellExecution: false
`

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.yaml")
	bad := strings.Replace(validRequest, "networkAccess", "networkAcess", 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown YAML field must be rejected")
	}
}

func TestLoadJSONRejectsUnknownField(t *testing.T) {
	data := `{"protocolVersion":"0.1","request":{"id":"CASE-1"},"requester":{"name":"Support"},"purpose":{"code":"test","description":"Test"},"capabilities":{"system.os":{"requirement":"optional"}},"policy":{"networkAccess":false,"arbitraryShellExecution":false,"networkAcess":true}}`
	if _, err := LoadJSON([]byte(data)); err == nil {
		t.Fatal("unknown JSON field must be rejected")
	}
}

func TestLoadValidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.yaml")
	if err := os.WriteFile(path, []byte(validRequest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}
