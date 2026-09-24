package application

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func TestCollectBoundedLogTail(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	if err := os.Mkdir("logs", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("logs", "app.log"), []byte("one\ntwo\nthree\nfour\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := &protocol.DiagnosticRequest{Local: &protocol.LocalConfig{ApplicationLogPath: filepath.Join("logs", "app.log")}}
	got := New().Collect(&collection.Context{
		Ctx: context.Background(), Request: req, Capability: CapabilityLogs,
		Constraints: &protocol.Constraints{MaxLines: 2, MaxBytes: 1024},
	})
	if got.Status != protocol.StatusSuccess {
		t.Fatalf("status = %q: %s", got.Status, got.Message)
	}
	content := string(got.Files["data/application/logs.txt"].Content)
	if strings.Contains(content, "one") || !strings.Contains(content, "three") || !strings.Contains(content, "four") {
		t.Fatalf("unexpected tail: %q", content)
	}
}

func TestCollectWithoutConfiguredLog(t *testing.T) {
	got := New().Collect(&collection.Context{Ctx: context.Background(), Request: &protocol.DiagnosticRequest{}})
	if got.Status != protocol.StatusSkipped {
		t.Fatalf("status = %q, want skipped", got.Status)
	}
}
