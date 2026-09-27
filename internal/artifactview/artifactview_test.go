package artifactview

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/safezip"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func TestPreviewIsManifestBoundAndReturnsInertText(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "preview.diagnostic")
	w, err := safezip.Create(artifact)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`<script>window.location='https://example.test'</script>`)
	manifest := protocol.Manifest{ProtocolVersion: protocol.ProtocolVersion, Entries: []protocol.ManifestEntry{{Path: "data/example.html", MediaType: "text/html", Size: int64(len(content))}}}
	manifestJSON, _ := json.Marshal(manifest)
	if err := w.AddBytes(protocol.FileManifest, manifestJSON); err != nil {
		t.Fatal(err)
	}
	if err := w.AddBytes("data/example.html", content); err != nil {
		t.Fatal(err)
	}
	if err := w.AddBytes("data/unlisted.txt", []byte("must not be readable")); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	got, err := Preview(artifact, "data/example.html")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(content) {
		t.Fatalf("preview changed content: %q", got)
	}
	if _, err := Preview(artifact, "data/unlisted.txt"); err == nil {
		t.Fatal("unlisted file was previewed")
	}
	if _, err := Preview(artifact, "../../secret"); err == nil {
		t.Fatal("traversal name was accepted")
	}
}
