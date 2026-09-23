package conformance

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/internal/pipeline"
)

// setRegistryForTest swaps the collector registry for the duration of a
// test and returns a restore function.
func setRegistryForTest(t *testing.T, collectors []collection.Collector) func() {
	t.Helper()
	prev := pipeline.RegistryFactory()
	pipeline.SetRegistryFactory(func() *collection.Registry {
		return collection.NewRegistry(collectors...)
	})
	return func() { pipeline.SetRegistryFactory(prev) }
}

// rewriteArchiveEntry returns a copy of in where entry name has new
// content (used to create deterministic tampering vectors).
func rewriteArchiveEntry(t *testing.T, in, name, content string) string {
	t.Helper()
	f, err := os.Open(in)
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
	outPath := filepath.Join(t.TempDir(), "tampered.diagnostic")
	of, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(of)
	for _, e := range zr.File {
		fw, err := zw.CreateHeader(&e.FileHeader)
		if err != nil {
			t.Fatal(err)
		}
		if e.Name == name {
			if _, err := fw.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		r, err := e.Open()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(fw, r)
		_ = r.Close()
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := of.Close(); err != nil {
		t.Fatal(err)
	}
	return outPath
}
