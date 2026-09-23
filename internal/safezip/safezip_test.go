package safezip

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func itoa(i int) string { return fmt.Sprintf("%d", i) }

func makeZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.diagnostic")
	w, err := Create(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range entries {
		if err := w.AddBytes(name, []byte(content)); err != nil {
			t.Fatalf("entry %q: %v", name, err)
		}
	}
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWriteAndReadRoundTrip(t *testing.T) {
	p := makeZip(t, map[string]string{
		"manifest.json": `{"x":1}`,
		"data/a.txt":    "hello",
	})
	r, err := Open(p, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := r.ReadEntry("data/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatalf("bad content: %q", b)
	}
}

func TestRejectTraversalNames(t *testing.T) {
	cases := []string{
		"../evil.txt",
		"../../etc/passwd",
		"a/../../b.txt",
		"/absolute.txt",
		"back\\slash.txt",
	}
	for _, name := range cases {
		if _, err := entryName(name); err == nil {
			t.Errorf("entryName(%q) must fail", name)
		}
	}
	if p, err := entryName("data/a.txt"); err != nil || p != "data/a.txt" {
		t.Fatalf("entryName valid case failed: %q %v", p, err)
	}
}

func TestOpenRejectsTraversalEntries(t *testing.T) {
	// Create a hostile archive directly with archive/zip.
	dir := t.TempDir()
	p := filepath.Join(dir, "hostile.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zf := zip.NewWriter(f)
	zw := zf
	if _, err := zw.Create("../evil.txt"); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()
	if r, err := Open(p, DefaultLimits()); err == nil {
		_ = r.Close()
		t.Fatal("archive with traversal entry must be rejected")
	}
}

func TestOpenRejectsDuplicateEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "duplicate.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for i := 0; i < 2; i++ {
		w, err := zw.Create("data/same.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("content")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if r, err := Open(p, DefaultLimits()); err == nil {
		_ = r.Close()
		t.Fatal("archive with duplicate entries must be rejected")
	}
}

func TestOpenRejectsOversizedEntry(t *testing.T) {
	p := makeZip(t, map[string]string{
		"big.txt": strings.Repeat("a", 1024*1024),
	})
	lim := DefaultLimits()
	lim.MaxEntrySize = 100
	lim.MaxTotalSize = 200
	if _, err := Open(p, lim); err == nil {
		t.Fatal("oversized entry must be rejected")
	}
}

func TestOpenRejectsTooManyEntries(t *testing.T) {
	entries := map[string]string{}
	for i := 0; i < 10; i++ {
		entries[itoa(i)+".txt"] = "x"
	}
	p := makeZip(t, entries)
	lim := DefaultLimits()
	lim.MaxEntries = 5
	if _, err := Open(p, lim); err == nil {
		t.Fatal("too many entries must be rejected")
	}
}

func TestCorruptedZip(t *testing.T) {
	p := makeZip(t, map[string]string{"a.txt": "hello"})
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the local file header signature.
	for i := 0; i < len(b)-4; i++ {
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 3 && b[i+3] == 4 {
			b[i+1] = 'X'
			break
		}
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.zip")
	if err := os.WriteFile(corrupt, b, 0o644); err != nil {
		t.Fatal(err)
	}
	r0, err := Open(corrupt, DefaultLimits())
	if err != nil {
		return // rejected up front: even better
	}
	_ = r0.Close()
	r, err := Open(corrupt, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadEntry("a.txt"); err == nil {
		t.Fatal("reading from a corrupted archive must fail")
	}
	_ = r.Close()
}
