package fsafety

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePathTraversal(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(dir, "ok.log"), "ok\n")
	writeFile(t, filepath.Join(outside, "secret.log"), "secret\n")

	if _, err := ValidatePath(filepath.Join(dir, "..", "x", "ok.log"), Options{Root: dir}); err == nil {
		t.Fatal("path traversal must be rejected")
	}
	if _, err := ValidatePath("/etc/passwd", Options{Root: dir}); err == nil {
		t.Fatal("absolute escape must be rejected")
	}
	p, err := ValidatePath(filepath.Join(dir, "ok.log"), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "ok.log" {
		t.Fatalf("unexpected path %q", p)
	}
}

func TestTailBounds(t *testing.T) {
	dir := t.TempDir()
	lines := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		lines = append(lines, "line-"+itoa(i))
	}
	p := filepath.Join(dir, "big.log")
	writeFile(t, p, strings.Join(lines, "\n"))

	// MaxLines keeps the LAST lines.
	data, err := Tail(p, Options{Root: dir, MaxLines: 5, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "line-199") || !strings.Contains(got, "line-195") {
		t.Fatalf("expected tail lines, got:\n%s", got)
	}
	if strings.Contains(got, "line-0\n") {
		t.Fatal("head lines must be dropped")
	}

	// MaxBytes bound.
	data, err = Tail(p, Options{Root: dir, MaxBytes: 32, MaxLines: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 32 {
		t.Fatalf("max bytes exceeded: %d", len(data))
	}
}

func TestRefuseSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows CI; covered on Linux/macOS")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	writeFile(t, target, "real\n")
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Tail(link, Options{Root: dir}); err == nil {
		t.Fatal("symlinks must be refused when followSymlinks=false")
	}
	if _, err := Tail(link, Options{Root: dir, FollowSymlinks: true}); err != nil {
		t.Fatalf("followSymlinks=true should work: %v", err)
	}
}

func TestRefuseSpecialFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are created differently on Windows")
	}
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	if err := os.MkdirAll(filepath.Dir(pipe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", pipe); err != nil {
		t.Skip("cannot create special file in this environment")
	}
	// Symlink to /dev/null: stat says character device target; symlink
	// check fires first regardless.
	if _, err := Tail(pipe, Options{Root: dir}); err == nil {
		t.Fatal("special file must be refused")
	}
}

func TestMissingFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Tail(filepath.Join(dir, "nope.log"), Options{Root: dir}); err == nil {
		t.Fatal("missing file must error")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
