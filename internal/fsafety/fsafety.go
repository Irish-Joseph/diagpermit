// Package fsafety implements the filesystem protections required of
// file-reading collectors (spec section 21): no symlink following by
// default, bounds on file sizes, refusal of special files, and a
// mandatory allowed root.
package fsafety

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Options bound a safe file read.
type Options struct {
	// Root is the directory the file must live under.
	Root string
	// MaxBytes bounds the number of bytes returned.
	MaxBytes int64
	// MaxLines bounds the number of trailing lines returned (0 = no limit).
	// When set, the LAST MaxLines lines are kept (tail semantics) because
	// recent lines are usually the relevant ones for troubleshooting.
	MaxLines int
	// FollowSymlinks is false by default (spec section 21).
	FollowSymlinks bool
}

// ValidatePath ensures p is a regular file inside root, is not a symlink
// (unless permitted) and is not a special file. It returns the resolved
// path to read.
func ValidatePath(p string, opts Options) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(opts.Root)
	if err != nil {
		return "", err
	}
	rootAbs = filepath.Clean(rootAbs)
	if rootAbs != filepath.VolumeName(rootAbs) {
		rel, err := filepath.Rel(rootAbs, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("path %q escapes allowed root %q", p, rootAbs)
		}
	}
	if !opts.FollowSymlinks {
		p := abs
		for {
			if l, err := os.Lstat(p); err == nil && l.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%s is a symlink; symlink following is disabled", p)
			}
			dp := filepath.Dir(p)
			if dp == p {
				break
			}
			p = dp
		}
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file (refusing special files, devices, named pipes)", abs)
	}
	return abs, nil
}

// Tail reads up to MaxBytes bytes from the end of the file, applies the
// line bound (keeping the last MaxLines lines) and returns the content.
func Tail(path string, opts Options) ([]byte, error) {
	abs, err := ValidatePath(path, opts)
	if err != nil {
		return nil, err
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 1 << 20 // hard default cap: 1 MiB
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > opts.MaxBytes {
		// Seek to the last MaxBytes.
		if _, err := f.Seek(info.Size()-opts.MaxBytes, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, opts.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > opts.MaxBytes {
		data = data[int(int64(len(data))-opts.MaxBytes):]
	}
	if opts.MaxLines > 0 {
		lines := strings.Split(string(data), "\n")
		if len(lines) > opts.MaxLines {
			lines = lines[len(lines)-opts.MaxLines:]
		}
		data = []byte(strings.Join(lines, "\n"))
	}
	return data, nil
}

// Supported reports whether the Go runtime supports the current OS for
// the typed system collectors. V0.1 targets Linux, Windows and macOS.
func Supported() bool {
	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		return true
	}
	return false
}
