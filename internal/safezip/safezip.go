// Package safezip provides defensive ZIP creation and reading for
// diagnostic artifacts. It protects against path traversal (zip slip),
// decompression bombs and oversized entries (spec sections 21 and 56).
package safezip

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	// DefaultMaxEntries bounds the number of entries in an artifact.
	DefaultMaxEntries = 1024
	// DefaultMaxTotalSize bounds the total decompressed size.
	DefaultMaxTotalSize = 256 << 20 // 256 MiB
	// DefaultMaxEntrySize bounds a single decompressed entry.
	DefaultMaxEntrySize = 128 << 20 // 128 MiB
	// DefaultMaxNameLength bounds logical path length.
	DefaultMaxNameLength = 255
)

// Limits bound archive reading.
type Limits struct {
	MaxEntries    int
	MaxTotalSize  int64
	MaxEntrySize  int64
	MaxNameLength int
}

// DefaultLimits returns the default reading limits.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:    DefaultMaxEntries,
		MaxTotalSize:  DefaultMaxTotalSize,
		MaxEntrySize:  DefaultMaxEntrySize,
		MaxNameLength: DefaultMaxNameLength,
	}
}

// entryName is a sanitized logical path inside the archive.
func entryName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty entry name")
	}
	if len(name) > DefaultMaxNameLength {
		return "", fmt.Errorf("entry name too long: %d chars", len(name))
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("entry name %q is not a relative forward-slash path", name)
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("entry name %q escapes the archive root", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", fmt.Errorf("entry name %q contains parent traversal", name)
		}
	}
	return name, nil
}

// Writer wraps a zip writer enforcing per-entry name safety.
type Writer struct {
	z *zip.Writer
	f *os.File
}

// Create opens (or truncates) a ZIP file for writing.
func Create(file string) (*Writer, error) {
	// #nosec G304 -- callers explicitly choose the local artifact output path.
	f, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	zw := zip.NewWriter(f)
	return &Writer{z: zw, f: f}, nil
}

// AddFile writes a file from disk under the given logical name.
func (w *Writer) AddFile(logicalName, diskPath string) (int64, error) {
	name, err := entryName(logicalName)
	if err != nil {
		_ = w.Close()
		return 0, err
	}
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
	hdr.SetMode(0o644)
	fw, err := w.z.CreateHeader(hdr)
	if err != nil {
		_ = w.Close()
		return 0, err
	}
	// #nosec G304 -- diskPath is an internal staging path created by the packager.
	f, err := os.Open(diskPath)
	if err != nil {
		_ = w.Close()
		return 0, err
	}
	defer f.Close()
	n, err := io.Copy(fw, f)
	if err != nil {
		_ = w.Close()
		return 0, err
	}
	return n, nil
}

// AddBytes writes bytes under the given logical name.
func (w *Writer) AddBytes(logicalName string, data []byte) error {
	name, err := entryName(logicalName)
	if err != nil {
		_ = w.Close()
		return err
	}
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
	hdr.SetMode(0o644)
	fw, err := w.z.CreateHeader(hdr)
	if err != nil {
		_ = w.Close()
		return err
	}
	_, err = fw.Write(data)
	return err
}

// Finish closes the underlying zip and file.
func (w *Writer) Finish() error {
	if err := w.z.Close(); err != nil {
		_ = w.f.Close()
		return err
	}
	return w.f.Close()
}

// Close aborts writing (used on error paths).
func (w *Writer) Close() error {
	_ = w.z.Close()
	return w.f.Close()
}

// Reader iterates archive entries with all safety checks applied.
type Reader struct {
	zr  *zip.Reader
	f   *os.File
	lim Limits
}

// Open opens an artifact for safe reading.
func Open(file string, lim Limits) (*Reader, error) {
	// #nosec G304 -- callers explicitly choose the local artifact input path.
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if lim.MaxEntries <= 0 || lim.MaxTotalSize <= 0 || lim.MaxEntrySize <= 0 || lim.MaxNameLength <= 0 {
		lim = DefaultLimits()
	}
	if len(zr.File) > lim.MaxEntries {
		_ = f.Close()
		return nil, fmt.Errorf("archive has %d entries, exceeding limit %d", len(zr.File), lim.MaxEntries)
	}
	var total uint64
	seen := make(map[string]struct{}, len(zr.File))
	for _, e := range zr.File {
		if len(e.Name) > lim.MaxNameLength {
			_ = f.Close()
			return nil, fmt.Errorf("entry name too long: %d chars", len(e.Name))
		}
		if _, err := entryName(e.Name); err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, exists := seen[e.Name]; exists {
			_ = f.Close()
			return nil, fmt.Errorf("archive contains duplicate entry %q", e.Name)
		}
		seen[e.Name] = struct{}{}
		// #nosec G115 -- limits were normalized to strictly positive values above.
		if e.UncompressedSize64 > uint64(lim.MaxEntrySize) {
			_ = f.Close()
			return nil, fmt.Errorf("entry %q decompresses to %d bytes, exceeding limit %d",
				e.Name, e.UncompressedSize64, lim.MaxEntrySize)
		}
		// #nosec G115 -- limits were normalized to strictly positive values above.
		if e.UncompressedSize64 > uint64(lim.MaxTotalSize)-total {
			_ = f.Close()
			return nil, fmt.Errorf("archive decompresses beyond total size limit %d", lim.MaxTotalSize)
		}
		total += e.UncompressedSize64
	}
	// #nosec G115 -- limits were normalized to strictly positive values above.
	if total > uint64(lim.MaxTotalSize) {
		_ = f.Close()
		return nil, fmt.Errorf("archive decompresses to %d bytes total, exceeding limit %d",
			total, lim.MaxTotalSize)
	}
	return &Reader{zr: zr, f: f, lim: lim}, nil
}

// Close releases the archive file.
func (r *Reader) Close() error { return r.f.Close() }

// Names returns all logical entry names.
func (r *Reader) Names() []string {
	out := make([]string, len(r.zr.File))
	for i, e := range r.zr.File {
		out[i] = e.Name
	}
	return out
}

// Find returns the entry with the given name, or nil.
func (r *Reader) Find(name string) *zip.File {
	for _, e := range r.zr.File {
		if e.Name == name {
			return e
		}
	}
	return nil
}

// ReadEntry returns the full bytes of an entry, enforcing size limits and
// validating the logical name.
func (r *Reader) ReadEntry(name string) ([]byte, error) {
	if _, err := entryName(name); err != nil {
		return nil, err
	}
	e := r.Find(name)
	if e == nil {
		return nil, fmt.Errorf("entry %q not found", name)
	}
	f, err := e.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, r.lim.MaxEntrySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > r.lim.MaxEntrySize {
		return nil, fmt.Errorf("entry %q exceeds limit %d while reading", name, r.lim.MaxEntrySize)
	}
	return data, nil
}
