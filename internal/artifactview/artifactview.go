// Package artifactview exposes a read-only, security-bounded view of a
// .diagnostic archive for both the CLI and local visual viewer.
package artifactview

import (
	"encoding/json"
	"fmt"
	"mime"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Irish-Joseph/diagpermit/internal/requestauth"
	"github.com/Irish-Joseph/diagpermit/internal/safezip"
	"github.com/Irish-Joseph/diagpermit/internal/verification"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

const MaxPreviewBytes = 256 << 10

type File struct {
	Path        string `json:"path"`
	MediaType   string `json:"mediaType"`
	Size        int64  `json:"size"`
	Transformed bool   `json:"transformed"`
	Truncated   bool   `json:"truncated"`
	Previewable bool   `json:"previewable"`
}

type Snapshot struct {
	Request         protocol.DiagnosticRequest       `json:"request"`
	Plan            protocol.EffectiveDisclosurePlan `json:"plan"`
	Collection      protocol.CollectionReport        `json:"collection"`
	Transformations protocol.TransformationReport    `json:"transformations"`
	Receipt         protocol.DisclosureReceipt       `json:"receipt"`
	Manifest        protocol.Manifest                `json:"manifest"`
	Findings        []protocol.Finding               `json:"findings"`
	Warnings        []string                         `json:"warnings"`
	Files           []File                           `json:"files"`
	Verification    *verification.Report             `json:"verification"`
	Authentication  *requestauth.Result              `json:"authentication,omitempty"`
}

func Open(artifactPath string) (*Snapshot, error) {
	return OpenWithTrust(artifactPath, nil)
}

// OpenWithTrust opens an artifact and evaluates an embedded DSSE request
// envelope against an explicit local trust store when one is supplied.
func OpenWithTrust(artifactPath string, trust *requestauth.TrustStore) (*Snapshot, error) {
	report, err := verification.Verify(artifactPath)
	if err != nil {
		return nil, err
	}
	zr, err := safezip.Open(artifactPath, safezip.DefaultLimits())
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	s := &Snapshot{Verification: report}
	read := func(name string, dst any) error {
		b, err := zr.ReadEntry(name)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
		return nil
	}
	for _, item := range []struct {
		name string
		dst  any
	}{{protocol.FileRequest, &s.Request}, {protocol.FileDisclosure, &s.Plan}, {protocol.FileCollection, &s.Collection}, {protocol.FileTransformations, &s.Transformations}, {protocol.FileDisclosureReceipt, &s.Receipt}, {protocol.FileManifest, &s.Manifest}} {
		if err := read(item.name, item.dst); err != nil {
			return nil, err
		}
	}
	var findings protocol.FindingsReport
	if zr.Find(protocol.FileFindings) != nil {
		if err := read(protocol.FileFindings, &findings); err != nil {
			return nil, err
		}
	}
	s.Findings = findings.Findings
	var warnings protocol.Warnings
	if err := read(protocol.FileWarnings, &warnings); err != nil {
		return nil, err
	}
	s.Warnings = warnings.Warnings
	if zr.Find(protocol.FileRequestEnvelope) != nil {
		envelope, err := zr.ReadEntry(protocol.FileRequestEnvelope)
		if err != nil {
			return nil, err
		}
		result := requestauth.Verify(envelope, trust)
		envelopeHash, envelopeErr := protocol.HashDocument(result.Payload)
		requestHash, requestErr := protocol.HashDocument(s.Request)
		if result.Request == nil || envelopeErr != nil || requestErr != nil || envelopeHash != requestHash {
			result.Status = requestauth.StatusInvalid
			result.Label = "SIGNATURE INVALID"
			result.Detail = "DSSE payload does not match request.json."
		}
		s.Authentication = &result
	}
	for _, entry := range s.Manifest.Entries {
		s.Files = append(s.Files, File{Path: entry.Path, MediaType: entry.MediaType, Size: entry.Size, Transformed: entry.Transformed, Truncated: entry.Truncated, Previewable: previewable(entry.Path, entry.MediaType, entry.Size)})
	}
	sort.Slice(s.Files, func(i, j int) bool { return s.Files[i].Path < s.Files[j].Path })
	return s, nil
}

// Preview returns inert UTF-8 text only. Browsers receive it inside JSON and
// the UI renders it as text, never as HTML.
func Preview(artifactPath, name string) (string, error) {
	zr, err := safezip.Open(artifactPath, safezip.DefaultLimits())
	if err != nil {
		return "", err
	}
	defer zr.Close()
	var manifest protocol.Manifest
	b, err := zr.ReadEntry(protocol.FileManifest)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return "", err
	}
	var found *protocol.ManifestEntry
	for i := range manifest.Entries {
		if manifest.Entries[i].Path == name {
			found = &manifest.Entries[i]
			break
		}
	}
	if found == nil {
		return "", fmt.Errorf("file is not covered by the artifact manifest")
	}
	if !previewable(found.Path, found.MediaType, found.Size) {
		return "", fmt.Errorf("file is not safe for text preview")
	}
	b, err = zr.ReadEntry(name)
	if err != nil {
		return "", err
	}
	if len(b) > MaxPreviewBytes || !utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0 {
		return "", fmt.Errorf("file is not safe for text preview")
	}
	return string(b), nil
}

func previewable(name, mediaType string, size int64) bool {
	if size < 0 || size > MaxPreviewBytes {
		return false
	}
	mt, _, _ := mime.ParseMediaType(mediaType)
	if strings.HasPrefix(mt, "text/") || mt == "application/json" || mt == "application/yaml" {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json", ".log", ".txt", ".yaml", ".yml", ".md", ".csv":
		return true
	}
	return false
}
