// Package packaging builds the diagnostic artifact: a ZIP-backed archive
// with the canonical logical layout (spec section 9), the SHA-256
// manifest (spec section 10) and the disclosure receipt (spec section 8).
package packaging

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/diagx/diagx/internal/collection"
	"github.com/diagx/diagx/internal/safezip"
	"github.com/diagx/diagx/internal/transform"
	"github.com/diagx/diagx/pkg/protocol"
)

// Input is everything needed to build one artifact.
type Input struct {
	Request      *protocol.DiagnosticRequest
	Decision     *protocol.ConsentDecision
	Plan         *protocol.EffectiveDisclosurePlan
	Collection   *protocol.CollectionReport
	Transform    *protocol.TransformationReport
	Files        map[string]collection.CollectedFile // logical path -> transformed file
	ManifestMeta map[string]ManifestMeta             // logical path -> collector metadata
	Warnings     []string
	Findings     []protocol.Finding
	CollectorVer map[string]string // collector id -> version
}

type ManifestMeta struct {
	Collector        string
	CollectorVersion string
	Transformed      bool
	Truncated        bool
}

// defaultMetaFor maps a logical path to reasonable defaults.
func defaultMetaFor(path string, files map[string]collection.CollectedFile) ManifestMeta {
	f, ok := files[path]
	return ManifestMeta{
		Collector:        "diagx",
		CollectorVersion: collection.CollectorVersion,
		Transformed:      true, // every data file is passed through the ruleset
		Truncated:        ok && f.Truncated,
	}
}

// Build writes the diagnostic artifact to outPath. It also returns the
// disclosure receipt (for display/verification purposes).
func Build(outPath string, in *Input) (*protocol.DisclosureReceipt, error) {
	if in.Request == nil || in.Plan == nil || in.Collection == nil || in.Transform == nil {
		return nil, fmt.Errorf("packaging: missing required inputs")
	}
	now := time.Now().UTC().Format(time.RFC3339)

	requestBytes, err := protocol.CanonicalJSON(in.Request)
	if err != nil {
		return nil, fmt.Errorf("canonicalize request: %w", err)
	}
	planBytes, err := protocol.CanonicalJSON(in.Plan)
	if err != nil {
		return nil, fmt.Errorf("canonicalize plan: %w", err)
	}
	collectionBytes, err := json.MarshalIndent(in.Collection, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal collection report: %w", err)
	}
	transformBytes, err := json.MarshalIndent(in.Transform, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal transformation report: %w", err)
	}
	warnings := &protocol.Warnings{Warnings: in.Warnings}
	if warnings.Warnings == nil {
		warnings.Warnings = []string{}
	}
	warningsBytes, err := json.MarshalIndent(warnings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal warnings: %w", err)
	}
	findings := &protocol.FindingsReport{Findings: in.Findings}
	if findings.Findings == nil {
		findings.Findings = []protocol.Finding{}
	}
	findingsBytes, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal findings: %w", err)
	}

	// Materialize transformed files on disk in a temp dir so the zip
	// writer can hash-and-store them consistently.
	tmp, err := os.MkdirTemp("", "diagx-artifact-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	// Write report documents to disk (these are not passed through the
	// privacy ruleset: they contain no original values by construction).
	docFiles := map[string][]byte{
		protocol.FileRequest:         requestBytes,
		protocol.FileDisclosure:      planBytes,
		protocol.FileCollection:      collectionBytes,
		protocol.FileTransformations: transformBytes,
		protocol.FileWarnings:        warningsBytes,
		protocol.FileFindings:        findingsBytes,
	}
	for name, data := range docFiles {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(tmp, name)), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o644); err != nil {
			return nil, err
		}
	}

	// Manifest over every entry except the disclosure receipt.
	entries := []protocol.ManifestEntry{}
	addEntry := func(path string) error {
		info, err := os.Lstat(filepath.Join(tmp, path))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(tmp, path))
		if err != nil {
			return err
		}
		meta, ok := in.ManifestMeta[path]
		if !ok {
			meta = ManifestMeta{}
		}
		if meta.Collector == "" {
			meta = defaultMetaFor(path, in.Files)
			// Root-level documents are not "collected" data.
			if !strings.HasPrefix(path, protocol.DirData+"/") {
				meta.Collector = "diagx"
				meta.CollectorVersion = collection.CollectorVersion
				meta.Transformed = false
			}
		}
		entries = append(entries, protocol.ManifestEntry{
			Path:             path,
			MediaType:        mediaTypeFor(path),
			Size:             info.Size(),
			SHA256:           protocol.SHA256(data),
			Collector:        meta.Collector,
			CollectorVersion: meta.CollectorVersion,
			CollectedAt:      collectedAtFor(in, path),
			Transformed:      meta.Transformed,
			Truncated:        meta.Truncated,
		})
		return nil
	}

	// Data files (already transformed by the pipeline).
	for path, f := range in.Files {
		dst := filepath.Join(tmp, path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, f.Content, 0o644); err != nil {
			return nil, err
		}
	}
	// Stable order: sorted logical paths.
	var allPaths []string
	for p := range docFiles {
		allPaths = append(allPaths, p)
	}
	for p := range in.Files {
		allPaths = append(allPaths, p)
	}
	sort.Strings(allPaths)
	total := int64(0)
	for _, p := range allPaths {
		if err := addEntry(p); err != nil {
			return nil, fmt.Errorf("manifest: %s: %w", p, err)
		}
		total += entries[len(entries)-1].Size
	}

	manifest := &protocol.Manifest{
		ProtocolVersion: protocol.ProtocolVersion,
		RequestID:       in.Request.RequestID(),
		GeneratedAt:     now,
		TotalBytes:      total,
		Entries:         entries,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, protocol.FileManifest), manifestBytes, 0o644); err != nil {
		return nil, err
	}
	manifestHash, err := protocol.HashDocument(manifestBytes)
	if err != nil {
		return nil, err
	}
	requestHash, err := protocol.HashDocument(requestBytes)
	if err != nil {
		return nil, err
	}
	planHash, err := protocol.HashDocument(planBytes)
	if err != nil {
		return nil, err
	}

	receipt := &protocol.DisclosureReceipt{
		ProtocolVersion:    protocol.ProtocolVersion,
		Request:            protocol.ReceiptRequest{ID: in.Request.RequestID(), Hash: requestHash},
		DisclosurePlanHash: planHash,
		Consent: protocol.ReceiptConsent{
			Approved:  in.Plan.Approved,
			Denied:    in.Plan.Denied,
			Forbidden: in.Plan.Forbidden,
		},
		Collection: protocol.ReceiptCollection{
			NetworkAccess:           in.Plan.NetworkAccess,
			ArbitraryShellExecution: in.Request.Policy.ArbitraryShellExecution,
			StartedAt:               in.Collection.StartedAt,
			CompletedAt:             in.Collection.CompletedAt,
		},
		Transformations: protocol.ReceiptTransformations{
			Ruleset:                in.Transform.Ruleset,
			DetectorsExecuted:      in.Transform.DetectorsExecuted,
			TransformationsApplied: in.Transform.TransformationsApplied,
		},
		Artifact: protocol.ReceiptArtifact{ManifestHash: manifestHash},
	}
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(tmp, protocol.DirAttestations), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, protocol.FileDisclosureReceipt), receiptBytes, 0o644); err != nil {
		return nil, err
	}

	// Zip everything.
	outDir := filepath.Dir(outPath)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	tmpOut, err := os.CreateTemp(outDir, ".diagnostic.tmp-")
	if err != nil {
		return nil, err
	}
	tmpOutName := tmpOut.Name()
	_ = tmpOut.Close()
	_ = os.Remove(tmpOutName)

	zw, err := safezip.Create(tmpOutName)
	if err != nil {
		return nil, err
	}
	for _, p := range allPaths {
		if _, err := zw.AddFile(p, filepath.Join(tmp, p)); err != nil {
			_ = zw.Close()
			os.Remove(tmpOutName)
			return nil, err
		}
	}
	if _, err := zw.AddFile(protocol.FileManifest, filepath.Join(tmp, protocol.FileManifest)); err != nil {
		_ = zw.Close()
		os.Remove(tmpOutName)
		return nil, err
	}
	if _, err := zw.AddFile(protocol.FileDisclosureReceipt, filepath.Join(tmp, protocol.FileDisclosureReceipt)); err != nil {
		_ = zw.Close()
		os.Remove(tmpOutName)
		return nil, err
	}
	if err := zw.Finish(); err != nil {
		os.Remove(tmpOutName)
		return nil, err
	}
	if err := os.Rename(tmpOutName, outPath); err != nil {
		os.Remove(tmpOutName)
		return nil, err
	}
	return receipt, nil
}

// DefaultOutputName derives the artifact file name from the request.
func DefaultOutputName(req *protocol.DiagnosticRequest, outDir string) string {
	id := sanitizeFilePart(req.RequestID())
	if id == "" {
		id = "support"
	}
	if outDir == "" {
		outDir = "."
	}
	return filepath.Join(outDir, "support-"+id+protocol.ArtifactExt)
}

func sanitizeFilePart(s string) string {
	var b []byte
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b = append(b, byte(r))
		} else if r == ' ' || r == '_' {
			b = append(b, '-')
		}
	}
	return string(b)
}

func mediaTypeFor(path string) string {
	switch {
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	case strings.HasSuffix(path, ".txt"), strings.HasSuffix(path, ".log"):
		return "text/plain"
	}
	return "application/octet-stream"
}

func collectedAtFor(in *Input, path string) string {
	f, ok := in.Files[path]
	if !ok {
		return ""
	}
	return f.CollectedAt.Format(time.RFC3339)
}

// NewSalt returns a fresh random per-artifact salt for pseudonymization.
func NewSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// BuildRuleset combines the default ruleset with optional user-defined
// detectors (name/pattern/action).
func BuildRuleset(extra []ExtraDetector) (transform.Ruleset, error) {
	rs := transform.DefaultRuleset()
	for _, e := range extra {
		if !e.Action.Valid() {
			return rs, fmt.Errorf("extra detector %q: invalid action %q", e.Name, e.Action)
		}
		if e.Pattern == "" {
			return rs, fmt.Errorf("extra detector %q: empty pattern", e.Name)
		}
		rs.Rules = append(rs.Rules, transform.Rule{
			Detector:    "custom:" + e.Name,
			Pattern:     e.Pattern,
			Action:      e.Action,
			ReplaceWith: e.ReplaceWith,
			TruncateTo:  e.TruncateTo,
			Required:    true,
		})
	}
	return rs, nil
}

// ExtraDetector is a user-defined detector (spec section 12).
type ExtraDetector struct {
	Name        string
	Pattern     string
	Action      transform.Action
	ReplaceWith string
	TruncateTo  int
}
