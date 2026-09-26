// Package protocol defines the canonical data types of the DiagPermit
// consent-driven diagnostic exchange protocol (protocol version 0.1).
//
// These types are the single source of truth shared by the CLI, the
// collectors, the transformation engine, the packaging code and the
// verification code. The canonical wire representation is JSON; YAML is
// supported only for human authoring.
package protocol

import (
	"fmt"
	"strings"
	"time"
)

// ProtocolVersion is the version of the diagnostic exchange protocol
// implemented by this package. The protocol version and the CLI version
// are independent.
const ProtocolVersion = "0.1"

// RulesetDefault is the identifier of the built-in privacy transformation
// ruleset shipped with V0.1.
const RulesetDefault = "diagpermit-default-0.1"

// Requirement states how a requester classifies a capability.
type Requirement string

// Capability requirements. required_for_case does NOT grant the requester
// any permission to bypass the user: it only records the requester's
// belief that the information is necessary for the case.
const (
	RequirementRequiredForCase Requirement = "required_for_case"
	RequirementOptional        Requirement = "optional"
	RequirementForbidden       Requirement = "forbidden"
	RequirementNotRequested    Requirement = "not_requested"
)

// Valid reports whether the requirement is one of the four defined states.
func (r Requirement) Valid() bool {
	switch r {
	case RequirementRequiredForCase, RequirementOptional,
		RequirementForbidden, RequirementNotRequested:
		return true
	}
	return false
}

// Capability is one declared diagnostic capability.
type Capability struct {
	Requirement Requirement  `json:"requirement" yaml:"requirement"`
	Constraints *Constraints `json:"constraints,omitempty" yaml:"constraints,omitempty"`
}

// Constraints bound how a capability may be collected.
type Constraints struct {
	// MaxLines limits line-based output (e.g. application logs).
	MaxLines int `json:"maxLines,omitempty" yaml:"maxLines,omitempty"`
	// MaxBytes limits the byte size of the collected data.
	MaxBytes int `json:"maxBytes,omitempty" yaml:"maxBytes,omitempty"`
	// Since is an optional lower bound (RFC 3339) for time-windowed collection.
	Since string `json:"since,omitempty" yaml:"since,omitempty"`
}

// Policy carries the hard limits and global switches that apply to a
// collection run.
type Policy struct {
	// NetworkAccess must be false unless a network-capable collector is
	// explicitly declared AND the user approves the connection.
	NetworkAccess bool `json:"networkAccess" yaml:"networkAccess"`
	// ArbitraryShellExecution must be false in V0.1. The reference
	// implementation refuses requests that set it to true.
	ArbitraryShellExecution bool `json:"arbitraryShellExecution" yaml:"arbitraryShellExecution"`
	// MaximumTotalBytes bounds the total size of collected (pre-package)
	// data.
	MaximumTotalBytes int `json:"maximumTotalBytes,omitempty" yaml:"maximumTotalBytes,omitempty"`
	// MaximumDurationSeconds bounds the whole collection run.
	MaximumDurationSeconds int `json:"maximumDurationSeconds,omitempty" yaml:"maximumDurationSeconds,omitempty"`
}

// RetentionNotice is a free-text declaration by the requester. DiagPermit only
// records the declaration; it does not enforce retention behaviour by
// third parties that later receive the artifact.
type RetentionNotice struct {
	Text string `json:"text" yaml:"text"`
}

// Requester identifies the party asking for diagnostics.
type Requester struct {
	Organization string `json:"organization,omitempty" yaml:"organization,omitempty"`
	Name         string `json:"name" yaml:"name"`
}

// Purpose explains why the information is needed.
type Purpose struct {
	Code        string `json:"code" yaml:"code"`
	Description string `json:"description" yaml:"description"`
}

// ExtraDetector is a user-defined privacy detector.
type ExtraDetector struct {
	Name        string `json:"name" yaml:"name"`
	Pattern     string `json:"pattern" yaml:"pattern"`
	Action      string `json:"action" yaml:"action"` // drop|mask|replace|truncate|hash|pseudonymize
	ReplaceWith string `json:"replaceWith,omitempty" yaml:"replaceWith,omitempty"`
	TruncateTo  int    `json:"truncateTo,omitempty" yaml:"truncateTo,omitempty"`
}

// PrivacyConfig configures the local transformation engine.
type PrivacyConfig struct {
	ExtraDetectors []ExtraDetector `json:"extraDetectors,omitempty" yaml:"extraDetectors,omitempty"`
}

// LocalConfig is reference-implementation-local configuration. It is part
// of the request document (and therefore covered by its hash) but carries
// no portable semantics.
type LocalConfig struct {
	// ApplicationLogPath is the local path read by the application.logs collector.
	ApplicationLogPath string `json:"applicationLogPath,omitempty" yaml:"applicationLogPath,omitempty"`
	// OutputDir is where the diagnostic artifact is written.
	OutputDir string `json:"outputDir,omitempty" yaml:"outputDir,omitempty"`
	// Privacy configures user-defined detectors.
	Privacy *PrivacyConfig `json:"privacy,omitempty" yaml:"privacy,omitempty"`
}

// DiagnosticRequest is the canonical V0.1 diagnostic request document.
// It is the first link in the disclosure chain and is stored verbatim
// (canonicalized) inside every diagnostic artifact.
type DiagnosticRequest struct {
	ProtocolVersion string                `json:"protocolVersion" yaml:"protocolVersion"`
	Request         struct{ ID string }   `json:"request" yaml:"request"`
	Requester       Requester             `json:"requester" yaml:"requester"`
	Purpose         Purpose               `json:"purpose" yaml:"purpose"`
	ExpiresAt       string                `json:"expiresAt,omitempty" yaml:"expiresAt,omitempty"`
	Capabilities    map[string]Capability `json:"capabilities" yaml:"capabilities"`
	Policy          Policy                `json:"policy" yaml:"policy"`
	RetentionNotice *RetentionNotice      `json:"retentionNotice,omitempty" yaml:"retentionNotice,omitempty"`
	Local           *LocalConfig          `json:"local,omitempty" yaml:"local,omitempty"`
}

// RequestID returns the stable case/case-reference identifier.
func (d *DiagnosticRequest) RequestID() string {
	if d == nil {
		return ""
	}
	return d.Request.ID
}

// ConsentDecision is the recorded outcome of the user's consent review.
type ConsentDecision struct {
	ProtocolVersion string              `json:"protocolVersion"`
	RequestID       string              `json:"requestId"`
	DecidedAt       time.Time           `json:"decidedAt"`
	Mode            string              `json:"mode"` // "interactive" | "assumed" | "file"
	Decisions       map[string]Decision `json:"decisions"`
}

// Decision is the user's per-capability choice.
type Decision struct {
	State ConsentState `json:"state"`
}

// ConsentState is a user consent state.
type ConsentState string

const (
	ConsentApproved ConsentState = "approved"
	ConsentDenied   ConsentState = "denied"
)

// EffectiveDisclosurePlan is the immutable logical plan computed from the
// request and the user's consent decisions, BEFORE any collection occurs.
// A hash of this document is embedded in the disclosure receipt.
type EffectiveDisclosurePlan struct {
	ProtocolVersion string   `json:"protocolVersion"`
	RequestID       string   `json:"requestId"`
	Approved        []string `json:"approved"`
	Denied          []string `json:"denied"`
	Forbidden       []string `json:"forbidden"`
	NotRequested    []string `json:"notRequested,omitempty"`
	NetworkAccess   bool     `json:"networkAccess"`
	ShellExecution  bool     `json:"shellExecution"`
}

// CollectionStatus is the outcome status of one capability/collector run.
type CollectionStatus string

// Defined collection statuses.
const (
	StatusSuccess           CollectionStatus = "success"
	StatusPartial           CollectionStatus = "partial"
	StatusFailed            CollectionStatus = "failed"
	StatusSkipped           CollectionStatus = "skipped"
	StatusDeniedByUser      CollectionStatus = "denied_by_user"
	StatusForbidden         CollectionStatus = "forbidden"
	StatusUnsupported       CollectionStatus = "unsupported"
	StatusTimedOut          CollectionStatus = "timed_out"
	StatusSizeLimitExceeded CollectionStatus = "size_limit_exceeded"
)

// Valid reports whether s is a defined collection status.
func (s CollectionStatus) Valid() bool {
	switch s {
	case StatusSuccess, StatusPartial, StatusFailed, StatusSkipped,
		StatusDeniedByUser, StatusForbidden, StatusUnsupported,
		StatusTimedOut, StatusSizeLimitExceeded:
		return true
	}
	return false
}

// CollectorResult describes what actually happened for one capability.
type CollectorResult struct {
	Capability       string           `json:"capability"`
	Collector        string           `json:"collector"`
	CollectorVersion string           `json:"collectorVersion"`
	Status           CollectionStatus `json:"status"`
	StartedAt        time.Time        `json:"startedAt"`
	CompletedAt      time.Time        `json:"completedAt"`
	Bytes            int64            `json:"bytes"`
	Files            []string         `json:"files,omitempty"`
	Message          string           `json:"message,omitempty"`
}

// CollectionReport records the full outcome of the collection phase.
type CollectionReport struct {
	ProtocolVersion string            `json:"protocolVersion"`
	RequestID       string            `json:"requestId"`
	StartedAt       time.Time         `json:"startedAt"`
	CompletedAt     time.Time         `json:"completedAt"`
	NetworkAccess   bool              `json:"networkAccess"`
	ShellExecution  bool              `json:"shellExecution"`
	Results         []CollectorResult `json:"results"`
}

// DetectorReport is the per-detector line of the transformation report.
// It must NEVER contain the original sensitive values, only counts and the
// detector identity.
type DetectorReport struct {
	Detector    string `json:"detector"`
	Category    string `json:"category"`
	Executed    bool   `json:"executed"`
	Matches     int    `json:"matches"`
	Transformer string `json:"transformer"` // drop | mask | replace | truncate | hash | pseudonymize
}

// TransformationReport summarises the privacy transformation phase.
type TransformationReport struct {
	ProtocolVersion        string           `json:"protocolVersion"`
	RequestID              string           `json:"requestId"`
	Ruleset                string           `json:"ruleset"`
	DetectorsExecuted      int              `json:"detectorsExecuted"`
	TransformationsApplied int              `json:"transformationsApplied"`
	Detectors              []DetectorReport `json:"detectors"`
	Files                  []string         `json:"files"`
}

// ManifestEntry records every file in the artifact.
type ManifestEntry struct {
	Path             string `json:"path"`
	MediaType        string `json:"mediaType"`
	Size             int64  `json:"size"`
	SHA256           string `json:"sha256"`
	Collector        string `json:"collector"`
	CollectorVersion string `json:"collectorVersion"`
	CollectedAt      string `json:"collectedAt,omitempty"`
	Transformed      bool   `json:"transformed"`
	Truncated        bool   `json:"truncated"`
}

// Manifest is the integrity manifest of a diagnostic artifact.
type Manifest struct {
	ProtocolVersion string          `json:"protocolVersion"`
	RequestID       string          `json:"requestId"`
	GeneratedAt     string          `json:"generatedAt"`
	TotalBytes      int64           `json:"totalBytes"`
	Entries         []ManifestEntry `json:"entries"`
}

// DisclosureReceipt is the disclosure receipt embedded in every artifact
// It answers: what was requested, what was approved,
// what actually ran, and what was ultimately packaged.
type DisclosureReceipt struct {
	ProtocolVersion    string                 `json:"protocolVersion"`
	Request            ReceiptRequest         `json:"request"`
	DisclosurePlanHash string                 `json:"disclosurePlanHash"`
	Consent            ReceiptConsent         `json:"consent"`
	Collection         ReceiptCollection      `json:"collection"`
	Transformations    ReceiptTransformations `json:"transformations"`
	Artifact           ReceiptArtifact        `json:"artifact"`
}

// ReceiptRequest identifies the request document and its hash.
type ReceiptRequest struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
}

// ReceiptConsent mirrors the user decision summary.
type ReceiptConsent struct {
	Approved  []string `json:"approved"`
	Denied    []string `json:"denied"`
	Forbidden []string `json:"forbidden,omitempty"`
}

// ReceiptCollection records what was enforced during collection.
type ReceiptCollection struct {
	NetworkAccess           bool      `json:"networkAccess"`
	ArbitraryShellExecution bool      `json:"arbitraryShellExecution"`
	StartedAt               time.Time `json:"startedAt"`
	CompletedAt             time.Time `json:"completedAt"`
}

// ReceiptTransformations records the transformation phase summary.
type ReceiptTransformations struct {
	Ruleset                string `json:"ruleset"`
	DetectorsExecuted      int    `json:"detectorsExecuted"`
	TransformationsApplied int    `json:"transformationsApplied"`
}

// ReceiptArtifact records what was packaged.
type ReceiptArtifact struct {
	ManifestHash string `json:"manifestHash"`
}

// FindingSeverity is the severity of a deterministic finding.
type FindingSeverity string

// Initial severities.
const (
	SeverityInfo    FindingSeverity = "info"
	SeverityWarning FindingSeverity = "warning"
	SeverityError   FindingSeverity = "error"
)

// Valid reports whether the severity is defined.
func (s FindingSeverity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityError:
		return true
	}
	return false
}

// Finding is a deterministic, evidence-backed observation. Findings are
// NOT vulnerability claims unless they truly represent one.
type Finding struct {
	ID       string          `json:"id"`
	Severity FindingSeverity `json:"severity"`
	Summary  string          `json:"summary"`
	Evidence []string        `json:"evidence"`
}

// Artifact file names in the logical layout.
const (
	ArtifactExt           = ".diagnostic"
	FileManifest          = "manifest.json"
	FileRequest           = "request.json"
	FileDisclosure        = "disclosure.json"
	FileCollection        = "collection.json"
	FileTransformations   = "reports/transformations.json"
	FileWarnings          = "reports/warnings.json"
	FileFindings          = "reports/findings.json"
	FileDisclosureReceipt = "attestations/disclosure-receipt.json"
	DirData               = "data"
	DirReports            = "reports"
	DirAttestations       = "attestations"
)

// Warnings is the payload of reports/warnings.json.
type Warnings struct {
	Warnings []string `json:"warnings"`
}

// FindingsReport is the payload of reports/findings.json.
type FindingsReport struct {
	Findings []Finding `json:"findings"`
}

// Error is a protocol-level validation error with a stable message.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// ValidationError builds a protocol validation error.
func ValidationError(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf("protocol: "+format, args...)}
}

// Validate performs structural and semantic validation of a request
// document. It is used by `diagpermit validate`, `diagpermit plan` and
// `diagpermit collect`.
func (d *DiagnosticRequest) Validate() error {
	var problems []string
	if d == nil {
		return ValidationError("request document is empty")
	}
	if d.ProtocolVersion != ProtocolVersion {
		problems = append(problems, fmt.Sprintf(
			"protocolVersion %q is not supported (expected %q)", d.ProtocolVersion, ProtocolVersion))
	}
	if strings.TrimSpace(d.Request.ID) == "" {
		problems = append(problems, "request.id is required")
	}
	if strings.TrimSpace(d.Requester.Name) == "" {
		problems = append(problems, "requester.name is required")
	}
	if strings.TrimSpace(d.Purpose.Code) == "" {
		problems = append(problems, "purpose.code is required")
	}
	if strings.TrimSpace(d.Purpose.Description) == "" {
		problems = append(problems, "purpose.description is required")
	}
	if d.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, d.ExpiresAt); err != nil {
			problems = append(problems, "expiresAt must be RFC 3339, e.g. 2026-10-10T00:00:00Z")
		}
	}
	if len(d.Capabilities) == 0 {
		problems = append(problems, "at least one capability must be declared")
	}
	for id, cap := range d.Capabilities {
		if !cap.Requirement.Valid() {
			problems = append(problems, fmt.Sprintf(
				"capability %q has invalid requirement %q", id, cap.Requirement))
		}
		if cap.Constraints != nil {
			if cap.Constraints.MaxLines < 0 {
				problems = append(problems, fmt.Sprintf("capability %q: maxLines must be >= 0", id))
			}
			if cap.Constraints.MaxBytes < 0 {
				problems = append(problems, fmt.Sprintf("capability %q: maxBytes must be >= 0", id))
			}
			if cap.Constraints.Since != "" {
				if _, err := time.Parse(time.RFC3339, cap.Constraints.Since); err != nil {
					problems = append(problems, fmt.Sprintf("capability %q: constraints.since must be RFC 3339", id))
				}
			}
		}
	}
	if d.Policy.ArbitraryShellExecution {
		problems = append(problems,
			"policy.arbitraryShellExecution is not permitted in protocol 0.1")
	}
	if d.Policy.MaximumTotalBytes < 0 || d.Policy.MaximumDurationSeconds < 0 {
		problems = append(problems, "policy size/duration limits must be >= 0")
	}
	if len(problems) > 0 {
		return ValidationError("%s", strings.Join(problems, "; "))
	}
	return nil
}
