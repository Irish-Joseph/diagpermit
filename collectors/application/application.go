// Package application implements the V0.1 application log collector
// using a specifically configured file path with maximum
// lines and maximum bytes. Filesystem safety (no symlink following,
// bounds, regular files only) is enforced by the fsafety package.
package application

import (
	"mime"
	"path"
	"time"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/internal/fsafety"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// CollectorID is the stable collector identifier.
const CollectorID = "application"

// CapabilityLogs is the capability ID provided by this collector.
const CapabilityLogs = "application.logs"

// defaultMaxLines bounds log output when the request sets no limit.
const defaultMaxLines = 500
const defaultMaxBytes = 1 << 20 // 1 MiB

// Collector tails a configured log file.
type Collector struct{}

// New returns the application log collector.
func New() *Collector { return &Collector{} }

func (c *Collector) ID() string      { return CollectorID }
func (c *Collector) Version() string { return collection.CollectorVersion }

func (c *Collector) Capabilities() []collection.DeclaredCapability {
	return []collection.DeclaredCapability{{
		ID:             CapabilityLogs,
		Description:    "Tail of the configured application log (bounded lines/bytes)",
		Platforms:      []string{"linux", "windows", "darwin"},
		MaxOutputBytes: defaultMaxBytes,
		Sensitivity:    "high",
	}}
}

// Plan describes what the collector would do.
func (c *Collector) Plan(cc *collection.Context) collection.PlanInfo {
	p := ""
	if cc.Request != nil && cc.Request.Local != nil {
		p = cc.Request.Local.ApplicationLogPath
	}
	info := collection.PlanInfo{
		Capability:  cc.Capability,
		Description: "read the tail of the configured log file (no network)",
	}
	if p == "" {
		info.Description = "no log path configured; nothing would be collected"
	} else {
		info.Files = []string{p}
	}
	return info
}

// Collect implements collection.Collector.
func (c *Collector) Collect(cc *collection.Context) collection.Result {
	p := ""
	if cc.Request != nil && cc.Request.Local != nil {
		p = cc.Request.Local.ApplicationLogPath
	}
	if p == "" {
		return collection.Result{Status: protocol.StatusSkipped, Message: "no applicationLogPath configured"}
	}
	// Allowed root is the project working directory: the configured log
	// file must live inside the project, which bounds traversal attacks.
	root := "."
	maxLines := defaultMaxLines
	maxBytes := int64(defaultMaxBytes)
	if cc.Constraints != nil {
		if cc.Constraints.MaxLines > 0 {
			maxLines = cc.Constraints.MaxLines
		}
		if cc.Constraints.MaxBytes > 0 {
			maxBytes = int64(cc.Constraints.MaxBytes)
		}
	}
	data, err := fsafety.Tail(p, fsafety.Options{
		Root:     root,
		MaxBytes: maxBytes,
		MaxLines: maxLines,
	})
	if err != nil {
		return collection.Result{Status: "failed", Message: err.Error()}
	}
	media := mime.TypeByExtension(path.Ext(p))
	if media == "" {
		media = "text/plain"
	}
	truncated := maxBytes < (1<<20) && int64(len(data)) == maxBytes
	return collection.Result{
		Status: "success",
		Bytes:  int64(len(data)),
		Files: map[string]collection.CollectedFile{
			"data/application/logs.txt": {
				Content: data, MediaType: media, Truncated: truncated,
				CollectedAt: time.Now().UTC(),
			},
		},
	}
}
