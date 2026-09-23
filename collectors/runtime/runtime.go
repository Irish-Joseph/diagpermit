// Package runtime implements the V0.1 runtime version collectors
// (spec section 19): Python, Node.js, Java and Go versions. Collection
// happens only when the relevant binary is present on the local system.
// Binaries are executed with a fixed argument array and a timeout — never
// through a shell.
package runtime

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// CollectorID is the stable collector identifier.
const CollectorID = "runtime"

// Capability IDs provided by this collector.
const (
	CapPython = "runtime.python.version"
	CapNode   = "runtime.node.version"
	CapJava   = "runtime.java.version"
	CapGo     = "runtime.go.version"
)

type probe struct {
	capID    string
	binaries []string
	args     []string
}

var probes = map[string]probe{
	CapPython: {capID: CapPython, binaries: []string{"python3", "python"}, args: []string{"--version"}},
	CapNode:   {capID: CapNode, binaries: []string{"node"}, args: []string{"--version"}},
	CapJava:   {capID: CapJava, binaries: []string{"java"}, args: []string{"-version"}},
	CapGo:     {capID: CapGo, binaries: []string{"go"}, args: []string{"version"}},
}

// Collector probes installed runtime versions.
type Collector struct{}

// New returns the runtime collector.
func New() *Collector { return &Collector{} }

func (c *Collector) ID() string      { return CollectorID }
func (c *Collector) Version() string { return collection.CollectorVersion }

func (c *Collector) Capabilities() []collection.DeclaredCapability {
	platforms := []string{"linux", "windows", "darwin"}
	return []collection.DeclaredCapability{
		{ID: CapPython, Description: "Python interpreter version (if installed)", Process: "python3 --version", Platforms: platforms, MaxOutputBytes: 256, Sensitivity: "low"},
		{ID: CapNode, Description: "Node.js runtime version (if installed)", Process: "node --version", Platforms: platforms, MaxOutputBytes: 256, Sensitivity: "low"},
		{ID: CapJava, Description: "Java runtime version (if installed)", Process: "java -version", Platforms: platforms, MaxOutputBytes: 256, Sensitivity: "low"},
		{ID: CapGo, Description: "Go toolchain version (if installed)", Process: "go version", Platforms: platforms, MaxOutputBytes: 256, Sensitivity: "low"},
	}
}

// RuntimeInfo is the data/runtime/<name>.json payload.
type RuntimeInfo struct {
	Binary      string `json:"binary"`
	Version     string `json:"version"`
	Available   bool   `json:"available"`
	CollectedAt string `json:"collectedAt"`
}

// Plan describes what the collector would do.
func (c *Collector) Plan(cc *collection.Context) collection.PlanInfo {
	p := probes[cc.Capability]
	return collection.PlanInfo{
		Capability:  cc.Capability,
		Description: "run " + strings.Join(p.args, " ") + " to report the installed version (no network)",
		Process:     p.binaries[0],
	}
}

// Collect implements collection.Collector.
func (c *Collector) Collect(cc *collection.Context) collection.Result {
	p, ok := probes[cc.Capability]
	if !ok {
		return collection.Result{Status: "unsupported", Message: "unknown runtime capability"}
	}
	bin := "none"
	for _, b := range p.binaries {
		if _, err := exec.LookPath(b); err == nil {
			bin = b
			break
		}
	}
	info := RuntimeInfo{Binary: bin, Available: bin != "none", CollectedAt: time.Now().UTC().Format(time.RFC3339)}
	if bin == "none" {
		// Only report if this runtime is relevant; absence is a
		// legitimate, recordable outcome.
		return resultFile(runtimeName(cc.Capability), info, "partial", p.binaries[0]+" not found on this system")
	}

	ctx, cancel := context.WithTimeout(cc.Ctx, 10*time.Second)
	defer cancel()
	// #nosec G204 -- bin and args come only from the fixed probes table above.
	cmd := exec.CommandContext(ctx, bin, p.args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out // java -version writes to stderr
	runErr := cmd.Run()
	if runErr != nil && ctx.Err() == context.DeadlineExceeded {
		return collection.Result{Status: "timed_out", Message: "version probe timed out"}
	}
	if runErr != nil {
		// Some runtimes return non-zero for --version (java).
		if strings.TrimSpace(out.String()) == "" {
			return collection.Result{Status: "failed", Message: "version probe failed: " + runErr.Error()}
		}
	}
	info.Version = firstLine(out.String())
	return resultFile(runtimeName(cc.Capability), info, "success", "")
}

func resultFile(name string, info RuntimeInfo, status protocol.CollectionStatus, msg string) collection.Result {
	b, _ := jsonMarshal(info)
	return collection.Result{
		Status:  status,
		Message: msg,
		Bytes:   int64(len(b)),
		Files: map[string]collection.CollectedFile{
			"data/runtime/" + name + ".json": {Content: b, MediaType: "application/json", CollectedAt: time.Now().UTC()},
		},
	}
}

func runtimeName(cap string) string {
	switch cap {
	case CapPython:
		return "python"
	case CapNode:
		return "node"
	case CapJava:
		return "java"
	case CapGo:
		return "go"
	}
	return "unknown"
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.TrimSpace(s)
}

var _ = runtime.GOOS
