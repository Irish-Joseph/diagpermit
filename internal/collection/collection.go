// Package collection implements the collection engine: it executes the
// approved capabilities of an EffectiveDisclosurePlan through the typed
// collector registry, enforcing the request policy (time and size limits,
// network policy) and producing a CollectionReport plus the raw collected
// files (spec sections 17 and 18).
package collection

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/diagx/diagx/internal/transform"
	"github.com/diagx/diagx/pkg/protocol"
)

// CollectorVersion is the shared V0.1 collector implementation version.
const CollectorVersion = "0.1.0"

// DeclaredCapability is a capability a collector offers, with the
// requirements it declares (spec section 18).
type DeclaredCapability struct {
	ID             string
	Description    string
	Network        bool
	Process        string // binary that would be executed, if any
	Platforms      []string
	MaxOutputBytes int64
	Sensitivity    string // low | medium | high
}

// PlanInfo describes what a collector would do, for `diagx plan`.
type PlanInfo struct {
	Capability  string
	Description string
	Files       []string // files that would be read
	Process     string   // binary that would be executed, if any
	Network     string   // destination description, if any
}

// CollectedFile is one produced data file.
type CollectedFile struct {
	Content     []byte
	MediaType   string
	Truncated   bool
	CollectedAt time.Time
}

// Result is the outcome of one capability collection.
type Result struct {
	Status  protocol.CollectionStatus
	Message string
	Files   map[string]CollectedFile // logical artifact path -> file
	Bytes   int64
}

// Context carries everything a collector needs for one capability run.
type Context struct {
	Ctx         context.Context
	Request     *protocol.DiagnosticRequest
	Plan        *protocol.EffectiveDisclosurePlan
	Capability  string
	Constraints *protocol.Constraints
	Policy      protocol.Policy
	Engine      *transform.Engine // shared per-artifact (pseudonym stability)
	Warnings    *[]string
}

// AddWarning appends a warning to the run warnings.
func (c *Context) AddWarning(format string, args ...any) {
	if c.Warnings != nil {
		*c.Warnings = append(*c.Warnings, fmt.Sprintf(format, args...))
	}
}

// Collector is the typed collector interface (spec section 18).
// Collectors expose capabilities, never arbitrary behaviour: there is no
// free-form command field in V0.1.
type Collector interface {
	ID() string
	Version() string
	Capabilities() []DeclaredCapability
	// Plan describes what Collect would do for a capability.
	Plan(c *Context) PlanInfo
	Collect(c *Context) Result
}

// Registry maps collectors and capabilities.
type Registry struct {
	collectors []Collector
	byID       map[string]Collector
	byCap      map[string]string // capability -> collector ID
}

// NewRegistry builds the default V0.1 registry.
func NewRegistry(all ...Collector) *Registry {
	r := &Registry{byID: map[string]Collector{}, byCap: map[string]string{}}
	for _, c := range all {
		r.Register(c)
	}
	return r
}

// Register adds a collector.
func (r *Registry) Register(c Collector) {
	r.collectors = append(r.collectors, c)
	r.byID[c.ID()] = c
	for _, cap := range c.Capabilities() {
		r.byCap[cap.ID] = c.ID()
	}
}

// All returns all collectors in stable ID order.
func (r *Registry) All() []Collector {
	out := make([]Collector, len(r.collectors))
	copy(out, r.collectors)
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// CollectorFor returns the collector providing the capability, or nil.
func (r *Registry) CollectorFor(capability string) Collector {
	id, ok := r.byCap[capability]
	if !ok {
		return nil
	}
	return r.byID[id]
}

// Engine executes the plan.
type Engine struct {
	Registry *Registry
}

// Run executes all approved capabilities. It returns the collection
// report, the collected files (logical path -> file) and the bytes used.
// It never fails the whole run for a single collector error; per-capability
// failures are recorded as statuses. A fail-closed transformation error
// propagates as an error and no artifact must be produced by the caller.
func (e *Engine) Run(ctx context.Context, req *protocol.DiagnosticRequest, plan *protocol.EffectiveDisclosurePlan, engine *transform.Engine, warnings *[]string) (*protocol.CollectionReport, map[string]CollectedFile, error) {
	report := &protocol.CollectionReport{
		ProtocolVersion: protocol.ProtocolVersion,
		RequestID:       req.RequestID(),
		StartedAt:       time.Now().UTC(),
		NetworkAccess:   plan.NetworkAccess,
		ShellExecution:  plan.ShellExecution,
	}
	files := map[string]CollectedFile{}
	total := int64(0)
	budget := int64(req.Policy.MaximumTotalBytes)
	if budget <= 0 {
		budget = 25 << 20 // default 25 MiB
	}
	if req.Policy.MaximumDurationSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.Policy.MaximumDurationSeconds)*time.Second)
		defer cancel()
	}

	caps := append([]string{}, plan.Approved...)
	sort.Strings(caps)

	for _, cap := range caps {
		if ctx.Err() != nil {
			report.Results = append(report.Results, protocol.CollectorResult{
				Capability: cap, Status: protocol.StatusTimedOut,
				StartedAt: report.StartedAt, CompletedAt: time.Now().UTC(),
				Message: "run exceeded maximum duration",
			})
			*warnings = append(*warnings, "collection exceeded maximum duration")
			continue
		}
		collector := e.Registry.CollectorFor(cap)
		started := time.Now().UTC()
		if collector == nil {
			report.Results = append(report.Results, protocol.CollectorResult{
				Capability: cap, Status: protocol.StatusUnsupported,
				StartedAt: started, CompletedAt: time.Now().UTC(),
				Message: "no V0.1 collector implements this capability",
			})
			*warnings = append(*warnings, fmt.Sprintf("capability %q has no V0.1 collector (unsupported)", cap))
			continue
		}
		// Policy enforcement: a collector that requires network must be
		// blocked when the plan disables network access.
		blocked := false
		for _, dc := range collector.Capabilities() {
			if dc.ID == cap && dc.Network && !plan.NetworkAccess {
				blocked = true
				break
			}
		}
		if blocked {
			report.Results = append(report.Results, protocol.CollectorResult{
				Capability: cap, Collector: collector.ID(),
				CollectorVersion: collector.Version(),
				Status:           protocol.StatusForbidden,
				StartedAt:        started, CompletedAt: time.Now().UTC(),
				Message: "collector requires network access which is disabled by policy",
			})
			*warnings = append(*warnings, fmt.Sprintf("capability %q blocked: requires network access (policy networkAccess=false)", cap))
			continue
		}
		if total >= budget {
			report.Results = append(report.Results, protocol.CollectorResult{
				Capability: cap, Collector: collector.ID(),
				CollectorVersion: collector.Version(),
				Status:           protocol.StatusSizeLimitExceeded,
				StartedAt:        started, CompletedAt: time.Now().UTC(),
				Message: "maximum total bytes reached",
			})
			continue
		}

		cctx := &Context{
			Ctx:         ctx,
			Request:     req,
			Plan:        plan,
			Capability:  cap,
			Constraints: constraintFor(req, cap),
			Policy:      req.Policy,
			Engine:      engine,
			Warnings:    warnings,
		}
		res := collector.Collect(cctx)
		completed := time.Now().UTC()

		// Enforce total byte budget: drop files that would exceed it.
		for path, f := range res.Files {
			if total+int64(len(f.Content)) > budget {
				res.Status = protocol.StatusSizeLimitExceeded
				if res.Message == "" {
					res.Message = "maximum total bytes exceeded"
				}
				*warnings = append(*warnings, fmt.Sprintf("capability %q: dropping %s (size limit)", cap, path))
				delete(res.Files, path)
				continue
			}
			files[path] = f
			total += int64(len(f.Content))
		}

		report.Results = append(report.Results, protocol.CollectorResult{
			Capability:       cap,
			Collector:        collector.ID(),
			CollectorVersion: collector.Version(),
			Status:           res.Status,
			StartedAt:        started,
			CompletedAt:      completed,
			Bytes:            res.Bytes,
			Files:            keys(res.Files),
			Message:          res.Message,
		})
	}
	report.CompletedAt = time.Now().UTC()
	// Record denied and forbidden capabilities too, so the collection
	// report shows the complete picture (spec section 17).
	for _, cap := range sorted(plan.Denied) {
		report.Results = append(report.Results, protocol.CollectorResult{
			Capability:  cap,
			Status:      protocol.StatusDeniedByUser,
			StartedAt:   report.StartedAt,
			CompletedAt: report.CompletedAt,
			Message:     "declined by user during consent review",
		})
	}
	for _, cap := range sorted(plan.Forbidden) {
		report.Results = append(report.Results, protocol.CollectorResult{
			Capability:  cap,
			Status:      protocol.StatusForbidden,
			StartedAt:   report.StartedAt,
			CompletedAt: report.CompletedAt,
			Message:     "prohibited by the diagnostic request",
		})
	}
	return report, files, nil
}

func sorted(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func keys(m map[string]CollectedFile) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func constraintFor(req *protocol.DiagnosticRequest, cap string) *protocol.Constraints {
	c, ok := req.Capabilities[cap]
	if !ok {
		return nil
	}
	return c.Constraints
}
