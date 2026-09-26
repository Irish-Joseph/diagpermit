// Package pipeline wires the consent engine, collection engine,
// transformation engine, analyzer and packager into the V0.1 workflow
// through the complete diagnostic workflow:
//
//	request → consent → plan → collection → transformation → package
package pipeline

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Irish-Joseph/diagpermit/internal/analysis"
	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/internal/consent"
	"github.com/Irish-Joseph/diagpermit/internal/packaging"
	"github.com/Irish-Joseph/diagpermit/internal/transform"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// Output carries the results of a run.
type Output struct {
	ArtifactPath string
	Receipt      *protocol.DisclosureReceipt
	Decision     *protocol.ConsentDecision
	Plan         *protocol.EffectiveDisclosurePlan
	Collection   *protocol.CollectionReport
	Transform    *protocol.TransformationReport
	Findings     []protocol.Finding
	Warnings     []string
	Success      int
	Partial      int
	Declined     int
	Forbidden    int
	Failed       int
}

// Run executes the full workflow and writes the artifact.
func Run(ctx context.Context, req *protocol.DiagnosticRequest, mode string, prompter *consent.Prompter, consentData []byte, outPath string, log io.Writer) (*Output, error) {
	// Fail closed if the ruleset cannot even be built.
	ruleset, err := buildRuleset(req)
	if err != nil {
		return nil, err
	}

	decision, plan, warnings, err := consent.Build(ctx, req, mode, prompter, consentData)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		fmt.Fprintln(log, w)
	}

	salt, err := packaging.NewSalt()
	if err != nil {
		return nil, err
	}
	engine, err := transform.NewEngine(ruleset, salt)
	if err != nil {
		return nil, err
	}

	registry := defaultRegistry()
	collEngine := &collection.Engine{Registry: registry}
	collectionStarted := time.Now().UTC()
	rep, files, err := collEngine.Run(ctx, req, plan, engine, &warnings)
	if err != nil {
		return nil, err
	}
	rep.StartedAt = collectionStarted

	// Transformation phase (fail closed).
	transformed, transformReport, err := runTransformations(engine, files, req)
	if err != nil {
		if fce, ok := transform.AsFailClosed(err); ok {
			return nil, &FailClosedPipelineError{FailClosedError: *fce}
		}
		return nil, err
	}

	// Findings from transformed data.
	dataForAnalysis := map[string][]byte{}
	for p, f := range transformed {
		dataForAnalysis[p] = f.Content
	}
	findings := analysis.Analyze(dataForAnalysis)

	// Manifest metadata: which collector produced each data file.
	meta := map[string]packaging.ManifestMeta{}
	for _, res := range rep.Results {
		for _, path := range res.Files {
			truncated := false
			if f, ok := transformed[path]; ok {
				truncated = f.Truncated
			}
			meta[path] = packaging.ManifestMeta{
				Collector:        res.Collector,
				CollectorVersion: res.CollectorVersion,
				Transformed:      true,
				Truncated:        truncated,
			}
		}
	}

	if outPath == "" {
		outDir := ""
		if req.Local != nil {
			outDir = req.Local.OutputDir
		}
		outPath = packaging.DefaultOutputName(req, outDir)
	}
	receipt, err := packaging.Build(outPath, &packaging.Input{
		Request:      req,
		Decision:     decision,
		Plan:         plan,
		Collection:   rep,
		Transform:    transformReport,
		Files:        transformed,
		ManifestMeta: meta,
		Warnings:     warnings,
		Findings:     findings,
	})
	if err != nil {
		return nil, err
	}

	out := &Output{
		ArtifactPath: outPath,
		Receipt:      receipt,
		Decision:     decision,
		Plan:         plan,
		Collection:   rep,
		Transform:    transformReport,
		Findings:     findings,
		Warnings:     warnings,
	}
	for _, r := range rep.Results {
		switch r.Status {
		case protocol.StatusSuccess:
			out.Success++
		case protocol.StatusPartial:
			out.Partial++
		case protocol.StatusDeniedByUser, protocol.StatusSkipped:
			out.Declined++
		case protocol.StatusForbidden:
			out.Forbidden++
		default:
			out.Failed++
		}
	}
	return out, nil
}

// buildRuleset merges the default ruleset with user-defined detectors.
func buildRuleset(req *protocol.DiagnosticRequest) (transform.Ruleset, error) {
	var extra []packaging.ExtraDetector
	if req.Local != nil && req.Local.Privacy != nil {
		for _, e := range req.Local.Privacy.ExtraDetectors {
			extra = append(extra, packaging.ExtraDetector{
				Name:        e.Name,
				Pattern:     e.Pattern,
				Action:      transform.Action(e.Action),
				ReplaceWith: e.ReplaceWith,
				TruncateTo:  e.TruncateTo,
			})
		}
	}
	return packaging.BuildRuleset(extra)
}

// runTransformations applies the engine to every collected file.
func runTransformations(engine *transform.Engine, files map[string]collection.CollectedFile, req *protocol.DiagnosticRequest) (map[string]collection.CollectedFile, *protocol.TransformationReport, error) {
	out := map[string]collection.CollectedFile{}
	merged := map[string]*transform.DetectorReport{}
	order := []string{}
	for path, f := range files {
		content, rep, err := engine.Apply(f.Content)
		if err != nil {
			// Fail closed: attribute the failure to this file's collector.
			return nil, nil, err
		}
		f.Content = content
		out[path] = f
		for i := range rep {
			d := rep[i]
			if m, ok := merged[d.Detector]; ok {
				m.Matches += d.Matches
				m.Executed = m.Executed || d.Executed
			} else {
				cp := d
				merged[d.Detector] = &cp
				order = append(order, d.Detector)
			}
		}
	}
	// Stable order for the report.
	detectors := make([]protocol.DetectorReport, 0, len(merged))
	for _, id := range order {
		d := merged[id]
		detectors = append(detectors, protocol.DetectorReport{
			Detector:    d.Detector,
			Category:    d.Category,
			Executed:    d.Executed,
			Matches:     d.Matches,
			Transformer: d.Transformer,
		})
	}
	filesList := make([]string, 0, len(files))
	for p := range files {
		filesList = append(filesList, p)
	}
	sort.Strings(filesList)
	return out, &protocol.TransformationReport{
		ProtocolVersion:        protocol.ProtocolVersion,
		RequestID:              req.RequestID(),
		Ruleset:                transform.DefaultRuleset().ID,
		DetectorsExecuted:      len(detectors),
		TransformationsApplied: engine.TotalTransformations(),
		Detectors:              detectors,
		Files:                  filesList,
	}, nil
}

// FailClosedPipelineError wraps a fail-closed transformation failure.
type FailClosedPipelineError struct {
	transform.FailClosedError
}

// Unwrap preserves fail-closed error classification across pipeline layers.
func (e *FailClosedPipelineError) Unwrap() error { return &e.FailClosedError }

// PrintFailClosed renders the spec-mandated fail-closed message.
func PrintFailClosed(w io.Writer, err error) bool {
	fce, ok := transform.AsFailClosed(err)
	if !ok {
		return false
	}
	fmt.Fprint(w, `COLLECTION STOPPED SAFELY

A required transformation failed.
No shareable diagnostic artifact was produced.

Collector:
`+fce.Collector+`

Transformer:
`+fce.Transformer+`

Reason:
`+fce.Reason+`
`)
	return true
}

// AllCollectors returns all registered collectors for display.
func AllCollectors() []collection.Collector {
	return registryFactory().All()
}

// defaultRegistry is overridable by the conformance suite via
// SetRegistryFactory.
var registryFactory = func() *collection.Registry {
	return collection.NewRegistry(
		newSystem(), newRuntime(), newApplication(), newDocker(),
	)
}

// RegistryFactory returns the current registry factory (for tests).
func RegistryFactory() func() *collection.Registry { return registryFactory }

// SetRegistryFactory overrides the collector registry (tests/conformance).
func SetRegistryFactory(f func() *collection.Registry) {
	registryFactory = f
}

func defaultRegistry() *collection.Registry { return registryFactory() }

var (
	newSystem      = newSystemCollector
	newRuntime     = newRuntimeCollector
	newApplication = newApplicationCollector
	newDocker      = newDockerCollector
)

// Silence nothing.
