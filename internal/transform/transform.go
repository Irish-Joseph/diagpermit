// Package transform implements the DiagPermit privacy transformation engine
// for diagnostic content.
//
// Design notes:
//
//   - Detectors are regular expressions executed by Go's regexp package
//     (RE2), which guarantees linear-time matching and therefore protects
//     against catastrophic backtracking / ReDoS even for user-defined
//     patterns.
//
//   - The engine is fail-closed: if a mandatory transformation fails for
//     any reason, the run is aborted and NO artifact is produced.
//
//   - The transformation report records counts and detector identities
//     only. It never contains the original sensitive values.
//
//   - Pseudonymization is stable within one artifact via a random
//     per-artifact salt: the same value always maps to
//     the same pseudonym in a given artifact, and different values map to
//     different pseudonyms with overwhelming probability.
package transform

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Action is one privacy transformation.
type Action string

// Supported transformations.
const (
	ActionDrop         Action = "drop"
	ActionMask         Action = "mask"
	ActionReplace      Action = "replace"
	ActionTruncate     Action = "truncate"
	ActionHash         Action = "hash"
	ActionPseudonymize Action = "pseudonymize"
)

// Valid reports whether the action is supported.
func (a Action) Valid() bool {
	switch a {
	case ActionDrop, ActionMask, ActionReplace, ActionTruncate,
		ActionHash, ActionPseudonymize:
		return true
	}
	return false
}

// FailClosedError is returned when a mandatory transformation fails.
// Callers MUST treat it as fatal: no shareable artifact is produced.
type FailClosedError struct {
	Collector   string
	Transformer string
	Reason      string
}

func (e *FailClosedError) Error() string {
	return fmt.Sprintf("fail-closed: required transformation failed (collector=%s transformer=%s reason=%s)",
		e.Collector, e.Transformer, e.Reason)
}

// AsFailClosed reports whether err is a fail-closed error.
func AsFailClosed(err error) (*FailClosedError, bool) {
	var fce *FailClosedError
	if ok := asError(err, &fce); ok {
		return fce, true
	}
	return nil, false
}

func asError(err error, target **FailClosedError) bool {
	for err != nil {
		if fce, ok := err.(*FailClosedError); ok {
			*target = fce
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// subFn is a replacement callback receiving the full match and capture
// groups (unmatched groups are empty strings).
type subFn func(full string, groups []string) string

// subAll applies re to s left-to-right, replacing each match via fn,
// never re-scanning replaced text.
func subAll(re *regexp.Regexp, s string, fn subFn) (string, int) {
	idxs := re.FindAllStringSubmatchIndex(s, -1)
	if len(idxs) == 0 {
		return s, 0
	}
	var b []byte
	b = append(b, s[:0]...)
	last := 0
	for _, idx := range idxs {
		full := s[idx[0]:idx[1]]
		groups := make([]string, 0, (len(idx)-2)/2)
		for g := 2; g < len(idx); g += 2 {
			if idx[g] >= 0 {
				groups = append(groups, s[idx[g]:idx[g+1]])
			} else {
				groups = append(groups, "")
			}
		}
		b = append(b, s[last:idx[0]]...)
		b = append(b, []byte(fn(full, groups))...)
		last = idx[1]
	}
	b = append(b, s[last:]...)
	return string(b), len(idxs)
}

// Detector is a sensitive-content detector.
type Detector struct {
	ID       string // stable machine identifier, e.g. "jwt"
	Category string // report category, e.g. "JWT-like values"
	Re       *regexp.Regexp
	// ValueGroup is the capture group holding the secret for generic
	// (custom) actions. 0 = whole match.
	ValueGroup int
	// fn performs the actual replacement. It must be idempotent w.r.t.
	// its own output.
	fn subFn
}

// Rule binds a detector to an action.
type Rule struct {
	Detector    string // detector ID, or "custom:<name>" for user patterns
	Pattern     string // regex source, required for "custom:" detectors
	Action      Action
	ReplaceWith string // used by ActionReplace
	TruncateTo  int    // used by ActionTruncate (characters to keep)
	// Required marks the transformation as mandatory (fail-closed).
	// All default rules are required.
	Required bool
}

// Ruleset is an ordered set of rules. Order matters: earlier detectors
// see raw content, later detectors see partially transformed content.
type Ruleset struct {
	ID    string
	Rules []Rule
}

// DefaultRuleset returns the built-in diagpermit-default-0.1 ruleset.
func DefaultRuleset() Ruleset {
	return Ruleset{
		ID: "diagpermit-default-0.1",
		Rules: []Rule{
			// Structural / high-signal credentials first, so later,
			// more generic detectors never double-process them.
			{Detector: "pem_private_key", Action: ActionDrop, Required: true},
			{Detector: "db_connection", Action: ActionMask, Required: true},
			{Detector: "auth_header", Action: ActionMask, Required: true},
			{Detector: "jwt", Action: ActionMask, Required: true},
			{Detector: "github_token", Action: ActionMask, Required: true},
			{Detector: "aws_access_key", Action: ActionMask, Required: true},
			{Detector: "aws_secret_assignment", Action: ActionMask, Required: true},
			{Detector: "password_assignment", Action: ActionMask, Required: true},
			{Detector: "api_token_assignment", Action: ActionMask, Required: true},
			// Pseudonymized identifiers (stable per artifact).
			{Detector: "url_host", Action: ActionPseudonymize, Required: true},
			{Detector: "mac_address", Action: ActionPseudonymize, Required: true},
			{Detector: "email", Action: ActionPseudonymize, Required: true},
			{Detector: "ipv6", Action: ActionPseudonymize, Required: true},
			{Detector: "ipv4", Action: ActionPseudonymize, Required: true},
			// Personal identifiers last.
			{Detector: "home_user", Action: ActionMask, Required: true},
		},
	}
}

// Engine applies a ruleset to content. One Engine instance is created per
// diagnostic artifact so that stable pseudonyms stay consistent across
// every file of that artifact.
type Engine struct {
	ruleset Ruleset
	det     map[string]*Detector
	pseudo  *PseudoMap
	counts  map[string]int
}

// NewEngine builds an engine for the given ruleset. salt must be a fresh
// random per-artifact value (16+ bytes recommended).
func NewEngine(ruleset Ruleset, salt []byte) (*Engine, error) {
	if len(salt) == 0 {
		return nil, fmt.Errorf("ruleset: pseudonymization salt must not be empty")
	}
	e := &Engine{
		ruleset: ruleset,
		pseudo:  NewPseudoMap(salt),
		counts:  make(map[string]int),
	}
	e.det = defaultDetectors(e.pseudo)
	for i, rule := range ruleset.Rules {
		if !rule.Action.Valid() {
			return nil, fmt.Errorf("ruleset: rule %d (%s): invalid action %q", i, rule.Detector, rule.Action)
		}
		if rule.Action == ActionReplace && rule.ReplaceWith == "" {
			return nil, fmt.Errorf("ruleset: rule %d (%s): replace action requires ReplaceWith", i, rule.Detector)
		}
		if rule.Action == ActionTruncate && rule.TruncateTo <= 0 {
			return nil, fmt.Errorf("ruleset: rule %d (%s): truncate action requires positive TruncateTo", i, rule.Detector)
		}
		id := rule.Detector
		if strings.HasPrefix(id, "custom:") {
			name := strings.TrimPrefix(id, "custom:")
			if name == "" {
				return nil, fmt.Errorf("ruleset: rule %d: empty custom detector name", i)
			}
			if rule.Pattern == "" {
				return nil, fmt.Errorf("ruleset: rule %d (custom %q): missing pattern", i, name)
			}
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				// Fail closed on unparseable mandatory custom detectors.
				return nil, fmt.Errorf("ruleset: rule %d (custom %q): %w", i, name, err)
			}
			vg := 0
			if re.NumSubexp() > 0 {
				vg = 1
			}
			e.det[id] = &Detector{
				ID:         id,
				Category:   "user-defined pattern: " + name,
				Re:         re,
				ValueGroup: vg,
				fn:         e.genericActionFn(rule, vg),
			}
			continue
		}
		if _, ok := e.det[id]; !ok {
			return nil, fmt.Errorf("ruleset: rule %d: unknown detector %q", i, id)
		}
	}
	return e, nil
}

// genericActionFn implements the six generic actions for custom detectors.
func (e *Engine) genericActionFn(rule Rule, valueGroup int) subFn {
	return func(full string, groups []string) string {
		val := full
		if valueGroup > 0 {
			groupIndex := valueGroup - 1
			if groupIndex < len(groups) && groups[groupIndex] != "" {
				val = groups[groupIndex]
			}
		}
		switch rule.Action {
		case ActionDrop:
			return ""
		case ActionReplace:
			return rule.ReplaceWith
		case ActionTruncate:
			runes := []rune(val)
			if len(runes) <= rule.TruncateTo {
				return val
			}
			return string(runes[:rule.TruncateTo]) + "...[truncated]"
		case ActionHash:
			sum := sha256.Sum256([]byte(val))
			return "sha256:" + hex.EncodeToString(sum[:])[:12]
		case ActionPseudonymize:
			label, _ := e.pseudo.For(rule.Detector + "|" + val)
			return label
		case ActionMask:
			return "***"
		}
		return "***"
	}
}

// Apply runs all rules in order over content. It returns the transformed
// content and a per-detector report (never containing original values).
func (e *Engine) Apply(content []byte) ([]byte, []DetectorReport, error) {
	out := string(content)
	report := make([]DetectorReport, 0, len(e.ruleset.Rules))
	for _, rule := range e.ruleset.Rules {
		d, ok := e.det[rule.Detector]
		if !ok {
			if rule.Required {
				return nil, nil, &FailClosedError{
					Collector:   "engine",
					Transformer: e.ruleset.ID,
					Reason:      fmt.Sprintf("detector %q not registered", rule.Detector),
				}
			}
			report = append(report, DetectorReport{
				Detector: rule.Detector, Executed: false, Transformer: string(rule.Action),
			})
			continue
		}
		var err error
		var n int
		out, n, err = e.applyRule(d, out)
		if err != nil {
			if rule.Required {
				return nil, nil, &FailClosedError{
					Collector:   "engine",
					Transformer: e.ruleset.ID,
					Reason:      fmt.Sprintf("detector %s: %v", d.ID, err),
				}
			}
			report = append(report, DetectorReport{
				Detector: d.ID, Category: d.Category, Executed: false,
				Transformer: string(rule.Action),
			})
			continue
		}
		e.counts[d.ID] += n
		report = append(report, DetectorReport{
			Detector:    d.ID,
			Category:    d.Category,
			Executed:    true,
			Matches:     n,
			Transformer: string(rule.Action),
		})
	}
	return []byte(out), report, nil
}

func (e *Engine) applyRule(d *Detector, s string) (out string, n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during %s: %v", d.ID, r)
		}
	}()
	out, n = subAll(d.Re, s, d.fn)
	return out, n, nil
}

// TotalTransformations returns the cumulative transformation count across
// all Apply calls on this engine.
func (e *Engine) TotalTransformations() int {
	total := 0
	for _, c := range e.counts {
		total += c
	}
	return total
}

// DetectorNames returns the IDs of all detectors that executed.
func (e *Engine) DetectorNames() []string {
	out := make([]string, 0, len(e.counts))
	for id := range e.counts {
		out = append(out, id)
	}
	return out
}

// DetectorsExecuted returns how many distinct detectors executed.
func (e *Engine) DetectorsExecuted() int { return len(e.counts) }

// DetectorReport is the per-detector line of the transformation report.
type DetectorReport struct {
	Detector    string `json:"detector"`
	Category    string `json:"category"`
	Executed    bool   `json:"executed"`
	Matches     int    `json:"matches"`
	Transformer string `json:"transformer"`
}
