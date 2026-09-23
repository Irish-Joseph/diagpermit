// Package analysis implements deterministic V0.1 analyzers that produce
// findings from already-collected, already-transformed data (spec
// section 32). Findings are observations with evidence paths, never
// vulnerability claims.
package analysis

import (
	"encoding/json"
	"strings"

	"github.com/diagx/diagx/pkg/protocol"
)

// Analyze inspects the collected data files and returns findings.
func Analyze(files map[string][]byte) []protocol.Finding {
	var out []protocol.Finding
	stopped := false
	unhealthy := false

	// Docker container state.
	if raw, ok := files["data/docker/containers.json"]; ok {
		var c struct {
			Containers []struct {
				Name   string `json:"name"`
				State  string `json:"state"`
				Health string `json:"health"`
			} `json:"containers"`
		}
		if err := json.Unmarshal(raw, &c); err == nil {
			for _, ct := range c.Containers {
				state := strings.ToLower(ct.State)
				if state == "exited" || state == "dead" || state == "stopped" || state == "created" {
					stopped = true
				}
				if strings.EqualFold(ct.Health, "unhealthy") {
					unhealthy = true
				}
			}
		}
	}
	if stopped {
		out = append(out, protocol.Finding{
			ID:       "DOCKER_CONTAINER_STOPPED",
			Severity: protocol.SeverityWarning,
			Summary:  "Docker container is not running.",
			Evidence: []string{"data/docker/containers.json"},
		})
	}
	if unhealthy {
		out = append(out, protocol.Finding{
			ID:       "DOCKER_CONTAINER_UNHEALTHY",
			Severity: protocol.SeverityWarning,
			Summary:  "Docker container reports unhealthy.",
			Evidence: []string{"data/docker/containers.json"},
		})
	}

	// Log signals.
	logs := ""
	if raw, ok := files["data/application/logs.txt"]; ok {
		logs = string(raw)
	}
	refused := containsFold(logs, "connection refused") ||
		containsFold(logs, "ECONNREFUSED") ||
		containsFold(logs, "could not connect")

	if refused {
		out = append(out, protocol.Finding{
			ID:       "LOG_CONNECTION_REFUSED",
			Severity: protocol.SeverityWarning,
			Summary:  "Application log reports connection refused.",
			Evidence: []string{"data/application/logs.txt"},
		})
	}

	// Cross-signal: stopped container + refused connection.
	if refused && stopped {
		out = append(out, protocol.Finding{
			ID:       "DATABASE_CONNECTIVITY_FAILURE",
			Severity: protocol.SeverityError,
			Summary:  "Application cannot connect and a container is not running. The stopped container is likely the cause of the connectivity failure.",
			Evidence: []string{"data/docker/containers.json", "data/application/logs.txt"},
		})
	}

	if len(out) == 0 {
		return []protocol.Finding{}
	}
	return out
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
