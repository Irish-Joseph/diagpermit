// Package docker implements the basic V0.1 Docker collector (spec
// section 19): Docker version, container names/states, image references
// and health state. It deliberately does NOT dump container environment
// variables.
//
// The collector executes the local `docker` binary with a fixed argument
// array and timeouts — never through a shell.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

// CollectorID is the stable collector identifier.
const CollectorID = "docker"

// Capability IDs provided by this collector.
const (
	CapVersion   = "docker.version"
	CapContainer = "docker.container_state"
)

// Collector collects basic Docker state.
type Collector struct{}

// New returns the docker collector.
func New() *Collector { return &Collector{} }

func (c *Collector) ID() string      { return CollectorID }
func (c *Collector) Version() string { return collection.CollectorVersion }

func (c *Collector) Capabilities() []collection.DeclaredCapability {
	return []collection.DeclaredCapability{
		{ID: CapVersion, Description: "Docker engine version", Process: "docker version", Platforms: []string{"linux", "windows", "darwin"}, MaxOutputBytes: 1 << 10, Sensitivity: "low"},
		{ID: CapContainer, Description: "Container names, states, images and health (no environment variables)", Process: "docker ps", Platforms: []string{"linux", "windows", "darwin"}, MaxOutputBytes: 64 << 10, Sensitivity: "medium"},
	}
}

// VersionInfo is the data/docker/version.json payload.
type VersionInfo struct {
	Available   bool   `json:"available"`
	Client      string `json:"client,omitempty"`
	Server      string `json:"server,omitempty"`
	CollectedAt string `json:"collectedAt"`
}

// Container is one container's coarse state.
type Container struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Status string `json:"status"`
	Image  string `json:"image"`
	Health string `json:"health,omitempty"`
}

// ContainersInfo is the data/docker/containers.json payload.
type ContainersInfo struct {
	Available   bool        `json:"available"`
	Containers  []Container `json:"containers"`
	CollectedAt string      `json:"collectedAt"`
}

// Plan describes what the collector would do.
func (c *Collector) Plan(cc *collection.Context) collection.PlanInfo {
	proc := "docker version"
	if cc.Capability == CapContainer {
		proc = "docker ps -a"
	}
	return collection.PlanInfo{
		Capability:  cc.Capability,
		Description: "query the local Docker daemon for " + cc.Capability + " (no network, local socket only)",
		Process:     proc,
	}
}

func (c *Collector) run(ctx context.Context, args ...string) (string, error) {
	// #nosec G204 -- every argument comes from a fixed capability switch.
	cmd := exec.CommandContext(ctx, "docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// Collect implements collection.Collector.
func (c *Collector) Collect(cc *collection.Context) collection.Result {
	if _, err := exec.LookPath("docker"); err != nil {
		return collection.Result{Status: "failed", Message: "docker CLI not found on this system"}
	}
	ctx, cancel := context.WithTimeout(cc.Ctx, 30*time.Second)
	defer cancel()

	switch cc.Capability {
	case CapVersion:
		out, err := c.run(ctx, "version", "--format", "{{.Client.Version}}|{{.Server.Version}}")
		info := VersionInfo{Available: true, CollectedAt: now()}
		if err != nil {
			info.Available = false
			return result("data/docker/version.json", info, "partial", "docker daemon not reachable: "+err.Error())
		}
		parts := strings.SplitN(strings.TrimSpace(out), "|", 2)
		info.Client = parts[0]
		if len(parts) > 1 {
			info.Server = parts[1]
		}
		return result("data/docker/version.json", info, "success", "")

	case CapContainer:
		out, err := c.run(ctx, "ps", "-a", "--format", "json")
		info := ContainersInfo{Available: true, CollectedAt: now()}
		if err != nil {
			info.Available = false
			return result("data/docker/containers.json", info, "failed", "docker ps failed: "+err.Error())
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var row struct {
				Names  string `json:"Names"`
				State  string `json:"State"`
				Status string `json:"Status"`
				Image  string `json:"Image"`
				Health string `json:"Health"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				continue
			}
			name := strings.TrimPrefix(row.Names, "/")
			info.Containers = append(info.Containers, Container{
				Name: name, State: row.State, Status: row.Status, Image: row.Image, Health: row.Health,
			})
			// Cap the list to bound output.
			if len(info.Containers) >= 100 {
				break
			}
		}
		return result("data/docker/containers.json", info, "success", "")
	}
	return collection.Result{Status: "unsupported", Message: "unknown docker capability"}
}

func result(path string, v any, status protocol.CollectionStatus, msg string) collection.Result {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"unmarshalable"}`)
	}
	return collection.Result{
		Status:  status,
		Message: msg,
		Bytes:   int64(len(b)),
		Files: map[string]collection.CollectedFile{
			path: {Content: b, MediaType: "application/json", CollectedAt: time.Now().UTC()},
		},
	}
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
