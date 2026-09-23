// Package system implements the V0.1 system collectors (spec section 19):
// operating-system name/version, architecture, CPU architecture, memory
// summary and disk summary. Hostnames and usernames are deliberately NOT
// collected.
package system

import (
	"context"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/diagx/diagx/internal/collection"
	"github.com/diagx/diagx/pkg/protocol"
)

// CollectorID is the stable collector identifier.
const CollectorID = "system"

// Capability IDs provided by this collector.
const (
	CapOS     = "system.os"
	CapMemory = "system.memory"
	CapDisk   = "system.disk"
)

// Collector collects OS, memory and disk metadata.
type Collector struct{}

// New returns the system collector.
func New() *Collector { return &Collector{} }

func (c *Collector) ID() string      { return CollectorID }
func (c *Collector) Version() string { return collection.CollectorVersion }

func (c *Collector) Capabilities() []collection.DeclaredCapability {
	platforms := []string{"linux", "windows", "darwin"}
	return []collection.DeclaredCapability{
		{ID: CapOS, Description: "Operating-system name, version and architecture", Platforms: platforms, MaxOutputBytes: 16 << 10, Sensitivity: "low"},
		{ID: CapMemory, Description: "Memory summary (total/available/used percent)", Platforms: platforms, MaxOutputBytes: 8 << 10, Sensitivity: "low"},
		{ID: CapDisk, Description: "Disk usage summary for mounted volumes", Platforms: platforms, MaxOutputBytes: 64 << 10, Sensitivity: "low"},
	}
}

// Plan describes what the collector would do.
func (c *Collector) Plan(cc *collection.Context) collection.PlanInfo {
	return collection.PlanInfo{
		Capability:  cc.Capability,
		Description: "read OS, memory and disk metadata locally (no network, no shell)",
	}
}

// OSInfo is the data/system/os.json payload.
type OSInfo struct {
	OS           string `json:"os"`
	Platform     string `json:"platform"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	CollectedAt  string `json:"collectedAt"`
}

// MemInfo summarizes memory.
type MemInfo struct {
	TotalBytes     uint64  `json:"totalBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsedPercent    float64 `json:"usedPercent"`
	CollectedAt    string  `json:"collectedAt"`
}

// Disk summarizes one mounted volume. Mount points are included because
// they are required to interpret capacity; nothing else identifying is
// collected.
type Disk struct {
	Mountpoint  string  `json:"mountpoint"`
	FSType      string  `json:"fstype"`
	TotalBytes  uint64  `json:"totalBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

// DisksInfo is the data/system/disks.json payload.
type DisksInfo struct {
	Disks       []Disk `json:"disks"`
	CollectedAt string `json:"collectedAt"`
}

// Collect implements collection.Collector.
func (c *Collector) Collect(cc *collection.Context) collection.Result {
	ctx, cancel := context.WithTimeout(cc.Ctx, 10*time.Second)
	defer cancel()
	collectedAt := time.Now().UTC().Format(time.RFC3339)

	switch cc.Capability {
	case CapOS:
		info := OSInfo{OS: runtime.GOOS, Platform: "unknown", Version: "unknown", Architecture: runtime.GOARCH, CollectedAt: collectedAt}
		status, message := protocol.StatusSuccess, ""
		if h, err := host.InfoWithContext(ctx); err != nil {
			status = protocol.StatusPartial
			message = "host info degraded: " + err.Error()
		} else {
			info.Platform = h.Platform
			info.Version = h.PlatformVersion
		}
		return result("data/system/os.json", info, status, message)

	case CapMemory:
		vm, err := mem.VirtualMemoryWithContext(ctx)
		if err != nil {
			return collection.Result{Status: protocol.StatusFailed, Message: "memory info unavailable: " + err.Error()}
		}
		info := MemInfo{TotalBytes: vm.Total, AvailableBytes: vm.Available, UsedPercent: vm.UsedPercent, CollectedAt: collectedAt}
		return result("data/system/memory.json", info, protocol.StatusSuccess, "")

	case CapDisk:
		parts, err := disk.PartitionsWithContext(ctx, false)
		if err != nil {
			return collection.Result{Status: protocol.StatusFailed, Message: "disk partitions unavailable: " + err.Error()}
		}
		info := DisksInfo{CollectedAt: collectedAt}
		for _, p := range parts {
			if len(info.Disks) >= 10 {
				break
			}
			if u, err := disk.UsageWithContext(ctx, p.Mountpoint); err == nil {
				info.Disks = append(info.Disks, Disk{
					Mountpoint: p.Mountpoint, FSType: p.Fstype,
					TotalBytes: u.Total, UsedBytes: u.Used, UsedPercent: u.UsedPercent,
				})
			}
		}
		if len(info.Disks) == 0 {
			return collection.Result{Status: protocol.StatusPartial, Message: "no disk usage available"}
		}
		return result("data/system/disks.json", info, protocol.StatusSuccess, "")

	default:
		return collection.Result{Status: protocol.StatusUnsupported, Message: "unknown system capability"}
	}
}

func result(path string, value any, status protocol.CollectionStatus, message string) collection.Result {
	result := collection.Result{Status: status, Message: message, Files: files(path, value)}
	for _, file := range result.Files {
		result.Bytes += int64(len(file.Content))
	}
	return result
}
