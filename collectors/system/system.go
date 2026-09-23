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
	OS           string   `json:"os"`
	Platform     string   `json:"platform"`
	Version      string   `json:"version"`
	Architecture string   `json:"architecture"`
	CollectedAt  string   `json:"collectedAt"`
	Memory       *MemInfo `json:"memory,omitempty"`
	Disks        []Disk   `json:"disks,omitempty"`
}

// MemInfo summarizes memory.
type MemInfo struct {
	TotalBytes     uint64  `json:"totalBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsedPercent    float64 `json:"usedPercent"`
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

// Collect implements collection.Collector.
func (c *Collector) Collect(cc *collection.Context) collection.Result {
	res := collection.Result{Status: "success"}
	now := time.Now().UTC().Format(time.RFC3339)

	var info OSInfo
	h, err := host.Info()
	if err != nil {
		// Degraded: still report the kernel-level OS name.
		info = OSInfo{OS: runtime.GOOS, Platform: "unknown", Version: "unknown", Architecture: runtime.GOARCH, CollectedAt: now}
		res.Status = "partial"
		res.Message = "host info degraded: " + err.Error()
	} else {
		info = OSInfo{
			OS:           runtime.GOOS,
			Platform:     h.Platform,
			Version:      h.PlatformVersion,
			Architecture: runtime.GOARCH,
			CollectedAt:  now,
		}
	}

	ctx, cancel := context.WithTimeout(cc.Ctx, 10*time.Second)
	defer cancel()
	_ = ctx

	if vm, err := mem.VirtualMemory(); err == nil {
		info.Memory = &MemInfo{TotalBytes: vm.Total, AvailableBytes: vm.Available, UsedPercent: vm.UsedPercent}
	} else {
		res.Status = "partial"
	}
	if parts, err := disk.Partitions(false); err == nil && len(parts) > 0 {
		for i, p := range parts {
			if i >= 10 {
				break
			}
			if u, err := disk.Usage(p.Mountpoint); err == nil {
				info.Disks = append(info.Disks, Disk{
					Mountpoint: p.Mountpoint, FSType: p.Fstype,
					TotalBytes: u.Total, UsedBytes: u.Used, UsedPercent: u.UsedPercent,
				})
			}
		}
	} else {
		if res.Status == "success" {
			res.Status = "partial"
		}
	}

	switch cc.Capability {
	case CapMemory:
		if info.Memory == nil {
			return collection.Result{Status: "failed", Message: "memory info unavailable"}
		}
		res.Files = files("data/system/os.json", subsetMem(info))
	case CapDisk:
		if len(info.Disks) == 0 {
			return collection.Result{Status: "partial", Message: "no disk usage available"}
		}
		res.Files = files("data/system/os.json", subsetDisk(info))
	default: // system.os (and unknown → full)
		res.Files = files("data/system/os.json", info)
	}
	for _, f := range res.Files {
		res.Bytes += int64(len(f.Content))
	}
	return res
}

func subsetMem(info OSInfo) OSInfo  { return info }
func subsetDisk(info OSInfo) OSInfo { return info }
