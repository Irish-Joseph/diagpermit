package system

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func TestCapabilitiesCollectOnlyTheirOwnData(t *testing.T) {
	c := New()

	osResult := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapOS})
	osFile, ok := osResult.Files["data/system/os.json"]
	if !ok {
		t.Fatalf("system.os did not produce its expected file: %+v", osResult)
	}
	var osPayload map[string]any
	if err := json.Unmarshal(osFile.Content, &osPayload); err != nil {
		t.Fatal(err)
	}
	if _, leaked := osPayload["memory"]; leaked {
		t.Fatal("system.os must not include memory data")
	}
	if _, leaked := osPayload["disks"]; leaked {
		t.Fatal("system.os must not include disk data")
	}

	memoryResult := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapMemory})
	if _, ok := memoryResult.Files["data/system/memory.json"]; !ok {
		t.Fatalf("system.memory did not produce its expected file: %+v", memoryResult)
	}
	if _, leaked := memoryResult.Files["data/system/os.json"]; leaked {
		t.Fatal("system.memory must not collect OS details")
	}
}

func TestUnknownCapabilityIsUnsupported(t *testing.T) {
	result := New().Collect(&collection.Context{Ctx: context.Background(), Capability: "system.unknown"})
	if result.Status != protocol.StatusUnsupported {
		t.Fatalf("got %q, want %q", result.Status, protocol.StatusUnsupported)
	}
}
