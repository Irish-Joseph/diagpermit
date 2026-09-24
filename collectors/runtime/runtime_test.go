package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func TestCollectRuntimeVersion(t *testing.T) {
	c := &Collector{
		lookPath: func(name string) (string, error) { return name, nil },
		run: func(_ context.Context, bin string, args ...string) (string, error) {
			if bin != "python3" || len(args) != 1 || args[0] != "--version" {
				t.Fatalf("unexpected command: %s %v", bin, args)
			}
			return "Python 3.13.7\nignored", nil
		},
	}
	got := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapPython})
	if got.Status != protocol.StatusSuccess {
		t.Fatalf("status = %q, want success: %s", got.Status, got.Message)
	}
	var info RuntimeInfo
	if err := json.Unmarshal(got.Files["data/runtime/python.json"].Content, &info); err != nil {
		t.Fatal(err)
	}
	if info.Binary != "python3" || info.Version != "Python 3.13.7" || !info.Available {
		t.Fatalf("unexpected runtime info: %+v", info)
	}
}

func TestCollectMissingRuntime(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "", errors.New("not found") },
		run:      func(context.Context, string, ...string) (string, error) { t.Fatal("run called"); return "", nil },
	}
	got := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapNode})
	if got.Status != protocol.StatusPartial {
		t.Fatalf("status = %q, want partial", got.Status)
	}
}

func TestUnknownRuntimeCapability(t *testing.T) {
	got := New().Collect(&collection.Context{Ctx: context.Background(), Capability: "runtime.unknown"})
	if got.Status != protocol.StatusUnsupported {
		t.Fatalf("status = %q, want unsupported", got.Status)
	}
}
