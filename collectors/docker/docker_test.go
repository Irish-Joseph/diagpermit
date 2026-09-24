package docker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Irish-Joseph/diagpermit/internal/collection"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func TestCollectContainerState(t *testing.T) {
	c := &Collector{
		lookPath: func(name string) (string, error) { return name, nil },
		runFn: func(_ context.Context, args ...string) (string, error) {
			if len(args) != 4 || args[0] != "ps" || args[1] != "-a" || args[2] != "--format" || args[3] != "json" {
				t.Fatalf("unexpected arguments: %v", args)
			}
			return `{"Names":"/diagshop-db","State":"exited","Status":"Exited (1)","Image":"postgres:16","Health":"unhealthy"}` + "\n", nil
		},
	}
	got := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapContainer})
	if got.Status != protocol.StatusSuccess {
		t.Fatalf("status = %q, want success: %s", got.Status, got.Message)
	}
	var info ContainersInfo
	if err := json.Unmarshal(got.Files["data/docker/containers.json"].Content, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.Containers) != 1 || info.Containers[0].Name != "diagshop-db" || info.Containers[0].State != "exited" {
		t.Fatalf("unexpected containers: %+v", info.Containers)
	}
}

func TestDockerDaemonUnavailable(t *testing.T) {
	c := &Collector{
		lookPath: func(name string) (string, error) { return name, nil },
		runFn:    func(context.Context, ...string) (string, error) { return "", errors.New("daemon unavailable") },
	}
	got := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapVersion})
	if got.Status != protocol.StatusPartial {
		t.Fatalf("status = %q, want partial", got.Status)
	}
}

func TestDockerCLIMissing(t *testing.T) {
	c := &Collector{lookPath: func(string) (string, error) { return "", errors.New("not found") }}
	got := c.Collect(&collection.Context{Ctx: context.Background(), Capability: CapContainer})
	if got.Status != protocol.StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
}
