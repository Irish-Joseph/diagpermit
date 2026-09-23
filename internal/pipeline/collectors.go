package pipeline

import (
	"github.com/Irish-Joseph/diagpermit/collectors/application"
	"github.com/Irish-Joseph/diagpermit/collectors/docker"
	"github.com/Irish-Joseph/diagpermit/collectors/runtime"
	"github.com/Irish-Joseph/diagpermit/collectors/system"
	"github.com/Irish-Joseph/diagpermit/internal/collection"
)

func newSystemCollector() collection.Collector      { return system.New() }
func newRuntimeCollector() collection.Collector     { return runtime.New() }
func newApplicationCollector() collection.Collector { return application.New() }
func newDockerCollector() collection.Collector      { return docker.New() }
