package pipeline

import (
	"github.com/diagx/diagx/collectors/application"
	"github.com/diagx/diagx/collectors/docker"
	"github.com/diagx/diagx/collectors/runtime"
	"github.com/diagx/diagx/collectors/system"
	"github.com/diagx/diagx/internal/collection"
)

func newSystemCollector() collection.Collector      { return system.New() }
func newRuntimeCollector() collection.Collector     { return runtime.New() }
func newApplicationCollector() collection.Collector { return application.New() }
func newDockerCollector() collection.Collector      { return docker.New() }
