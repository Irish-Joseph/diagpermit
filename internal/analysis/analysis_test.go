package analysis

import "testing"

func TestAnalyzeReportsStoppedAndUnhealthyContainers(t *testing.T) {
	files := map[string][]byte{
		"data/docker/containers.json": []byte(`{"containers":[{"state":"exited","health":""},{"state":"running","health":"unhealthy"}]}`),
	}
	findings := Analyze(files)
	seen := map[string]bool{}
	for _, finding := range findings {
		seen[finding.ID] = true
	}
	if !seen["DOCKER_CONTAINER_STOPPED"] || !seen["DOCKER_CONTAINER_UNHEALTHY"] {
		t.Fatalf("expected both findings, got %+v", findings)
	}
}
