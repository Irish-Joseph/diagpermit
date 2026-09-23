package system

import (
	"encoding/json"
	"time"

	"github.com/diagx/diagx/internal/collection"
)

func files(path string, v any) map[string]collection.CollectedFile {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"unmarshalable"}`)
	}
	return map[string]collection.CollectedFile{
		path: {Content: b, MediaType: "application/json", CollectedAt: time.Now().UTC()},
	}
}
