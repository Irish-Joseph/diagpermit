package runtime

import "encoding/json"

func jsonMarshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":"unmarshalable"}`), nil
	}
	return b, nil
}
