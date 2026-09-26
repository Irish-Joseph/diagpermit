package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalization ensures hashing structured documents
// requires deterministic serialization. Equivalently-valued documents must
// produce the same hash regardless of whitespace, property ordering or
// (within reason) number formatting.
//
// The V0.1 canonical form is defined as:
//
//  1. Parse the document into a generic structure (object, array,
//     string, number (as originally written), bool, null).
//  2. Object keys are sorted bytewise (lexicographic over UTF-8 bytes).
//  3. Numbers are preserved exactly as the decimal text they were written
//     with (json.Number), so 1.0 and 1.000 remain distinguishable only if
//     an author deliberately wrote them that way.
//  4. Serialize compactly: no insignificant whitespace, standard JSON
//     escaping, no HTML escaping of <, >, &.
//
// This is deliberately close in spirit to JCS (RFC 8785) without pulling
// in a full dependency; the V0.1 corpus consists of machine-generated
// JSON documents with well-defined number shapes.
func CanonicalJSON(v any) ([]byte, error) {
	switch t := v.(type) {
	case []byte:
		return canonicalizeBytes(t)
	case string:
		return canonicalizeBytes([]byte(t))
	default:
		enc, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return canonicalizeBytes(enc)
	}
}

func canonicalizeBytes(b []byte) ([]byte, error) {
	var raw any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("canonicalize: trailing data after JSON document")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			ks, err := marshalJSONString(k)
			if err != nil {
				return err
			}
			buf.Write(ks)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		s, err := marshalJSONString(t)
		if err != nil {
			return err
		}
		buf.Write(s)
	case json.Number:
		// The number is emitted exactly as parsed.
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	default:
		return fmt.Errorf("canonicalize: unsupported value type %T", v)
	}
	return nil
}

// marshalJSONString marshals a string as a JSON string literal without
// HTML escaping.
func marshalJSONString(s string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	// Encoder appends a trailing newline; strip it.
	return bytes.TrimRight(b, "\n"), nil
}

// SHA256 returns "sha256:<hex>" of the raw bytes.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashDocument computes the V0.1 document hash: SHA-256 over the
// canonical JSON form of v, prefixed with "sha256:".
func HashDocument(v any) (string, error) {
	canon, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256(canon), nil
}
