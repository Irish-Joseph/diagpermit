package requestauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func testRequest() *protocol.DiagnosticRequest {
	r := &protocol.DiagnosticRequest{
		ProtocolVersion: protocol.ProtocolVersion,
		Requester:       protocol.Requester{Name: "Example Support"},
		Purpose:         protocol.Purpose{Code: "support", Description: "Diagnose a local failure"},
		Capabilities: map[string]protocol.Capability{
			"system.os": {Requirement: protocol.RequirementRequiredForCase},
		},
	}
	r.Request.ID = "case-123"
	return r
}

func TestSignAndVerifyTrustStates(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(testRequest(), "key-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	key := TrustKey{KeyID: "key-1", Identity: "support@example.test", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	result := Verify(envelope, &TrustStore{Keys: []TrustKey{key}})
	if result.Status != StatusValidUntrusted {
		t.Fatalf("status = %s, want %s (%s)", result.Status, StatusValidUntrusted, result.Detail)
	}
	key.TrustedRequesters = []string{"Example Support"}
	result = Verify(envelope, &TrustStore{Keys: []TrustKey{key}})
	if result.Status != StatusVerified {
		t.Fatalf("status = %s, want %s (%s)", result.Status, StatusVerified, result.Detail)
	}
	result = Verify(envelope, nil)
	if result.Status != StatusNotVerified {
		t.Fatalf("status = %s, want %s", result.Status, StatusNotVerified)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	pub, priv, _ := GenerateKey()
	envelope, _ := Sign(testRequest(), "key-1", priv)
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	payload[10] ^= 1
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, _ := json.Marshal(env)
	result := Verify(tampered, &TrustStore{Keys: []TrustKey{{KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(pub)}}})
	if result.Status != StatusInvalid {
		t.Fatalf("status = %s, want %s", result.Status, StatusInvalid)
	}
}

func TestUnsignedRequestIsExplicit(t *testing.T) {
	b, err := protocol.CanonicalJSON(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	result := Verify(b, nil)
	if result.Status != StatusUnsigned || result.Request == nil {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestMalformedSignatureIsInvalidEvenWithoutTrustKey(t *testing.T) {
	_, priv, _ := GenerateKey()
	envelope, _ := Sign(testRequest(), "unknown-key", priv)
	var env Envelope
	_ = json.Unmarshal(envelope, &env)
	env.Signatures[0].Sig = "not-base64"
	malformed, _ := json.Marshal(env)
	result := Verify(malformed, nil)
	if result.Status != StatusInvalid {
		t.Fatalf("status = %s, want %s", result.Status, StatusInvalid)
	}
}
