// Package requestauth implements requester authentication using the DSSE
// envelope format and Ed25519 signatures. Trust is a separate, explicit local
// policy: a valid signature is not automatically a trusted requester.
package requestauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Irish-Joseph/diagpermit/internal/config"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

const PayloadType = "application/vnd.diagpermit.request.v0.1+json"

type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type TrustKey struct {
	KeyID             string   `json:"keyId"`
	Identity          string   `json:"identity"`
	PublicKey         string   `json:"publicKey"`
	TrustedRequesters []string `json:"trustedRequesters,omitempty"`
}

type TrustStore struct {
	Keys []TrustKey `json:"keys"`
}

type Status string

const (
	StatusUnsigned       Status = "unsigned"
	StatusNotVerified    Status = "signature_not_verified"
	StatusInvalid        Status = "signature_invalid"
	StatusValidUntrusted Status = "signature_valid_identity_untrusted"
	StatusVerified       Status = "requester_verified"
)

type Result struct {
	Status   Status                      `json:"status"`
	Label    string                      `json:"label"`
	Detail   string                      `json:"detail"`
	KeyID    string                      `json:"keyId,omitempty"`
	Identity string                      `json:"identity,omitempty"`
	Request  *protocol.DiagnosticRequest `json:"-"`
	Payload  []byte                      `json:"-"`
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func MarshalPrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}

func MarshalPublicKey(key ed25519.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}), nil
}

func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected PKCS#8 PRIVATE KEY PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return key, nil
}

func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	data := []byte(value)
	if block, _ := pem.Decode(data); block != nil {
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		key, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not Ed25519")
		}
		return key, nil
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("publicKey must be Ed25519 PEM or base64 raw bytes")
	}
	return ed25519.PublicKey(raw), nil
}

// Sign creates a DSSE v1 envelope over canonical request JSON.
func Sign(req *protocol.DiagnosticRequest, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("key ID is required")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key length")
	}
	payload, err := protocol.CanonicalJSON(req)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, PAE(PayloadType, payload))
	env := Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	return json.MarshalIndent(env, "", "  ")
}

// PAE is DSSE v1 pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

func LoadTrustStore(path string) (*TrustStore, error) {
	// #nosec G304 -- trust store path is explicitly selected by the local user.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("trust store exceeds 1 MiB limit")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var store TrustStore
	if err := dec.Decode(&store); err != nil {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("trust store contains multiple JSON values")
		}
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if len(store.Keys) == 0 {
		return nil, errors.New("trust store contains no keys")
	}
	seen := map[string]bool{}
	for _, key := range store.Keys {
		if strings.TrimSpace(key.KeyID) == "" || strings.TrimSpace(key.Identity) == "" || strings.TrimSpace(key.PublicKey) == "" {
			return nil, errors.New("every trust-store key requires keyId, identity, and publicKey")
		}
		if seen[key.KeyID] {
			return nil, fmt.Errorf("duplicate trust-store keyId %q", key.KeyID)
		}
		seen[key.KeyID] = true
		if _, err := ParsePublicKey(key.PublicKey); err != nil {
			return nil, fmt.Errorf("key %q: %w", key.KeyID, err)
		}
	}
	return &store, nil
}

// Verify validates the request first, then verifies each signature for which a
// key is locally available. It never treats an unknown key ID as invalid.
func Verify(data []byte, store *TrustStore) Result {
	var env Envelope
	if err := decodeEnvelope(data, &env); err != nil || env.PayloadType == "" {
		req, loadErr := config.LoadJSON(data)
		if loadErr != nil {
			req, loadErr = config.LoadBytes(data, "request")
		}
		if loadErr == nil {
			return Result{Status: StatusUnsigned, Label: "UNSIGNED", Detail: "Request has no cryptographic signature.", Request: req, Payload: data}
		}
		return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "Document is neither a valid request nor a DSSE envelope."}
	}
	if env.PayloadType != PayloadType {
		return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "Unsupported DSSE payload type."}
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "DSSE payload is not valid base64."}
	}
	req, err := config.LoadJSON(payload)
	if err != nil {
		return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "Signed payload is not a valid DiagPermit request."}
	}
	if len(env.Signatures) == 0 {
		return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "DSSE envelope contains no signatures.", Request: req, Payload: payload}
	}
	decodedSignatures := make(map[int][]byte, len(env.Signatures))
	for i, signature := range env.Signatures {
		sig, sigErr := base64.StdEncoding.DecodeString(signature.Sig)
		if sigErr != nil || len(sig) != ed25519.SignatureSize {
			return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "DSSE signature is malformed.", Request: req, Payload: payload}
		}
		decodedSignatures[i] = sig
	}
	keys := map[string]TrustKey{}
	if store != nil {
		for _, key := range store.Keys {
			keys[key.KeyID] = key
		}
	}
	checked := false
	for i, signature := range env.Signatures {
		trustedKey, ok := keys[signature.KeyID]
		if !ok {
			continue
		}
		checked = true
		pub, keyErr := ParsePublicKey(trustedKey.PublicKey)
		if keyErr != nil || !ed25519.Verify(pub, PAE(env.PayloadType, payload), decodedSignatures[i]) {
			continue
		}
		result := Result{Status: StatusValidUntrusted, Label: "SIGNATURE VALID — IDENTITY NOT TRUSTED", Detail: "Signature is valid, but local policy does not trust this key for the named requester.", KeyID: signature.KeyID, Identity: trustedKey.Identity, Request: req, Payload: payload}
		if requesterTrusted(req.Requester.Name, trustedKey.TrustedRequesters) {
			result.Status = StatusVerified
			result.Label = "REQUESTER VERIFIED"
			result.Detail = "Signature and local requester trust policy both passed."
		}
		return result
	}
	if checked {
		return Result{Status: StatusInvalid, Label: "SIGNATURE INVALID", Detail: "No signature verified with a matching local key.", Request: req, Payload: payload}
	}
	return Result{Status: StatusNotVerified, Label: "SIGNATURE NOT VERIFIED", Detail: "No matching verification key is present in the local trust store.", Request: req, Payload: payload}
}

func requesterTrusted(requester string, allowed []string) bool {
	for _, value := range allowed {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(requester)) {
			return true
		}
	}
	return false
}

func decodeEnvelope(data []byte, dst *Envelope) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
