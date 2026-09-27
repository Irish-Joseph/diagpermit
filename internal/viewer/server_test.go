package viewer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

func testServer(t *testing.T) (*server, http.Handler) {
	t.Helper()
	s := &server{token: "unit-test-token", origin: "http://127.0.0.1:43210", tempDir: t.TempDir(), ctx: context.Background()}
	return s, s.routes()
}

func mutationRequest(method, target, body, contentType string) *http.Request {
	r := authenticatedRequest(method, target, body)
	r.Header.Set("Origin", "http://127.0.0.1:43210")
	r.Header.Set("X-DiagPermit-Request", "1")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func authenticatedRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = "127.0.0.1:43210"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "unit-test-token"})
	return r
}

func TestBootstrapUsesOneTimeTokenAndRedirects(t *testing.T) {
	_, handler := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:43210/?token=unit-test-token", nil)
	r.Host = "127.0.0.1:43210"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", w.Code)
	}
	if len(w.Result().Cookies()) != 1 || !w.Result().Cookies()[0].HttpOnly || w.Result().Cookies()[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("secure local session cookie was not set")
	}
}

func TestRejectsHostOriginAndMissingSession(t *testing.T) {
	_, handler := testServer(t)
	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"host", httptest.NewRequest(http.MethodGet, "http://evil.example/api/state", nil), http.StatusBadRequest},
		{"session", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:43210/api/state", nil)
			r.Host = "127.0.0.1:43210"
			return r
		}(), http.StatusUnauthorized},
		{"origin", authenticatedRequest(http.MethodPost, "http://127.0.0.1:43210/api/cancel", ""), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, tt.req)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestSecurityHeadersAndNoCORS(t *testing.T) {
	_, handler := testServer(t)
	r := authenticatedRequest(http.MethodGet, "http://127.0.0.1:43210/api/state", "")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("required browser security headers are missing")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS must not be enabled")
	}
}

func TestRejectsOversizedRequestUpload(t *testing.T) {
	_, handler := testServer(t)
	r := authenticatedRequest(http.MethodPost, "http://127.0.0.1:43210/api/request", strings.Repeat("x", maxRequestBytes+1))
	r.Header.Set("Origin", "http://127.0.0.1:43210")
	r.Header.Set("X-DiagPermit-Request", "1")
	r.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestLocalRequestConsentCollectVerifyFlow(t *testing.T) {
	s, handler := testServer(t)
	req := &protocol.DiagnosticRequest{
		ProtocolVersion: protocol.ProtocolVersion,
		Requester:       protocol.Requester{Name: "Test Support"},
		Purpose:         protocol.Purpose{Code: "test", Description: "Exercise the local viewer flow"},
		Capabilities: map[string]protocol.Capability{
			"system.os": {Requirement: protocol.RequirementRequiredForCase},
		},
	}
	req.Request.ID = "viewer-e2e"
	b, _ := json.Marshal(req)

	for _, step := range []struct {
		path, body, contentType string
		want                    int
	}{
		{"/api/request", string(b), "application/octet-stream", http.StatusOK},
		{"/api/consent", `{"approved":["system.os"],"denied":[]}`, "application/json", http.StatusOK},
		{"/api/collect", "", "", http.StatusAccepted},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, mutationRequest(http.MethodPost, "http://127.0.0.1:43210"+step.path, step.body, step.contentType))
		if w.Code != step.want {
			t.Fatalf("%s status = %d, want %d: %s", step.path, w.Code, step.want, w.Body.String())
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		running, artifact, stateErr := s.state.Running, s.state.Artifact, s.state.Error
		s.mu.RUnlock()
		if !running {
			if stateErr != "" {
				t.Fatal(stateErr)
			}
			if artifact == nil || artifact.Verification.Verdict() != "INTEGRITY VERIFIED" {
				t.Fatal("collection did not produce a verified artifact")
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("collection did not complete")
}
