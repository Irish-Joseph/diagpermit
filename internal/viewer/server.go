// Package viewer serves DiagPermit's local-only visual workflow.
package viewer

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Irish-Joseph/diagpermit/internal/artifactview"
	"github.com/Irish-Joseph/diagpermit/internal/consent"
	"github.com/Irish-Joseph/diagpermit/internal/pipeline"
	"github.com/Irish-Joseph/diagpermit/internal/requestauth"
	"github.com/Irish-Joseph/diagpermit/pkg/protocol"
)

const (
	maxRequestBytes  = 4 << 20
	maxArtifactBytes = 260 << 20
	sessionCookie    = "diagpermit_session"
)

//go:embed all:dist
var assets embed.FS

type Options struct {
	Input      string
	TrustStore string
	NoOpen     bool
	Logger     *log.Logger
}

type State struct {
	Request        *protocol.DiagnosticRequest       `json:"request,omitempty"`
	Authentication *requestauth.Result               `json:"authentication,omitempty"`
	Plan           *protocol.EffectiveDisclosurePlan `json:"plan,omitempty"`
	Artifact       *artifactview.Snapshot            `json:"artifact,omitempty"`
	ArtifactName   string                            `json:"artifactName,omitempty"`
	Running        bool                              `json:"running"`
	Error          string                            `json:"error,omitempty"`
	Message        string                            `json:"message,omitempty"`
}

type server struct {
	mu              sync.RWMutex
	state           State
	token           string
	origin          string
	tempDir         string
	artifactPath    string
	requestEnvelope []byte
	trust           *requestauth.TrustStore
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	logger          *log.Logger
	ctx             context.Context
}

// Run starts a loopback-only server and blocks until ctx is cancelled.
func Run(ctx context.Context, opts Options) error {
	tmp, err := os.MkdirTemp("", "diagpermit-viewer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// #nosec G302 -- this is a directory and requires its execute bit; 0700 is owner-only.
	if err := os.Chmod(tmp, 0o700); err != nil && runtime.GOOS != "windows" {
		return err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	s := &server{token: base64.RawURLEncoding.EncodeToString(tokenBytes), tempDir: tmp, logger: opts.Logger, ctx: ctx}
	if s.logger == nil {
		s.logger = log.New(io.Discard, "", 0)
	}
	if opts.TrustStore != "" {
		s.trust, err = requestauth.LoadTrustStore(opts.TrustStore)
		if err != nil {
			return fmt.Errorf("load trust store: %w", err)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	s.origin = "http://" + listener.Addr().String()
	if opts.Input != "" {
		if err := s.loadInput(opts.Input); err != nil {
			return err
		}
	}

	httpServer := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	// #nosec G118 -- shutdown needs a fresh bounded context after ctx is cancelled.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	bootstrap := s.origin + "/?token=" + url.QueryEscape(s.token)
	fmt.Printf("DiagPermit local viewer: %s\n", s.origin)
	fmt.Println("Diagnostic data stays on this machine. Press Ctrl+C to stop.")
	if !opts.NoOpen {
		if err := openBrowser(bootstrap); err != nil {
			fmt.Printf("Open this local session URL in your browser: %s\n", bootstrap)
		}
	} else {
		fmt.Printf("Open this local session URL in your browser: %s\n", bootstrap)
	}
	err = httpServer.Serve(listener)
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /assets/", s.static)
	mux.HandleFunc("GET /api/state", s.apiState)
	mux.HandleFunc("POST /api/request", s.mutate(s.apiRequest))
	mux.HandleFunc("POST /api/consent", s.mutate(s.apiConsent))
	mux.HandleFunc("POST /api/collect", s.mutate(s.apiCollect))
	mux.HandleFunc("POST /api/cancel", s.mutate(s.apiCancel))
	mux.HandleFunc("POST /api/artifact", s.mutate(s.apiArtifact))
	mux.HandleFunc("GET /api/artifact/download", s.apiDownload)
	mux.HandleFunc("GET /api/file", s.apiFile)
	return s.security(mux)
}

func (s *server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		if !validHost(r.Host) {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/" && r.URL.Query().Get("token") != "" {
			if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(s.token)) != 1 {
				http.Error(w, "invalid session token", http.StatusForbidden)
				return
			}
			// #nosec G124 -- Secure cookies are ignored over the intentional HTTP loopback origin; HttpOnly and Strict SameSite are enforced.
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.token)) != 1 {
			http.Error(w, "local viewer session required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) mutate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != s.origin || r.Header.Get("X-DiagPermit-Request") != "1" {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func validHost(host string) bool {
	name, _, err := net.SplitHostPort(host)
	return err == nil && name == "127.0.0.1"
}

func (s *server) index(w http.ResponseWriter, _ *http.Request) {
	b, err := assets.ReadFile("dist/index.html")
	if err != nil {
		http.Error(w, "viewer assets unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// #nosec G705 -- b is a compile-time embedded asset, never request or artifact content.
	_, _ = w.Write(b)
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(assets, "dist/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch filepath.Ext(name) {
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	// #nosec G705 -- b comes only from compile-time embedded viewer assets; artifact content is never served here.
	_, _ = w.Write(b)
}

func (s *server) apiState(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, http.StatusOK, s.state)
}

func (s *server) apiRequest(w http.ResponseWriter, r *http.Request) {
	if media := strings.Split(r.Header.Get("Content-Type"), ";")[0]; media != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, errors.New("content type must be application/octet-stream"))
		return
	}
	b, err := readBounded(r.Body, maxRequestBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	result := requestauth.Verify(b, s.trust)
	if result.Request == nil || result.Status == requestauth.StatusInvalid {
		writeError(w, http.StatusBadRequest, errors.New(result.Detail))
		return
	}
	if expired(result.Request.ExpiresAt) {
		writeError(w, http.StatusBadRequest, errors.New("diagnostic request has expired"))
		return
	}
	s.mu.Lock()
	s.state = State{Request: result.Request, Authentication: &result, Message: "Request loaded. Review every capability before consenting."}
	s.requestEnvelope = nil
	if result.Status != requestauth.StatusUnsigned {
		s.requestEnvelope = append([]byte(nil), b...)
	}
	s.mu.Unlock()
	s.apiState(w, r)
}

type consentInput struct {
	Approved []string `json:"approved"`
	Denied   []string `json:"denied"`
}

func (s *server) apiConsent(w http.ResponseWriter, r *http.Request) {
	var input consentInput
	if err := decodeJSON(r, &input, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.RLock()
	req := s.state.Request
	s.mu.RUnlock()
	if req == nil {
		writeError(w, http.StatusConflict, errors.New("load a request first"))
		return
	}
	b, _ := json.Marshal(input)
	_, plan, warnings, err := consent.Build(r.Context(), req, consent.ModeFile, nil, b)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	s.state.Plan = plan
	s.state.Error = ""
	s.state.Message = "Consent saved locally. Collection has not started."
	if len(warnings) > 0 {
		s.state.Message = strings.Join(warnings, " ")
	}
	s.mu.Unlock()
	s.apiState(w, r)
}

func (s *server) apiCollect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.state.Request == nil || s.state.Plan == nil {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, errors.New("save consent before collecting"))
		return
	}
	if s.state.Running {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, errors.New("collection is already running"))
		return
	}
	req, plan := s.state.Request, s.state.Plan
	requestEnvelope := append([]byte(nil), s.requestEnvelope...)
	input := consentInput{Approved: append([]string(nil), plan.Approved...), Denied: append([]string(nil), plan.Denied...)}
	consentJSON, _ := json.Marshal(input)
	ctx, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	s.state.Running = true
	s.state.Error = ""
	s.state.Message = "Collection running locally…"
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		outputPath := filepath.Join(s.tempDir, "support-"+safeFilename(req.RequestID())+protocol.ArtifactExt)
		out, err := pipeline.RunAuthenticated(ctx, req, consent.ModeFile, nil, consentJSON, outputPath, io.Discard, requestEnvelope)
		var snapshot *artifactview.Snapshot
		if err == nil {
			snapshot, err = artifactview.OpenWithTrust(out.ArtifactPath, s.trust)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.state.Running = false
		s.cancel = nil
		if err != nil {
			if errors.Is(err, context.Canceled) {
				s.state.Message = "Collection cancelled. No shareable artifact was produced."
			} else {
				s.state.Error = err.Error()
				s.state.Message = "Collection stopped safely."
			}
			return
		}
		s.artifactPath = out.ArtifactPath
		s.state.Artifact = snapshot
		s.state.ArtifactName = filepath.Base(out.ArtifactPath)
		s.state.Message = "Collection complete. Nothing was uploaded."
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func (s *server) apiCancel(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil {
		writeError(w, http.StatusConflict, errors.New("no collection is running"))
		return
	}
	s.cancel()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "cancelling"})
}

func (s *server) apiArtifact(w http.ResponseWriter, r *http.Request) {
	if media := strings.Split(r.Header.Get("Content-Type"), ";")[0]; media != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, errors.New("content type must be application/octet-stream"))
		return
	}
	b, err := readBounded(r.Body, maxArtifactBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, err)
		return
	}
	path := filepath.Join(s.tempDir, "opened.diagnostic")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	snapshot, err := artifactview.OpenWithTrust(path, s.trust)
	if err != nil {
		_ = os.Remove(path)
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	s.artifactPath = path
	s.state.Artifact = snapshot
	s.state.ArtifactName = "opened.diagnostic"
	s.state.Message = "Artifact opened locally."
	s.state.Error = ""
	s.mu.Unlock()
	s.apiState(w, r)
}

func (s *server) apiDownload(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	path, name := s.artifactPath, s.state.ArtifactName
	s.mu.RUnlock()
	if path == "" {
		writeError(w, http.StatusConflict, errors.New("open an artifact first"))
		return
	}
	if name == "" {
		name = "support.diagnostic"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeFilename(strings.TrimSuffix(name, protocol.ArtifactExt))+protocol.ArtifactExt))
	http.ServeFile(w, r, path)
}

func (s *server) apiFile(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	path := s.artifactPath
	s.mu.RUnlock()
	if path == "" {
		writeError(w, http.StatusConflict, errors.New("open an artifact first"))
		return
	}
	preview, err := artifactview.Preview(path, r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"content": preview})
}

func (s *server) loadInput(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	maximum := int64(maxRequestBytes)
	if strings.HasSuffix(strings.ToLower(path), protocol.ArtifactExt) {
		maximum = maxArtifactBytes
	}
	if info.Size() > maximum {
		return fmt.Errorf("input exceeds %d byte limit", maximum)
	}
	// #nosec G304 -- the command-line user explicitly selected this path.
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasSuffix(strings.ToLower(path), protocol.ArtifactExt) {
		destination := filepath.Join(s.tempDir, "opened.diagnostic")
		// #nosec G703 -- destination is a fixed filename under the server-created private temp directory.
		if err := os.WriteFile(destination, b, 0o600); err != nil {
			return err
		}
		snapshot, err := artifactview.OpenWithTrust(destination, s.trust)
		if err != nil {
			return err
		}
		s.artifactPath = destination
		s.state.Artifact, s.state.ArtifactName = snapshot, filepath.Base(path)
		return nil
	}
	result := requestauth.Verify(b, s.trust)
	if result.Request == nil || result.Status == requestauth.StatusInvalid {
		return errors.New(result.Detail)
	}
	if expired(result.Request.ExpiresAt) {
		return errors.New("diagnostic request has expired")
	}
	s.state.Request, s.state.Authentication = result.Request, &result
	if result.Status != requestauth.StatusUnsigned {
		s.requestEnvelope = append([]byte(nil), b...)
	}
	return nil
}

func readBounded(r io.Reader, maximum int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maximum {
		return nil, fmt.Errorf("request body exceeds %d bytes", maximum)
	}
	return b, nil
}

func decodeJSON(r *http.Request, dst any, maximum int64) error {
	if media := strings.Split(r.Header.Get("Content-Type"), ";")[0]; media != "application/json" {
		return errors.New("content type must be application/json")
	}
	b, err := readBounded(r.Body, maximum)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func expired(value string) bool {
	if value == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, value)
	return err != nil || t.Before(time.Now())
}

func safeFilename(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "diagnostic"
	}
	return b.String()
}

func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// #nosec G204 -- executable and option are fixed; target is an internally generated loopback URL passed as one argument, never through a shell.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		// #nosec G204 -- executable is fixed and target is an internally generated loopback URL passed as one argument.
		cmd = exec.Command("open", target)
	default:
		// #nosec G204 -- executable is fixed and target is an internally generated loopback URL passed as one argument.
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}
