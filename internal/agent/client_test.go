package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// fakeServer is a minimal control plane: it issues numbered sessions and can
// be told to reject the next check-in's session.
type fakeServer struct {
	logins      atomic.Int32
	checkins    atomic.Int32
	rejectNext  atomic.Bool
	lastToken   atomic.Value
	expiresIn   atomic.Int64 // nanoseconds
	lastSession atomic.Value
}

func (f *fakeServer) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.SessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != protocol.MethodK8sOIDC {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		f.lastToken.Store(req.Token)
		n := f.logins.Add(1)
		session := "session-" + strconv.Itoa(int(n))
		f.lastSession.Store(session)
		_ = json.NewEncoder(w).Encode(protocol.SessionResponse{Token: session, ExpiresAt: time.Now().Add(time.Duration(f.expiresIn.Load())), AgentID: "use1-blue", Env: "dev"})
	})
	mux.HandleFunc("POST /agent/v1/checkin", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.lastSession.Load().(string) || f.rejectNext.Swap(false) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.UserAgent(), "k8s-sealed-secrets-sealer-agent/") {
			t.Errorf("headers = %v", r.Header)
		}
		f.checkins.Add(1)
		_ = json.NewEncoder(w).Encode(protocol.CheckInResponse{NextCheckInSeconds: 15})
	})
	return mux
}

func newClient(t *testing.T, srv *httptest.Server, token string) *Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewClient(ClientOptions{BaseURL: srv.URL + "/", Identity: K8sTokenIdentity{TokenFile: path}, Version: "test"})
}

func TestClient_LogsInOnceAndReusesSession(t *testing.T) {
	f := &fakeServer{}
	f.expiresIn.Store(int64(15 * time.Minute))
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := newClient(t, srv, "projected-token")

	for range 3 {
		if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
			t.Fatal(err)
		}
	}
	if f.logins.Load() != 1 || f.checkins.Load() != 3 {
		t.Fatalf("logins=%d checkins=%d", f.logins.Load(), f.checkins.Load())
	}
	if got := f.lastToken.Load(); got != "projected-token" {
		t.Errorf("login token = %q (must be trimmed)", got)
	}
	if c.AgentID() != "use1-blue" {
		t.Errorf("AgentID = %q", c.AgentID())
	}
}

func TestClient_LogsInAgainWhenSessionRejectedOrExpiring(t *testing.T) {
	f := &fakeServer{}
	f.expiresIn.Store(int64(15 * time.Minute))
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := newClient(t, srv, "projected-token")

	if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
		t.Fatal(err)
	}
	f.rejectNext.Store(true)
	if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
		t.Fatalf("check-in after a rejected session: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins = %d, want 2", f.logins.Load())
	}

	// a session about to expire is renewed before use
	f.expiresIn.Store(int64(30 * time.Second))
	c.dropSession(c.session)
	for range 2 {
		if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
			t.Fatal(err)
		}
	}
	if f.logins.Load() != 4 {
		t.Fatalf("logins = %d, want 4", f.logins.Load())
	}
}

func TestClient_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newClient(t, srv, "projected-token")
	if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err == nil || !strings.Contains(err.Error(), "failed to log in") {
		t.Fatalf("err = %v", err)
	}

	missing := NewClient(ClientOptions{BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: filepath.Join(t.TempDir(), "absent")}})
	if _, err := missing.CheckIn(context.Background(), protocol.CheckIn{}); err == nil || !strings.Contains(err.Error(), "identity token") {
		t.Fatalf("err = %v", err)
	}
}

func TestClient_RefusesControlPlaneOfAnotherEnv(t *testing.T) {
	f := &fakeServer{}
	f.expiresIn.Store(int64(15 * time.Minute))
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientOptions{BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: path}, Env: "prod", Version: "test"})
	if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err == nil || !strings.Contains(err.Error(), `serves env "dev"`) {
		t.Fatalf("err = %v", err)
	}
	if f.checkins.Load() != 0 {
		t.Fatal("checked in with a control plane of another env")
	}
}

func TestClient_EscrowPathIsOneSegment(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.SessionResponse{Token: "s", ExpiresAt: time.Now().Add(time.Hour), AgentID: "a", Env: "dev"})
	})
	mux.HandleFunc("GET /agent/v1/escrow/{fp}", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_ = json.NewEncoder(w).Encode(protocol.EscrowRecord{Fingerprint: protocol.ParseFingerprintPath(r.PathValue("fp"))})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newClient(t, srv, "t")

	fp := "SHA256:ab+c/d"
	rec, err := c.GetEscrow(context.Background(), fp)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/agent/v1/escrow/SHA256:ab-c_d" || rec.Fingerprint != fp {
		t.Fatalf("path = %q, fingerprint = %q", gotPath, rec.Fingerprint)
	}
}

// Every request names the agent's env, so a control plane serving several
// envs sends it to this one.
func TestClient_NamesItsEnv(t *testing.T) {
	var envs []string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, r *http.Request) {
		envs = append(envs, r.Header.Get(protocol.EnvHeader))
		_ = json.NewEncoder(w).Encode(protocol.SessionResponse{Token: "s", ExpiresAt: time.Now().Add(time.Hour), AgentID: "a", Env: "prod"})
	})
	mux.HandleFunc("POST /agent/v1/checkin", func(w http.ResponseWriter, r *http.Request) {
		envs = append(envs, r.Header.Get(protocol.EnvHeader))
		_ = json.NewEncoder(w).Encode(protocol.CheckInResponse{NextCheckInSeconds: 15})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(ClientOptions{BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: path}, Env: "prod", Version: "test"})
	if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(envs, ",") != "prod,prod" {
		t.Fatalf("env headers = %q", envs)
	}
}

func tokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The check-in and command loops start together; their logins must not
// race, or the control plane refuses the second signed request as a replay.
func TestClient_OneLoginAtATime(t *testing.T) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, _ *http.Request) {
		logins.Add(1)
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(protocol.SessionResponse{Token: "s", ExpiresAt: time.Now().Add(time.Hour), AgentID: "a", Env: "dev"})
	})
	mux.HandleFunc("POST /agent/v1/checkin", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.CheckInResponse{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(ClientOptions{BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: tokenFile(t)}})

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1", n)
	}
}

// A redirect would resend a signed login or an escrowed key elsewhere.
func TestClient_DoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/elsewhere", func(http.ResponseWriter, *http.Request) { followed.Store(true) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(ClientOptions{BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: tokenFile(t)}, HTTPClient: srv.Client()})
	if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("err = %v", err)
	}
	if followed.Load() {
		t.Fatal("the redirect was followed")
	}
}

// A response cut at the size limit must fail as too large, not as JSON
// that does not parse.
func TestClient_RefusesOversizedResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.SessionResponse{Token: "s", ExpiresAt: time.Now().Add(time.Hour), AgentID: "a"})
	})
	mux.HandleFunc("GET /agent/v1/commands", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"commands":[{"id":"%s"}]}`, strings.Repeat("x", maxResponseBytes))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(ClientOptions{BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: tokenFile(t)}})
	if _, err := c.Commands(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}

// Sessions and commands expire in the control plane's time, so a clock that
// is off must not make every session look expired.
func TestClient_UsesTheControlPlanesClock(t *testing.T) {
	cpNow := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	local := cpNow.Add(20 * time.Minute) // this agent's clock is 20 minutes fast
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/session", func(w http.ResponseWriter, _ *http.Request) {
		logins.Add(1)
		w.Header().Set("Date", cpNow.Format(http.TimeFormat))
		_ = json.NewEncoder(w).Encode(protocol.SessionResponse{Token: "s", ExpiresAt: cpNow.Add(15 * time.Minute), AgentID: "a"})
	})
	mux.HandleFunc("POST /agent/v1/checkin", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", cpNow.Format(http.TimeFormat))
		_ = json.NewEncoder(w).Encode(protocol.CheckInResponse{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var logs bytes.Buffer
	c := NewClient(ClientOptions{
		BaseURL: srv.URL, Identity: K8sTokenIdentity{TokenFile: tokenFile(t)},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)), Now: func() time.Time { return local },
	})
	for range 3 {
		if _, err := c.CheckIn(context.Background(), protocol.CheckIn{}); err != nil {
			t.Fatal(err)
		}
	}
	if n := logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1: the session looked expired by the agent's clock", n)
	}
	if got := c.Now(); !got.Equal(cpNow) {
		t.Fatalf("Now = %s, want the control plane's %s", got, cpNow)
	}
	if !strings.Contains(logs.String(), "event=agent.clock_skew") {
		t.Errorf("skew not logged:\n%s", logs.String())
	}
}

func TestRetryable(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"unreachable":   {&url.Error{Op: "Post", URL: "https://cp", Err: errors.New("connection refused")}, true},
		"server error":  {&statusError{code: http.StatusBadGateway}, true},
		"throttled":     {&statusError{code: http.StatusTooManyRequests}, true},
		"refused":       {&statusError{code: http.StatusConflict}, false},
		"bad request":   {&statusError{code: http.StatusBadRequest}, false},
		"unauthorized":  {errUnauthorized, false},
		"not found":     {fmt.Errorf("x: %w", errNotFound), false},
		"shutting down": {&url.Error{Op: "Post", URL: "https://cp", Err: context.Canceled}, false},
		"other":         {errors.New("failed to decode"), false},
	}
	for name, tc := range cases {
		if got := retryable(tc.err); got != tc.want {
			t.Errorf("%s: retryable = %v, want %v", name, got, tc.want)
		}
	}
}
