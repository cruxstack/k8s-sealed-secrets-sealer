package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
