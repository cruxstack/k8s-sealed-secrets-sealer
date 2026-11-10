package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// reloadHarness serves an env whose registry can be changed under it.
type reloadHarness struct {
	t     *testing.T
	h     http.Handler
	logs  *bytes.Buffer
	clock time.Time

	mu      sync.Mutex
	next    *registry.Registry
	failure error
	reads   int
}

func parseRegistry(t *testing.T, agents string) *registry.Registry {
	t.Helper()
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
`+agents), "")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// loginsFor accepts "<agent id>-token" for each agent in reg.
func loginsFor(reg *registry.Registry) map[string]LoginVerifier {
	tokens := map[string]string{}
	for _, a := range reg.Agents {
		tokens[a.ID+"-token"] = a.ID
	}
	return map[string]LoginVerifier{protocol.MethodK8sOIDC: fakeVerifier{reg: reg, tokens: tokens}}
}

func newReloadHarness(t *testing.T, reg *registry.Registry) *reloadHarness {
	t.Helper()
	sessions, err := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	rh := &reloadHarness{t: t, logs: &bytes.Buffer{}, clock: time.Now()}
	srv := New(Options{
		Logger:   slog.New(slog.NewTextHandler(rh.logs, nil)),
		Env:      "dev",
		Registry: reg,
		Logins:   loginsFor(reg),
		ReloadRegistry: func(context.Context) (*registry.Registry, map[string]LoginVerifier, error) {
			rh.mu.Lock()
			defer rh.mu.Unlock()
			rh.reads++
			if rh.failure != nil {
				return nil, nil, rh.failure
			}
			next := rh.next
			rh.next = nil
			if next == nil {
				return nil, nil, nil
			}
			return next, loginsFor(next), nil
		},
		Sessions:   sessions,
		Store:      store.NewMemory(),
		AdminToken: adminToken,
		Now:        func() time.Time { return rh.clock },
	})
	rh.h = srv.Handler()
	return rh
}

func (rh *reloadHarness) do(method, path, auth string, body any) *httptest.ResponseRecorder {
	rh.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			rh.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	rh.h.ServeHTTP(rec, req)
	return rec
}

func (rh *reloadHarness) login(id string) (string, int) {
	rec := rh.do(http.MethodPost, "/agent/v1/session", "", protocol.SessionRequest{Method: protocol.MethodK8sOIDC, Token: id + "-token"})
	var resp protocol.SessionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	return resp.Token, rec.Code
}

func (rh *reloadHarness) checkIn(session string) int {
	rh.t.Helper()
	return rh.do(http.MethodPost, "/agent/v1/checkin", session, checkIn(protoKey(rh.t, rh.clock.Add(-time.Hour)))).Code
}

func (rh *reloadHarness) fleetIDs() []string {
	rh.t.Helper()
	rec := rh.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil)
	var f fleet.Fleet
	if err := json.NewDecoder(rec.Body).Decode(&f); err != nil {
		rh.t.Fatalf("fleet = %d %s", rec.Code, rec.Body)
	}
	var ids []string
	for _, a := range f.Agents {
		ids = append(ids, a.ID)
	}
	return ids
}

func (rh *reloadHarness) readCount() int {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return rh.reads
}

// An agent removed from the registry loses access when the registry is
// next read, without a restart; a registry that cannot be read leaves the
// one in force.
func TestRegistryReload(t *testing.T) {
	const (
		use1 = "  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:a:agent\"}}}\n"
		use2 = "  - {id: use2-blue, cluster: blue, region: use2, capabilities: [seal], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:b:agent\"}}}\n"
	)
	rh := newReloadHarness(t, parseRegistry(t, use1+use2))
	session, code := rh.login("use1-blue")
	if code != http.StatusOK || rh.checkIn(session) != http.StatusOK {
		t.Fatalf("login = %d", code)
	}

	// use1-blue is removed; nothing is read before a minute has passed
	rh.next = parseRegistry(t, use2)
	if rh.checkIn(session) != http.StatusOK || rh.readCount() != 0 {
		t.Fatalf("the registry was read %d times within a minute", rh.readCount())
	}

	// a read that fails keeps the registry in force, and is not retried on
	// every request
	rh.mu.Lock()
	rh.failure = errors.New("parameter not found")
	rh.mu.Unlock()
	rh.clock = rh.clock.Add(RegistryReloadInterval)
	for range 3 {
		if code := rh.checkIn(session); code != http.StatusOK {
			t.Fatalf("check-in after a failed read = %d", code)
		}
	}
	if n := rh.readCount(); n != 1 || !strings.Contains(rh.logs.String(), "event=registry.reload_failed") {
		t.Fatalf("reads = %d, logs:\n%s", n, rh.logs)
	}

	// the next read takes effect for sessions, logins and the fleet alike
	rh.mu.Lock()
	rh.failure = nil
	rh.mu.Unlock()
	rh.clock = rh.clock.Add(RegistryReloadInterval)
	if code := rh.checkIn(session); code != http.StatusUnauthorized {
		t.Fatalf("check-in by a removed agent = %d, want 401", code)
	}
	if !strings.Contains(rh.logs.String(), "event=registry.reloaded") {
		t.Fatalf("logs:\n%s", rh.logs)
	}
	if _, code := rh.login("use1-blue"); code != http.StatusUnauthorized {
		t.Fatalf("login by a removed agent = %d, want 401", code)
	}
	if ids := rh.fleetIDs(); strings.Join(ids, ",") != "use2-blue" {
		t.Fatalf("fleet = %v", ids)
	}

	// an unchanged registry keeps the one in force
	rh.clock = rh.clock.Add(RegistryReloadInterval)
	if _, code := rh.login("use2-blue"); code != http.StatusOK || rh.readCount() != 3 {
		t.Fatalf("login after an unchanged read = %d, reads = %d", code, rh.readCount())
	}
}
