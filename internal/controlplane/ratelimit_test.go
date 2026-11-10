package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

func TestRateLimit_Seals(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	for i := range limitSessionSeals.max {
		if rec := sh.seal(sess.ID, billing, "k", "v"); rec.Code != http.StatusAccepted {
			t.Fatalf("seal %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	// past the session's limit
	rec := sh.seal(sess.ID, billing, "k", "v")
	retry, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
	if rec.Code != http.StatusTooManyRequests || retry < 1 || retry > 60 || !strings.Contains(rec.Body.String(), "try again in") {
		t.Fatalf("seal past the limit = %d %s, Retry-After %q", rec.Code, rec.Body, rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(sh.logs.String(), "event=request.rate_limited") {
		t.Error("the refusal was not logged")
	}
	// other sessions have their own limit, but the user's own limit spans
	// them; refused requests count too
	other := "/api/v1/repos/example-org/platform/session/01J0000000000000000000000Z/seals"
	for i := range limitSeals.max - limitSessionSeals.max {
		if rec := sh.do("alice", http.MethodPost, other, map[string]string{"path": billing, "key": "k", "value": "v"}, true); rec.Code != http.StatusNotFound {
			t.Fatalf("seal %d in another session = %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := sh.do("alice", http.MethodPost, other, map[string]string{"path": billing, "key": "k", "value": "v"}, true); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("seal past the user's limit = %d %s", rec.Code, rec.Body)
	}

	// the next minute starts afresh
	sh.advance(time.Minute)
	for id := range sh.agents {
		sh.checkIn(id, sh.key.Key)
	}
	if rec := sh.seal(sess.ID, billing, "k", "v"); rec.Code != http.StatusAccepted {
		t.Fatalf("seal in the next minute = %d %s", rec.Code, rec.Body)
	}
}

func TestRateLimit_PerUser(t *testing.T) {
	sh := newSealHarness(t)
	for i := range limitRepos.max {
		if rec := sh.do("alice", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusOK {
			t.Fatalf("list %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := sh.do("alice", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("list past the limit = %d %s", rec.Code, rec.Body)
	}
	if rec := sh.do("bob", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("another user's list = %d %s", rec.Code, rec.Body)
	}
	// other calls have their own limits
	if rec := sh.do("alice", http.MethodGet, "/api/v1/repos/example-org/apps/files", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("files = %d %s", rec.Code, rec.Body)
	}
}

// failingCounts is a store that cannot count requests.
type failingCounts struct{ *store.Memory }

func (failingCounts) CountRequest(context.Context, string, int, time.Time) (bool, error) {
	return false, errors.New("throttled")
}

func TestRateLimit_LetsRequestsThroughWhenItCannotCount(t *testing.T) {
	s := New(Options{Store: failingCounts{store.NewMemory()}})
	served := false
	h := s.limit(func(http.ResponseWriter, *http.Request) { served = true }, limitRepos)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/repos", nil)
	req = req.WithContext(userauth.WithUser(req.Context(), &userauth.User{ID: 1001, Login: "alice"}))
	h(httptest.NewRecorder(), req)
	if !served {
		t.Fatal("a request was refused because its count failed")
	}
}
