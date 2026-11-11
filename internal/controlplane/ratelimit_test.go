package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
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

// failingCounts is a store that cannot count requests, as when DynamoDB
// throttles a busy counter.
type failingCounts struct{ *store.Memory }

func (failingCounts) CountRequest(context.Context, string, int, int, time.Time) (bool, error) {
	return false, errors.New("throttled")
}

// A store that cannot count must not lift the limits: the instance counts
// the requests itself meanwhile.
func TestRateLimit_CountsInTheInstanceWhenTheStoreCannot(t *testing.T) {
	s := New(Options{Store: failingCounts{store.NewMemory()}, Logger: slog.New(slog.DiscardHandler)})
	served := 0
	h := s.limit(func(http.ResponseWriter, *http.Request) { served++ }, limitRepos)
	for range limitRepos.max + 5 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/repos", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req = req.WithContext(userauth.WithUser(req.Context(), &userauth.User{ID: 1001, Login: "alice"}))
		h(httptest.NewRecorder(), req)
	}
	if served != limitRepos.max {
		t.Fatalf("served %d requests, want the limit's %d", served, limitRepos.max)
	}
}

func TestLocalCounts_ForgetsWindowsThatEnded(t *testing.T) {
	var c localCounts
	now := time.Now()
	for i := range maxLocalCounts {
		c.count(strconv.Itoa(i), 1, 1, now, now)
	}
	c.count("current", 1, 1, now.Add(time.Minute), now)
	if n := len(c.counts); n != 1 {
		t.Fatalf("windows = %d, want the one not ended", n)
	}
	if c.count("current", 1, 1, now.Add(time.Minute), now) {
		t.Fatal("a window kept lost its count")
	}
}

// Another site's page can send the user to a limited GET with links and
// redirects; that must not spend the user's limit.
func TestRateLimit_RefusesGETsFromOtherSites(t *testing.T) {
	sh := newSealHarness(t)
	get := func(headers map[string]string) *httptest.ResponseRecorder {
		token, _, _ := sh.users.Issue(testUsers["alice"], userauth.Grants{"dev": false})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/repos", nil)
		req.AddCookie(&http.Cookie{Name: "sealer_session", Value: token})
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		sh.h.ServeHTTP(rec, req)
		return rec
	}
	for name, headers := range map[string]map[string]string{
		"a navigation from another site": {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"},
		"a sibling subdomain's page":     {"Sec-Fetch-Site": "same-site"},
		"a typed URL":                    {"Sec-Fetch-Site": "none"},
		"a browser that says nothing":    {},
	} {
		if rec := get(headers); rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, rec.Code)
		}
	}
	// none of them counted
	for name, headers := range map[string]map[string]string{
		"the UI, by its browser": {"Sec-Fetch-Site": "same-origin"},
		"the UI's scripts":       {"X-Requested-With": "XMLHttpRequest"},
	} {
		for range limitRepos.max / 2 {
			if rec := get(headers); rec.Code != http.StatusOK {
				t.Fatalf("%s = %d %s", name, rec.Code, rec.Body)
			}
		}
	}
}

// A repository list costs a permission lookup on GitHub per repository the
// instance has not checked lately; the lookups, not only the lists, are
// limited.
func TestRateLimit_WeighsListsByTheirLookups(t *testing.T) {
	sh := newSealHarness(t)
	key := "repo-checks#" + strconv.FormatInt(testUsers["alice"].ID, 10)
	end := sh.clock().Truncate(limitRepoChecks.window).Add(limitRepoChecks.window)
	if rec := sh.do("alice", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	// the fixtures' repositories were each looked up once: one more check
	// would pass the limit set just above them
	installed := len(mustFixtures(t))
	if ok, _ := sh.store.CountRequest(context.Background(), key, 0, installed+1, end); !ok {
		t.Fatal("the lookups were counted more than once each")
	}
	if ok, _ := sh.store.CountRequest(context.Background(), key, 0, installed, end); ok {
		t.Fatal("the list's lookups were not counted")
	}

	// a list of what the instance knows costs none
	sh.store.CountRequest(context.Background(), key, limitRepoChecks.max-installed-1, limitRepoChecks.max, end)
	if rec := sh.do("alice", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("list from the cache = %d %s", rec.Code, rec.Body)
	}
	// once the lookups are spent, lists wait for the window to end
	sh.store.CountRequest(context.Background(), key, 1, limitRepoChecks.max, end)
	rec := sh.do("alice", http.MethodGet, "/api/v1/repos", nil, false)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("list past the lookups = %d %s", rec.Code, rec.Body)
	}
	if rec := sh.do("bob", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("another user's list = %d", rec.Code)
	}
	sh.advance(limitRepoChecks.window)
	if rec := sh.do("alice", http.MethodGet, "/api/v1/repos", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("list in the next window = %d %s", rec.Code, rec.Body)
	}
}

func mustFixtures(t *testing.T) []mockgithub.Repo {
	t.Helper()
	f, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	return f
}
