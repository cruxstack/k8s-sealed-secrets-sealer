package githubapp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

type fixture struct {
	srv     *httptest.Server
	mock    *mockgithub.Server
	key     *rsa.PrivateKey
	minted  atomic.Int32
	lookups atomic.Int32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	repos, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: testcerts.RSA(t, 2048)}
	f.mock = mockgithub.New(mockgithub.Options{
		Org:   "example-org",
		Users: mockgithub.DefaultUsers(),
		App:   mockgithub.App{ID: "42", PublicKey: &f.key.PublicKey, InstallationID: 7},
		Repos: repos,
	})
	h := f.mock.Handler()
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			f.minted.Add(1)
		case strings.HasSuffix(r.URL.Path, "/installation"):
			f.lookups.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) client(t *testing.T, mutate func(*Options)) *Client {
	t.Helper()
	opts := Options{
		APIURL:     f.srv.URL,
		AppID:      "42",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.key)}),
		Org:        "example-org",
	}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClient_ReadsRepositories(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()

	repos, err := c.Repositories(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 3 || repos[0].FullName != "example-org/apps" || !repos[0].Private || repos[0].DefaultBranch != "main" || repos[0].Owner != "example-org" {
		t.Fatalf("repositories = %+v", repos)
	}

	head, err := c.BranchHead(ctx, "example-org", "apps", "main")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := c.Tree(ctx, "example-org", "apps", head)
	if err != nil {
		t.Fatal(err)
	}
	var blob string
	for _, e := range tree.Entries {
		if e.Path == "deploy/billing/sealed-secret.yaml" && e.Type == "blob" {
			blob = e.SHA
		}
	}
	if blob == "" || tree.Truncated {
		t.Fatalf("tree = %+v", tree)
	}
	content, err := c.Blob(ctx, "example-org", "apps", blob)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := f.mock.File("example-org", "apps", "main", "deploy/billing/sealed-secret.yaml")
	if string(content) != want || !strings.Contains(want, "kind: SealedSecret") {
		t.Fatalf("blob = %q", content)
	}

	// one installation lookup and one token for all of the above
	if f.lookups.Load() != 1 || f.minted.Load() != 1 {
		t.Errorf("installation lookups = %d, tokens minted = %d, want 1 and 1", f.lookups.Load(), f.minted.Load())
	}
}

func TestClient_Permission(t *testing.T) {
	c := newFixture(t).client(t, func(o *Options) { o.Org = ""; o.InstallationID = 7 })
	ctx := context.Background()
	cases := map[string]Permission{
		"alice":         {UserID: 1001, Read: true, Write: true},
		"bob":           {UserID: 1002, Read: true},
		"carol":         {UserID: 1003},
		"nobody-at-all": {},
	}
	for login, want := range cases {
		got, err := c.Permission(ctx, "example-org", "apps", login)
		if err != nil || got != want {
			t.Errorf("%s: permission = %+v, %v; want %+v", login, got, err, want)
		}
	}
	if _, err := c.Permission(ctx, "example-org", "apps", "../alice"); err == nil {
		t.Error("an invalid login was looked up")
	}
}

func TestClient_Errors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	c := f.client(t, nil)
	if _, err := c.Repository(ctx, "example-org", "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing repository: %v", err)
	}
	if _, err := c.BranchHead(ctx, "example-org", "apps", "no-such-branch"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing branch: %v", err)
	}
	if _, err := c.Tree(ctx, "example-org", "apps", "HEAD"); err == nil {
		t.Error("a tree was read by a non-SHA ref")
	}
	if _, err := c.Blob(ctx, "example-org", "apps", strings.Repeat("0", 40)); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing blob: %v", err)
	}

	// a key GitHub does not know
	other := testcerts.RSA(t, 2048)
	wrongKey := f.client(t, func(o *Options) {
		o.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	})
	if _, err := wrongKey.Repositories(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong key: %v", err)
	}
	// an org the App is not installed on
	if _, err := f.client(t, func(o *Options) { o.Org = "elsewhere" }).Repositories(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("other org: %v", err)
	}
}

func TestClient_CachesTokensPerPermissionSet(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	for range 3 {
		if _, err := c.Token(ctx, ReadOnly); err != nil {
			t.Fatal(err)
		}
	}
	if f.minted.Load() != 1 {
		t.Fatalf("minted %d tokens, want 1", f.minted.Load())
	}
	// another permission set is another token
	if _, err := c.Token(ctx, Permissions{"contents": "write", "metadata": "read"}); err != nil {
		t.Fatal(err)
	}
	if f.minted.Load() != 2 {
		t.Fatalf("minted %d tokens, want 2", f.minted.Load())
	}
}

func TestClient_RenewsTokensCloseToExpiry(t *testing.T) {
	f := newFixture(t)
	// tokens that expire within the renewal margin are never reused
	repos, _ := mockgithub.Fixtures()
	short := mockgithub.New(mockgithub.Options{
		Org:   "example-org",
		App:   mockgithub.App{ID: "42", PublicKey: &f.key.PublicKey, InstallationID: 7, TokenTTL: 4 * time.Minute},
		Repos: repos,
	})
	h := short.Handler()
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			f.minted.Add(1)
		}
		h.ServeHTTP(w, r)
	})
	c := f.client(t, nil)
	for range 2 {
		if _, err := c.Token(context.Background(), ReadOnly); err != nil {
			t.Fatal(err)
		}
	}
	if f.minted.Load() != 2 {
		t.Fatalf("minted %d tokens, want 2", f.minted.Load())
	}
}

func TestNew_Rejects(t *testing.T) {
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testcerts.RSA(t, 2048))})
	for name, opts := range map[string]Options{
		"no key":          {AppID: "1", Org: "o"},
		"not pem":         {AppID: "1", Org: "o", PrivateKey: []byte("secret")},
		"no app id":       {Org: "o", PrivateKey: key},
		"no installation": {AppID: "1", PrivateKey: key},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"apps", "example-org", "a.b_c-1"} {
		if !ValidName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a b", strings.Repeat("a", 101), "a%2fb"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClient_RateLimits(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	reset := now.Add(17 * time.Minute)
	cases := map[string]struct {
		status  int
		headers map[string]string
		message string
		want    *RateLimitError // nil: not a rate limit
	}{
		"hourly budget used up": {
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": strconv.FormatInt(reset.Unix(), 10)},
			message: "API rate limit exceeded for installation.",
			want:    &RateLimitError{Status: 403, RetryAt: reset},
		},
		"hourly budget used up, as 429": {
			status:  http.StatusTooManyRequests,
			headers: map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": strconv.FormatInt(reset.Unix(), 10)},
			want:    &RateLimitError{Status: 429, RetryAt: reset},
		},
		"secondary, with retry-after": {
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "30", "X-RateLimit-Remaining": "4000"},
			message: "You have exceeded a secondary rate limit.",
			want:    &RateLimitError{Status: 403, RetryAt: now.Add(30 * time.Second), Secondary: true},
		},
		"secondary, naming no time": {
			status:  http.StatusForbidden,
			message: "You have exceeded a secondary rate limit. Please wait a few minutes before you try again.",
			want:    &RateLimitError{Status: 403, RetryAt: now.Add(time.Minute), Secondary: true},
		},
		"too many requests": {
			status: http.StatusTooManyRequests,
			want:   &RateLimitError{Status: 429, RetryAt: now.Add(time.Minute), Secondary: true},
		},
		"forbidden for another reason": {
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "4000"},
			message: "Resource not accessible by integration",
		},
		"server error": {status: http.StatusBadGateway, message: "Server Error"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/access_tokens") {
					w.WriteHeader(http.StatusCreated)
					_, _ = fmt.Fprintf(w, `{"token":"ghs_x","expires_at":%q}`, now.Add(time.Hour).Format(time.RFC3339))
					return
				}
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"message":%q}`, tc.message)
			}))
			defer srv.Close()
			key := testcerts.RSA(t, 2048)
			c, err := New(Options{
				APIURL: srv.URL, AppID: "1", InstallationID: 7, Now: func() time.Time { return now },
				PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Repository(context.Background(), "example-org", "apps")
			var limited *RateLimitError
			if tc.want == nil {
				var refusal *StatusError
				if errors.As(err, &limited) || !errors.As(err, &refusal) || refusal.Status != tc.status {
					t.Fatalf("err = %v, want a %d that is not a rate limit", err, tc.status)
				}
				return
			}
			if !errors.As(err, &limited) || limited.Status != tc.want.Status || !limited.RetryAt.Equal(tc.want.RetryAt) ||
				limited.Secondary != tc.want.Secondary {
				t.Fatalf("err = %#v, want %#v", err, tc.want)
			}
			if d := limited.RetryAfter(now); d != tc.want.RetryAt.Sub(now) {
				t.Errorf("retry after %s", d)
			}
		})
	}
	// a reset already past still waits a little
	if d := (&RateLimitError{RetryAt: now.Add(-time.Minute)}).RetryAfter(now); d != time.Second {
		t.Errorf("retry after a past reset = %s", d)
	}
}

func TestClient_WarnsOnceWhenTheRateLimitRunsLow(t *testing.T) {
	f := newFixture(t)
	repos, _ := mockgithub.Fixtures()
	limited := mockgithub.New(mockgithub.Options{
		Org: "example-org", Users: mockgithub.DefaultUsers(), Repos: repos, RateLimit: 20,
		App: mockgithub.App{ID: "42", PublicKey: &f.key.PublicKey, InstallationID: 7},
	})
	f.srv.Config.Handler = limited.Handler()
	var logs bytes.Buffer
	c := f.client(t, func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(&logs, nil)) })
	ctx := context.Background()
	var err error
	for i := 0; i < 20 && err == nil; i++ {
		_, err = c.Repository(ctx, "example-org", "apps")
	}
	if err != nil {
		t.Fatalf("within the limit: %v", err)
	}
	// warned once two of twenty were left, and not again
	if n := strings.Count(logs.String(), "event=github.rate_limit_low"); n != 1 || !strings.Contains(logs.String(), "remaining=2 limit=20") {
		t.Fatalf("%d warnings:\n%s", n, logs.String())
	}
	_, err = c.Repository(ctx, "example-org", "apps")
	var refused *RateLimitError
	if !errors.As(err, &refused) || refused.Secondary || !refused.RetryAt.After(time.Now().Add(50*time.Minute)) {
		t.Fatalf("past the limit: %#v", err)
	}

	// the next window warns again when it runs low
	limited.ResetRateLimit()
	for range 18 {
		if _, err := c.Repository(ctx, "example-org", "apps"); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logs.String(), "event=github.rate_limit_low"); n != 2 {
		t.Fatalf("%d warnings after a new window", n)
	}
}

func TestClient_RepositoriesCutShort(t *testing.T) {
	f := newFixture(t)
	var many []mockgithub.Repo
	for i := range 150 {
		many = append(many, mockgithub.Repo{Owner: "example-org", Name: fmt.Sprintf("repo-%03d", i), DefaultBranch: "main"})
	}
	// the first page is the last call the budget allows
	limited := mockgithub.New(mockgithub.Options{
		Org: "example-org", Repos: many, RateLimit: 1,
		App: mockgithub.App{ID: "42", PublicKey: &f.key.PublicKey, InstallationID: 7},
	})
	f.srv.Config.Handler = limited.Handler()
	c := f.client(t, func(o *Options) { o.Logger = slog.New(slog.DiscardHandler) })
	got, err := c.Repositories(context.Background())
	var refused *RateLimitError
	if len(got) != 100 || got[0].Name != "repo-000" || !errors.As(err, &refused) {
		t.Fatalf("%d repositories, %v", len(got), err)
	}
}
