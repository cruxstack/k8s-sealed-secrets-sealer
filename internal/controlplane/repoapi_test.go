package controlplane

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// repoRoutes serves the repository API of the dev env, backed by a GitHub
// mock with the fixture repositories and the given rate limit (zero: none).
func repoRoutes(t *testing.T, rateLimit int) (http.Handler, *httptest.Server, *userauth.Sessions) {
	t.Helper()
	fixtures, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	key := testcerts.RSA(t, 2048)
	mock := httptest.NewServer(mockgithub.New(mockgithub.Options{
		Org:       "example-org",
		Users:     mockgithub.DefaultUsers(),
		App:       mockgithub.App{ID: "1", PublicKey: &key.PublicKey, InstallationID: 1},
		Repos:     fixtures,
		RateLimit: rateLimit,
	}).Handler())
	t.Cleanup(mock.Close)
	gh, err := githubapp.New(githubapp.Options{
		APIURL: mock.URL, AppID: "1", Org: "example-org", Logger: slog.New(slog.DiscardHandler),
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := repos.New(repos.Options{
		GitHub: gh, Env: "dev",
		Annotations: manifest.Annotations{Env: manifest.DefaultEnvAnnotation, Region: manifest.DefaultRegionAnnotation},
	})
	if err != nil {
		t.Fatal(err)
	}

	reg, _ := registry.Parse([]byte("issuers: []\nagents: []\n"), "")
	agentSessions, _ := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "http://localhost:4100", "dev", nil)
	userSessions, _ := userauth.NewSessions([]byte("fedcba9876543210fedcba9876543210"), "http://localhost:4100", time.Hour, nil)
	users := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: userSessions, PublicURL: "http://localhost:4100", Org: "example-org",
		Envs: []userauth.EnvPolicy{{Name: "dev"}}, Logger: slog.New(slog.DiscardHandler),
	})
	h := New(Options{
		Env: "dev", Registry: reg, Sessions: agentSessions, Store: store.NewMemory(),
		Users: users.Env("dev"), Repos: rs, Logger: slog.New(slog.DiscardHandler),
	}).Handler()
	return h, mock, userSessions
}

func getAs(t *testing.T, h http.Handler, userSessions *userauth.Sessions) func(string, *userauth.User) *httptest.ResponseRecorder {
	return func(path string, u *userauth.User) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		if u != nil {
			token, _, _ := userSessions.Issue(*u, userauth.Grants{"dev": false})
			req.AddCookie(&http.Cookie{Name: "sealer_session", Value: token})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
}

func TestRepoRoutes(t *testing.T) {
	h, mock, userSessions := repoRoutes(t, 0)
	get := getAs(t, h, userSessions)
	alice := &userauth.User{ID: 1001, Login: "alice"}
	carol := &userauth.User{ID: 1003, Login: "carol"}

	if rec := get("/api/v1/repos", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("repos without sign-in = %d", rec.Code)
	}
	// only what alice can read, with her access
	rec := get("/api/v1/repos", alice)
	var list repos.RepoList
	if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&list) != nil || list.Incomplete {
		t.Fatalf("repos = %d %s", rec.Code, rec.Body)
	}
	var got []string
	for _, r := range list.Repositories {
		got = append(got, r.FullName+":"+r.Access)
	}
	if !slices.Equal(got, []string{"example-org/apps:write", "example-org/platform:read"}) || strings.Contains(rec.Body.String(), "restricted") {
		t.Fatalf("repos = %s", rec.Body)
	}

	rec = get("/api/v1/repos/example-org/apps/files", alice)
	var listing repos.Listing
	if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&listing) != nil || len(listing.Files) != 4 {
		t.Fatalf("files = %d %+v", rec.Code, listing)
	}
	for _, path := range []string{
		"/api/v1/repos/example-org/restricted/files", // exists, alice cannot read it
		"/api/v1/repos/example-org/missing/files",
		"/api/v1/repos/example-org/%2e%2e/files",
	} {
		if rec := get(path, alice); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "repository not found") {
			t.Errorf("%s = %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := get("/api/v1/repos/example-org/apps/files", carol); rec.Code != http.StatusNotFound {
		t.Errorf("carol's files = %d", rec.Code)
	}

	// files at a commit: the head is allowed, other commits are not
	if rec := get("/api/v1/repos/example-org/apps/files?commit="+listing.Commit, alice); rec.Code != http.StatusOK {
		t.Errorf("files at the head = %d %s", rec.Code, rec.Body)
	}
	if rec := get("/api/v1/repos/example-org/apps/files?commit="+strings.Repeat("a", 40), alice); rec.Code != http.StatusNotFound {
		t.Errorf("files at another commit = %d %s", rec.Code, rec.Body)
	}

	// GitHub failures are a bad gateway, without GitHub's detail
	mock.Close()
	bob := &userauth.User{ID: 1002, Login: "bob"}
	if rec := get("/api/v1/repos", bob); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Errorf("github down = %d %s", rec.Code, rec.Body)
	}
	if rec := get("/api/v1/repos/example-org/apps/files", bob); rec.Code != http.StatusBadGateway {
		t.Errorf("github down = %d %s", rec.Code, rec.Body)
	}
}

func TestRepoRoutes_GitHubRateLimit(t *testing.T) {
	// listing the installation is the last call the App's budget allows, so
	// no permission can be checked
	h, _, userSessions := repoRoutes(t, 1)
	get := getAs(t, h, userSessions)
	alice := &userauth.User{ID: 1001, Login: "alice"}
	rec := get("/api/v1/repos", alice)
	retry, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if rec.Code != http.StatusServiceUnavailable || err != nil || retry < 3500 || retry > 3600 ||
		!strings.Contains(rec.Body.String(), "try again in 60 minutes") {
		t.Fatalf("rate limited = %d, Retry-After %q, %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
}

func TestFiles_OnlyAtTheSessionsCommitOrTheHead(t *testing.T) {
	sh := newSealHarness(t)
	ctx := context.Background()
	sess := sh.openSession()
	files := func(login, commit string) int {
		t.Helper()
		return sh.do(login, http.MethodGet, "/api/v1/repos/example-org/apps/files?commit="+commit, nil, false).Code
	}
	// a commit of the repository that is neither: one on another branch
	other, err := sh.app.CreatePullRequest(ctx, "example-org", "apps", githubapp.NewPullRequest{
		Base: "main", Parent: sess.Commit, Branch: "feature/x", Message: "m", Title: "t",
		Files: []githubapp.FileChange{{Path: "deploy/billing/sealed-secret.yaml", Mode: "100644", Content: []byte("x\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		login, commit string
		want          int
	}{
		{"alice", sess.Commit, http.StatusOK},          // her session's base
		{"bob", sess.Commit, http.StatusOK},            // the head, which bob may read
		{"alice", other.Commit, http.StatusNotFound},   // exists, but neither
		{"alice", "not-a-commit", http.StatusNotFound}, // not even a commit
	}
	for _, tc := range cases {
		if got := files(tc.login, tc.commit); got != tc.want {
			t.Errorf("%s at %s = %d, want %d", tc.login, tc.commit, got, tc.want)
		}
	}
}

func TestSeal_GitHubFailingToSendTheFileIsABadGateway(t *testing.T) {
	sh := newSealHarness(t)
	sess := sh.openSession()
	tree, err := sh.app.Tree(context.Background(), "example-org", "apps", sess.Commit)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range tree.Entries {
		if e.Path == billing {
			sh.github.FailNext(http.MethodGet, "/git/blobs/"+e.SHA, mockgithub.ServerError)
		}
	}
	if rec := sh.seal(sess.ID, billing, "api-token", "v"); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "cannot be sealed into") {
		t.Fatalf("seal while github fails = %d %s", rec.Code, rec.Body)
	}
	// nothing about the file was kept: the next seal reads it
	if rec := sh.seal(sess.ID, billing, "api-token", "v"); rec.Code != http.StatusAccepted {
		t.Fatalf("seal = %d %s", rec.Code, rec.Body)
	}
}
