package controlplane

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func TestRepoRoutes(t *testing.T) {
	fixtures, err := mockgithub.Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	key := testcerts.RSA(t, 2048)
	mock := httptest.NewServer(mockgithub.New(mockgithub.Options{
		Org:   "example-org",
		Users: mockgithub.DefaultUsers(),
		App:   mockgithub.App{ID: "1", PublicKey: &key.PublicKey, InstallationID: 1},
		Repos: fixtures,
	}).Handler())
	defer mock.Close()
	gh, err := githubapp.New(githubapp.Options{
		APIURL: mock.URL, AppID: "1", Org: "example-org",
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

	get := func(path string, u *userauth.User) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if u != nil {
			token, _, _ := userSessions.Issue(*u, userauth.Grants{"dev": false})
			req.AddCookie(&http.Cookie{Name: "sealer_session", Value: token})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	alice := &userauth.User{ID: 1001, Login: "alice"}
	carol := &userauth.User{ID: 1003, Login: "carol"}

	if rec := get("/api/v1/repos", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("repos without sign-in = %d", rec.Code)
	}
	rec := get("/api/v1/repos", alice)
	var list struct {
		Repositories []repos.Repo `json:"repositories"`
	}
	if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&list) != nil || len(list.Repositories) != 2 {
		t.Fatalf("repos = %d %+v", rec.Code, list)
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

	// GitHub failures are a bad gateway, without GitHub's detail
	mock.Close()
	if rec := get("/api/v1/repos", &userauth.User{ID: 1002, Login: "bob"}); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Errorf("github down = %d %s", rec.Code, rec.Body)
	}
}
