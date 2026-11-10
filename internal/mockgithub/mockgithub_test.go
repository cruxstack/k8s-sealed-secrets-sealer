package mockgithub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

func TestAuthorize_RedirectsOnlyToRegisteredCallback(t *testing.T) {
	h := New(Options{ClientID: "cid", CallbackURLs: []string{"http://localhost:4100/api/v1/auth/callback"}, Users: DefaultUsers()}).Handler()
	get := func(redirectURI string) *httptest.ResponseRecorder {
		q := url.Values{"client_id": {"cid"}, "redirect_uri": {redirectURI}, "state": {"s"}, "login": {"alice"}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login/oauth/authorize?"+q.Encode(), nil))
		return rec
	}
	rec := get("http://localhost:4100/api/v1/auth/callback")
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, "http://localhost:4100/api/v1/auth/callback?") || !strings.Contains(loc, "code=") {
		t.Fatalf("registered callback: %d %q", rec.Code, loc)
	}
	for _, evil := range []string{"https://evil.example.com/cb", "http://localhost:4100/api/v1/auth/callback/../../x", ""} {
		if rec := get(evil); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("redirect_uri %q: %d %q", evil, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestInstallationTokens_CarryTheirPermissions(t *testing.T) {
	key := testcerts.RSA(t, 2048)
	repos, err := Fixtures()
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Org: "example-org", Users: DefaultUsers(), App: App{ID: "1", PublicKey: &key.PublicKey, InstallationID: 5}, Repos: repos}).Handler()
	appJWT, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    "1",
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, bearer, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	mint := func(perms string) string {
		t.Helper()
		rec := do(http.MethodPost, "/app/installations/5/access_tokens", appJWT, `{"permissions":`+perms+`}`)
		var out struct {
			Token string `json:"token"`
		}
		if rec.Code != http.StatusCreated || json.NewDecoder(rec.Body).Decode(&out) != nil {
			t.Fatalf("mint %s = %d %s", perms, rec.Code, rec.Body)
		}
		return out.Token
	}

	contentsOnly := mint(`{"contents":"read"}`)
	if rec := do(http.MethodGet, "/installation/repositories", contentsOnly, ""); rec.Code != http.StatusForbidden {
		t.Errorf("listing with contents only = %d, want 403", rec.Code)
	}
	if rec := do(http.MethodGet, "/repos/example-org/apps/git/ref/heads/main", contentsOnly, ""); rec.Code != http.StatusOK {
		t.Errorf("reading a ref with contents = %d", rec.Code)
	}
	// permissions the App was not granted are refused
	if rec := do(http.MethodPost, "/app/installations/5/access_tokens", appJWT, `{"permissions":{"administration":"write"}}`); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("minting administration = %d, want 422", rec.Code)
	}
	// an App JWT is not an installation token, and vice versa
	if rec := do(http.MethodGet, "/installation/repositories", appJWT, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("listing with the app jwt = %d, want 401", rec.Code)
	}
	if rec := do(http.MethodGet, "/orgs/example-org/installation", contentsOnly, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("installation lookup with a token = %d, want 401", rec.Code)
	}
}
