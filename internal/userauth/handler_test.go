package userauth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
)

const testKey = "0123456789abcdef0123456789abcdef"

type flow struct {
	t       *testing.T
	gh      *httptest.Server
	h       *Handler
	mux     http.Handler
	cookies map[string]*http.Cookie
}

// newFlow serves sign-in for a dev env limited to teams (any org member
// without them).
func newFlow(t *testing.T, publicURL string, teams ...string) *flow {
	t.Helper()
	return newEnvsFlow(t, publicURL, EnvPolicy{Name: "dev", Teams: teams})
}

func newEnvsFlow(t *testing.T, publicURL string, envs ...EnvPolicy) *flow {
	t.Helper()
	gh := httptest.NewServer(mockgithub.New(mockgithub.Options{
		ClientID: "cid", ClientSecret: "csecret", Org: "example-org", Users: mockgithub.DefaultUsers(),
		CallbackURLs: []string{publicURL + "/api/v1/auth/callback"},
	}).Handler())
	t.Cleanup(gh.Close)

	sessions, err := NewSessions([]byte(testKey), publicURL, 8*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(HandlerOptions{
		Sessions:     sessions,
		GitHub:       NewGitHub(GitHubOptions{ClientID: "cid", ClientSecret: "csecret", TokenURL: gh.URL + "/login/oauth/access_token", APIURL: gh.URL}),
		PublicURL:    publicURL,
		AuthorizeURL: gh.URL + "/login/oauth/authorize",
		ClientID:     "cid",
		Org:          "example-org",
		Envs:         envs,
		Logger:       slog.New(slog.DiscardHandler),
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/auth/login", h.Login)
	mux.HandleFunc("GET /api/v1/auth/callback", h.Callback)
	mux.HandleFunc("GET /api/v1/auth/me", h.Me)
	mux.HandleFunc("POST /api/v1/auth/logout", h.RequireUser(h.RequireCSRF(h.Logout)))
	// an env's route answers with the user as that env sees them
	for _, env := range envs {
		g := h.Env(env.Name)
		mux.HandleFunc("GET /api/v1/envs/"+env.Name+"/whoami", g.RequireUser(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, UserFrom(r.Context()))
		}))
		mux.HandleFunc("GET /api/v1/envs/"+env.Name+"/fleet", g.RequireUser(g.RequireAdmin(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})))
	}
	return &flow{t: t, gh: gh, h: h, mux: mux, cookies: map[string]*http.Cookie{}}
}

// response is what a test needs from a reply.
type response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// do sends a request with the cookies collected so far and keeps any new ones.
func (f *flow) do(method, target string, header http.Header) response {
	f.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, c := range f.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(f.cookies, c.Name)
		} else {
			f.cookies[c.Name] = c
		}
	}
	body, _ := io.ReadAll(resp.Body)
	return response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}
}

// signIn runs the browser's side of the flow as login and returns where the
// callback redirected to.
func (f *flow) signIn(login, returnTo string) string {
	f.t.Helper()
	resp := f.do(http.MethodGet, "/api/v1/auth/login?return_to="+url.QueryEscape(returnTo), nil)
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("login = %d", resp.StatusCode)
	}
	authorize, _ := url.Parse(resp.Header.Get("Location"))
	q := authorize.Query()
	q.Set("login", login)
	authorize.RawQuery = q.Encode()

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ghResp, err := noFollow.Get(authorize.String())
	if err != nil {
		f.t.Fatal(err)
	}
	_ = ghResp.Body.Close()
	back, _ := url.Parse(ghResp.Header.Get("Location"))
	cb := f.do(http.MethodGet, back.RequestURI(), nil)
	if cb.StatusCode != http.StatusFound {
		f.t.Fatalf("callback = %d", cb.StatusCode)
	}
	return cb.Header.Get("Location")
}

func (f *flow) me() (int, map[string]any) {
	resp := f.do(http.MethodGet, "/api/v1/auth/me", nil)
	var body map[string]any
	_ = json.Unmarshal(resp.Body, &body)
	return resp.StatusCode, body
}

func TestSignIn_MemberOfAllowedTeam(t *testing.T) {
	f := newFlow(t, "http://localhost:4100", "sealers")
	if got := f.signIn("alice", "/agents?x=1"); got != "/agents?x=1" {
		t.Fatalf("redirected to %q, want the return_to path", got)
	}
	status, body := f.me()
	if status != http.StatusOK {
		t.Fatalf("/me = %d", status)
	}
	user := body["user"].(map[string]any)
	envs, _ := json.Marshal(body["envs"])
	if user["login"] != "alice" || string(envs) != `[{"admin":false,"name":"dev"}]` || body["csrf_token"] == "" {
		t.Fatalf("/me = %v", body)
	}
	session := f.cookies["sealer_session"]
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v", session)
	}

	csrf := body["csrf_token"].(string)
	if resp := f.do(http.MethodPost, "/api/v1/auth/logout", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without csrf = %d, want 403", resp.StatusCode)
	}
	if resp := f.do(http.MethodPost, "/api/v1/auth/logout", http.Header{CSRFHeader: {strings.Repeat("0", len(csrf))}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with a wrong csrf = %d, want 403", resp.StatusCode)
	}
	if resp := f.do(http.MethodPost, "/api/v1/auth/logout", http.Header{CSRFHeader: {csrf}}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	if status, _ := f.me(); status != http.StatusUnauthorized {
		t.Fatalf("/me after logout = %d", status)
	}
}

func TestSignIn_Refusals(t *testing.T) {
	cases := map[string]string{
		"bob":   "/login?error=" + ErrCodeNotInTeam,
		"carol": "/login?error=" + ErrCodeNotMember,
		"deny":  "/login?error=" + ErrCodeAccessDenied,
	}
	for login, want := range cases {
		t.Run(login, func(t *testing.T) {
			f := newFlow(t, "http://localhost:4100", "sealers")
			if got := f.signIn(login, "/"); got != want {
				t.Fatalf("redirected to %q, want %q", got, want)
			}
			if _, ok := f.cookies["sealer_session"]; ok {
				t.Fatal("a refused sign-in set a session cookie")
			}
		})
	}
}

func TestSignIn_OrgOnlyWithoutTeams(t *testing.T) {
	f := newFlow(t, "http://localhost:4100")
	if got := f.signIn("bob", "/"); got != "/" {
		t.Fatalf("org member without a team requirement redirected to %q", got)
	}
}

func TestSignIn_StateMismatchAndUnsafeReturnTo(t *testing.T) {
	f := newFlow(t, "http://localhost:4100")
	resp := f.do(http.MethodGet, "/api/v1/auth/callback?code=x&state=forged", nil)
	if loc := resp.Header.Get("Location"); loc != "/login?error="+ErrCodeStateMismatch {
		t.Fatalf("callback without the state cookie redirected to %q", loc)
	}
	for _, rt := range []string{"//evil.example.com", "https://evil.example.com", "/\\evil.example.com", "/api/v1/auth/logout"} {
		f := newFlow(t, "http://localhost:4100")
		if got := f.signIn("alice", rt); got != "/" {
			t.Errorf("return_to %q redirected to %q, want /", rt, got)
		}
	}
}

func TestSecureCookiesOnHTTPS(t *testing.T) {
	f := newFlow(t, "https://sealer.dev.example.com")
	f.signIn("alice", "/")
	c := f.cookies["__Host-sealer_session"]
	if c == nil || !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Fatalf("session cookie on https = %+v", c)
	}
}

func TestSessions_Rejects(t *testing.T) {
	now := time.Now()
	s, _ := NewSessions([]byte(testKey), "https://sealer.example.com", time.Hour, func() time.Time { return now })
	good, _, err := s.Issue(User{ID: 1, Login: "alice"}, Grants{"dev": false, "prod": true})
	if err != nil {
		t.Fatal(err)
	}
	if u, grants, err := s.Verify(good); err != nil || u.Login != "alice" || len(grants) != 2 || !grants["prod"] || u.Admin {
		t.Fatalf("Verify = %v, %v, %v", u, grants, err)
	}
	if _, _, err := s.Issue(User{ID: 1, Login: "alice"}, nil); err == nil {
		t.Error("a session granting no env was issued")
	}

	later, _ := NewSessions([]byte(testKey), "https://sealer.example.com", time.Hour, func() time.Time { return now.Add(2 * time.Hour) })
	otherAud, _ := NewSessions([]byte(testKey), "https://sealer.other.example.com", time.Hour, nil)
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims{Envs: Grants{"dev": true}, GitHubID: 1, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: sessionIssuer, Subject: "alice", Audience: jwt.ClaimStrings{"https://sealer.example.com"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	noEnvs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{GitHubID: 1, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: sessionIssuer, Subject: "alice", Audience: jwt.ClaimStrings{"https://sealer.example.com"},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}}).SignedString([]byte(testKey))

	for name, tc := range map[string]struct {
		s     *Sessions
		token string
	}{
		"expired":        {later, good},
		"no envs":        {s, noEnvs},
		"other audience": {otherAud, good},
		"alg none":       {s, none},
		"tampered":       {s, good[:len(good)-2] + "xx"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := tc.s.Verify(tc.token); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Verify = %v", err)
			}
		})
	}
	if _, err := NewSessions([]byte("short"), "https://x", time.Hour, nil); err == nil {
		t.Error("a short key was accepted")
	}
	other, _, _ := s.Issue(User{ID: 2, Login: "bob"}, Grants{"dev": false})
	if s.CSRFToken(good) == s.CSRFToken(other) {
		t.Error("two sessions share a csrf token")
	}
}

func TestSignIn_AdminTeams(t *testing.T) {
	for login, want := range map[string]int{"alice": http.StatusNoContent, "dave": http.StatusForbidden} {
		f := newEnvsFlow(t, "http://localhost:4100", EnvPolicy{Name: "dev", Teams: []string{"sealers"}, AdminTeams: []string{"sealer-admins"}})
		f.signIn(login, "/")
		if resp := f.do(http.MethodGet, "/api/v1/envs/dev/fleet", nil); resp.StatusCode != want {
			t.Errorf("%s: an admin route = %d, want %d", login, resp.StatusCode, want)
		}
	}
	// without admin teams nobody is an admin
	f := newFlow(t, "http://localhost:4100", "sealers")
	f.signIn("alice", "/")
	if resp := f.do(http.MethodGet, "/api/v1/envs/dev/fleet", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin without admin teams: %d", resp.StatusCode)
	}
}

// Each env is granted, and administered, on its own teams; a session works
// in the envs it grants and is refused in the rest.
func TestSignIn_Envs(t *testing.T) {
	envs := []EnvPolicy{
		{Name: "dev", Teams: []string{"sealers"}, AdminTeams: []string{"sealer-admins"}},
		{Name: "prod", Teams: []string{"sealer-admins"}, AdminTeams: []string{"sealer-admins"}},
	}
	for login, want := range map[string]string{
		"alice": `[{"admin":true,"name":"dev"},{"admin":true,"name":"prod"}]`,
		"dave":  `[{"admin":false,"name":"dev"}]`,
	} {
		t.Run(login, func(t *testing.T) {
			f := newEnvsFlow(t, "http://localhost:4100", envs...)
			f.signIn(login, "/")
			_, body := f.me()
			if got, _ := json.Marshal(body["envs"]); string(got) != want {
				t.Fatalf("envs = %s, want %s", got, want)
			}
			prod := f.do(http.MethodGet, "/api/v1/envs/prod/whoami", nil)
			dev := f.do(http.MethodGet, "/api/v1/envs/dev/whoami", nil)
			if dev.StatusCode != http.StatusOK {
				t.Fatalf("dev = %d", dev.StatusCode)
			}
			if login == "dave" && (prod.StatusCode != http.StatusForbidden || !strings.Contains(string(prod.Body), "may not use the prod env")) {
				t.Fatalf("dave in prod = %d %s", prod.StatusCode, prod.Body)
			}
			if login == "alice" && (prod.StatusCode != http.StatusOK || !strings.Contains(string(prod.Body), `"admin":true`)) {
				t.Fatalf("alice in prod = %d %s", prod.StatusCode, prod.Body)
			}
		})
	}
	// someone no env admits cannot sign in
	f := newEnvsFlow(t, "http://localhost:4100", envs...)
	if got := f.signIn("bob", "/"); got != "/login?error="+ErrCodeNotInTeam {
		t.Fatalf("bob redirected to %q", got)
	}
}
