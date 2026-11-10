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

func newFlow(t *testing.T, publicURL string, teams ...string) *flow {
	t.Helper()
	gh := httptest.NewServer(mockgithub.New(mockgithub.Options{
		ClientID: "cid", ClientSecret: "csecret", Org: "example-org", Users: mockgithub.DefaultUsers(),
		CallbackURLs: []string{publicURL + "/api/v1/auth/callback"},
	}).Handler())
	t.Cleanup(gh.Close)

	sessions, err := NewSessions([]byte(testKey), publicURL, "dev", 8*time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(HandlerOptions{
		Sessions:     sessions,
		GitHub:       NewGitHub(GitHubOptions{ClientID: "cid", ClientSecret: "csecret", TokenURL: gh.URL + "/login/oauth/access_token", APIURL: gh.URL}),
		PublicURL:    publicURL,
		AuthorizeURL: gh.URL + "/login/oauth/authorize",
		ClientID:     "cid",
		Env:          "dev",
		Org:          "example-org",
		Teams:        teams,
		Logger:       slog.New(slog.DiscardHandler),
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/auth/login", h.Login)
	mux.HandleFunc("GET /api/v1/auth/callback", h.Callback)
	mux.HandleFunc("GET /api/v1/auth/me", h.Me)
	mux.HandleFunc("POST /api/v1/auth/logout", h.RequireUser(h.RequireCSRF(h.Logout)))
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
	if user["login"] != "alice" || body["env"] != "dev" || body["csrf_token"] == "" {
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
	s, _ := NewSessions([]byte(testKey), "https://sealer.dev.example.com", "dev", time.Hour, func() time.Time { return now })
	good, _, err := s.Issue(User{ID: 1, Login: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if u, err := s.Verify(good); err != nil || u.Login != "alice" {
		t.Fatalf("Verify = %v, %v", u, err)
	}

	later, _ := NewSessions([]byte(testKey), "https://sealer.dev.example.com", "dev", time.Hour, func() time.Time { return now.Add(2 * time.Hour) })
	otherEnv, _ := NewSessions([]byte(testKey), "https://sealer.dev.example.com", "prod", time.Hour, nil)
	otherAud, _ := NewSessions([]byte(testKey), "https://sealer.prod.example.com", "dev", time.Hour, nil)
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims{Env: "dev", GitHubID: 1, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: sessionIssuer, Subject: "alice", Audience: jwt.ClaimStrings{"https://sealer.dev.example.com"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}}).SignedString(jwt.UnsafeAllowNoneSignatureType)

	for name, tc := range map[string]struct {
		s     *Sessions
		token string
	}{
		"expired":        {later, good},
		"other env":      {otherEnv, good},
		"other audience": {otherAud, good},
		"alg none":       {s, none},
		"tampered":       {s, good[:len(good)-2] + "xx"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.s.Verify(tc.token); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Verify = %v", err)
			}
		})
	}
	if _, err := NewSessions([]byte("short"), "https://x", "dev", time.Hour, nil); err == nil {
		t.Error("a short key was accepted")
	}
	other, _, _ := s.Issue(User{ID: 2, Login: "bob"})
	if s.CSRFToken(good) == s.CSRFToken(other) {
		t.Error("two sessions share a csrf token")
	}
}
