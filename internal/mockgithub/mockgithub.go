// Package mockgithub is a small stand-in for GitHub, for tests and the local
// stack: OAuth sign-in and the user and org APIs, and a GitHub App with
// installation tokens and the repository APIs the sealer uses. It is never
// part of a release.
//
// /login/oauth/authorize shows a page listing the mock users; choosing one
// (or passing login=<user>) redirects back with a code, as GitHub does.
// Installation tokens carry the permissions they were minted with, and every
// repository call checks them, so a token minted too narrowly fails here as
// it would on GitHub. Calls with them send GitHub's rate limit headers, and
// with Options.RateLimit set, are refused as GitHub refuses them once the
// budget is used up.
package mockgithub

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// User is a mock GitHub user.
type User struct {
	ID        int64    `json:"id"`
	Login     string   `json:"login"`
	Name      string   `json:"name"`
	AvatarURL string   `json:"avatar_url"`
	Member    bool     `json:"-"` // of the mock org
	Teams     []string `json:"-"` // team slugs in the mock org
}

// Options configures a Server.
type Options struct {
	ClientID     string
	ClientSecret string
	// CallbackURLs are the OAuth app's registered callback URLs. Like
	// GitHub, the mock redirects only to one of these.
	CallbackURLs []string
	Org          string
	Users        []User
	// App is the GitHub App; repository routes need its tokens.
	App App
	// Repos are the repositories the App is installed on.
	Repos []Repo
	// WebURL is where browsers reach the mock, for the html_url of pull
	// requests. Empty means the request's host.
	WebURL string
	// RateLimit is how many calls installation tokens may make before the
	// mock refuses them for its rate limit, until ResetRateLimit. Zero means
	// 5000 that are never used up.
	RateLimit int
}

// DefaultUsers are the local stack's users: alice may sign in and is an
// admin, dave may sign in, bob is in the org but not in the allowed team,
// and carol is not in the org.
func DefaultUsers() []User {
	return []User{
		{ID: 1001, Login: "alice", Name: "Alice Example", Member: true, Teams: []string{"sealers", "sealer-admins"}},
		{ID: 1002, Login: "bob", Name: "Bob Example", Member: true},
		{ID: 1003, Login: "carol", Name: "Carol Example"},
		{ID: 1004, Login: "dave", Name: "Dave Example", Member: true, Teams: []string{"sealers"}},
	}
}

// Server is the mock.
type Server struct {
	opts Options

	mu            sync.Mutex
	codes         map[string]string // code -> login
	tokens        map[string]string // access token -> login
	installTokens map[string]installationToken
	repos         map[string]*repoState // lowercase "owner/name"
	// calls counts installation token calls against Options.RateLimit in
	// the window that started at window
	calls  int
	window time.Time
	faults []fault
}

// Fault is how a request fails, for testing what a client does when GitHub
// fails, and when it cannot tell whether GitHub acted.
type Fault int

// Faults.
const (
	// LoseAnswer drops the connection once the request is done: GitHub
	// acted, and the client never hears back. (Go's HTTP client sends a GET
	// again when its connection drops, so use it for writes.)
	LoseAnswer Fault = iota + 1
	// Stall answers nothing once the request is done, until the client gives
	// up (or a minute passes), then drops the connection.
	Stall
	// ServerError answers 502 without acting, as GitHub does now and then.
	ServerError
)

type fault struct {
	method, suffix string
	fault          Fault
}

// FailNext makes the next request with method whose path ends in suffix
// fail with f, after the mock acted on it.
func (s *Server) FailNext(method, suffix string, f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, fault{method: method, suffix: suffix, fault: f})
}

// takeFault removes and returns the fault planned for r, if any.
func (s *Server) takeFault(r *http.Request) Fault {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.faults {
		if f.method == r.Method && strings.HasSuffix(r.URL.Path, f.suffix) {
			s.faults = slices.Delete(s.faults, i, i+1)
			return f.fault
		}
	}
	return 0
}

// withFaults serves requests with next and fails those FailNext planned.
func (s *Server) withFaults(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := s.takeFault(r)
		switch f {
		case 0:
			next.ServeHTTP(w, r)
			return
		case ServerError:
			writeError(w, http.StatusBadGateway, "Server Error")
			return
		}
		next.ServeHTTP(discard{}, r)
		if f == Stall {
			select {
			case <-r.Context().Done():
			case <-time.After(time.Minute):
			}
		}
		panic(http.ErrAbortHandler)
	})
}

// discard is a ResponseWriter that keeps nothing.
type discard struct{}

func (discard) Header() http.Header         { return http.Header{} }
func (discard) Write(b []byte) (int, error) { return len(b), nil }
func (discard) WriteHeader(int)             {}

// New returns a Server.
func New(opts Options) *Server {
	s := &Server{
		opts:          opts,
		codes:         map[string]string{},
		tokens:        map[string]string{},
		installTokens: map[string]installationToken{},
		repos:         map[string]*repoState{},
		window:        time.Now(),
	}
	for _, r := range opts.Repos {
		s.repos[strings.ToLower(r.Owner+"/"+r.Name)] = newRepoState(r)
	}
	return s
}

// Handler returns the mock's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /login/oauth/authorize", s.authorize)
	mux.HandleFunc("POST /login/oauth/access_token", s.accessToken)
	mux.HandleFunc("GET /user", s.withUser(s.getUser))
	mux.HandleFunc("GET /orgs/{org}/members/{username}", s.withUser(s.orgMember))
	mux.HandleFunc("GET /orgs/{org}/teams/{team}/memberships/{username}", s.withUser(s.teamMembership))

	mux.HandleFunc("GET /orgs/{org}/installation", s.withApp(s.orgInstallation))
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", s.withApp(s.accessTokens))
	mux.HandleFunc("GET /installation/repositories", s.withInstallation("metadata", "read", s.installationRepositories))
	mux.HandleFunc("GET /repos/{owner}/{repo}", s.withInstallation("metadata", "read", s.getRepo))
	mux.HandleFunc("GET /repos/{owner}/{repo}/collaborators/{username}/permission", s.withInstallation("metadata", "read", s.collaboratorPermission))
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/ref/{ref...}", s.withInstallation("contents", "read", s.gitRef))
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/trees/{sha}", s.withInstallation("contents", "read", s.gitTree))
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/blobs/{sha}", s.withInstallation("contents", "read", s.gitBlob))
	mux.HandleFunc("GET /repos/{owner}/{repo}/git/commits/{sha}", s.withInstallation("contents", "read", s.getCommit))

	mux.HandleFunc("POST /repos/{owner}/{repo}/git/blobs", s.withInstallation("contents", "write", s.createBlob))
	mux.HandleFunc("POST /repos/{owner}/{repo}/git/trees", s.withInstallation("contents", "write", s.createTree))
	mux.HandleFunc("POST /repos/{owner}/{repo}/git/commits", s.withInstallation("contents", "write", s.createCommit))
	mux.HandleFunc("POST /repos/{owner}/{repo}/git/refs", s.withInstallation("contents", "write", s.createRef))
	mux.HandleFunc("PATCH /repos/{owner}/{repo}/git/refs/{ref...}", s.withInstallation("contents", "write", s.updateRef))
	mux.HandleFunc("DELETE /repos/{owner}/{repo}/git/refs/{ref...}", s.withInstallation("contents", "write", s.deleteRef))
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls", s.withInstallation("pull_requests", "read", s.listPulls))
	mux.HandleFunc("POST /repos/{owner}/{repo}/pulls", s.withInstallation("pull_requests", "write", s.createPull))
	mux.HandleFunc("PATCH /repos/{owner}/{repo}/pulls/{number}", s.withInstallation("pull_requests", "write", s.updatePull))

	// not GitHub APIs: the data of a pull request for the end-to-end tests,
	// and the page its html_url opens, which would overlap the API's paths
	// in one mux
	mux.HandleFunc("GET /_mock/repos/{owner}/{repo}/pulls/{number}", s.pullJSON)
	pages := http.NewServeMux()
	pages.HandleFunc("GET /{owner}/{repo}/pull/{number}", s.pullHTML)
	return s.withFaults(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		pages.ServeHTTP(w, r)
	}))
}

var chooser = template.Must(template.New("authorize").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Mock GitHub sign-in</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto">
<h1>Mock GitHub</h1>
<p>Sign in to the local stack as:</p>
<ul>{{range .Users}}<li><a href="{{.URL}}">{{.Login}}</a> ({{.Note}})</li>{{end}}</ul>
</body></html>`))

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != s.opts.ClientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	callback, ok := s.callback(q.Get("redirect_uri"))
	if !ok {
		http.Error(w, "redirect_uri is not a registered callback URL", http.StatusBadRequest)
		return
	}
	login := q.Get("login")
	if login == "" {
		type choice struct{ Login, Note, URL string }
		var choices []choice
		for _, u := range s.opts.Users {
			next := *r.URL
			nq := next.Query()
			nq.Set("login", u.Login)
			next.RawQuery = nq.Encode()
			note := "not in the org"
			if u.Member {
				note = "org member, teams: " + strings.Join(u.Teams, ", ")
			}
			choices = append(choices, choice{Login: u.Login, Note: note, URL: next.String()})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = chooser.Execute(w, map[string]any{"Users": choices})
		return
	}

	back := url.Values{}
	back.Set("state", q.Get("state"))
	if login == "deny" {
		back.Set("error", "access_denied")
	} else {
		if _, ok := s.user(login); !ok {
			http.Error(w, "unknown user", http.StatusBadRequest)
			return
		}
		code := random()
		s.mu.Lock()
		s.codes[code] = login
		s.mu.Unlock()
		back.Set("code", code)
	}
	// the target is the registered URL, never the one in the request
	http.Redirect(w, r, callback+"?"+back.Encode(), http.StatusFound)
}

// callback returns the registered callback URL equal to redirectURI.
func (s *Server) callback(redirectURI string) (string, bool) {
	for _, cb := range s.opts.CallbackURLs {
		if cb == redirectURI {
			return cb, true
		}
	}
	return "", false
}

func (s *Server) accessToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.PostForm.Get("client_id") != s.opts.ClientID || r.PostForm.Get("client_secret") != s.opts.ClientSecret {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "incorrect_client_credentials"})
		return
	}
	s.mu.Lock()
	login, ok := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code"))
	token := ""
	if ok {
		token = "gho_mock_" + random()
		s.tokens[token] = login
	}
	s.mu.Unlock()
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token, "token_type": "bearer", "scope": "read:org"})
}

func (s *Server) withUser(next func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		login, ok := s.tokens[token]
		s.mu.Unlock()
		u, found := s.user(login)
		if !ok || !found {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		next(w, r, u)
	}
}

func (s *Server) getUser(w http.ResponseWriter, _ *http.Request, u User) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(u)
}

func (s *Server) orgMember(w http.ResponseWriter, r *http.Request, caller User) {
	target, ok := s.user(r.PathValue("username"))
	switch {
	case r.PathValue("org") != s.opts.Org:
		w.WriteHeader(http.StatusNotFound)
	case !caller.Member:
		// like GitHub: a non-member asking is sent to the public members list
		w.Header().Set("Location", fmt.Sprintf("/orgs/%s/public_members/%s", s.opts.Org, r.PathValue("username")))
		w.WriteHeader(http.StatusFound)
	case ok && target.Member:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) teamMembership(w http.ResponseWriter, r *http.Request, _ User) {
	target, ok := s.user(r.PathValue("username"))
	if r.PathValue("org") != s.opts.Org || !ok || !target.Member || !slices.Contains(target.Teams, r.PathValue("team")) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"state": "active", "role": "member"})
}

func (s *Server) user(login string) (User, bool) {
	for _, u := range s.opts.Users {
		if u.Login == login {
			return u, true
		}
	}
	return User{}, false
}

func random() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
