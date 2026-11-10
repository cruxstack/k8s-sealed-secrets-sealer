// Package mockgithub is a small stand-in for GitHub, for tests and the local
// stack: OAuth sign-in and the user and org APIs, and a GitHub App with
// installation tokens and the repository APIs the sealer uses. It is never
// part of a release.
//
// /login/oauth/authorize shows a page listing the mock users; choosing one
// (or passing login=<user>) redirects back with a code, as GitHub does.
// Installation tokens carry the permissions they were minted with, and every
// repository call checks them, so a token minted too narrowly fails here as
// it would on GitHub.
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
}

// DefaultUsers are the local stack's users: alice may sign in, bob is in the
// org but not in the allowed team, and carol is not in the org.
func DefaultUsers() []User {
	return []User{
		{ID: 1001, Login: "alice", Name: "Alice Example", Member: true, Teams: []string{"sealers"}},
		{ID: 1002, Login: "bob", Name: "Bob Example", Member: true},
		{ID: 1003, Login: "carol", Name: "Carol Example"},
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
}

// New returns a Server.
func New(opts Options) *Server {
	s := &Server{
		opts:          opts,
		codes:         map[string]string{},
		tokens:        map[string]string{},
		installTokens: map[string]installationToken{},
		repos:         map[string]*repoState{},
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
	mux.HandleFunc("DELETE /repos/{owner}/{repo}/git/refs/{ref...}", s.withInstallation("contents", "write", s.deleteRef))
	mux.HandleFunc("POST /repos/{owner}/{repo}/pulls", s.withInstallation("pull_requests", "write", s.createPull))

	// not GitHub APIs: the page a pull request's html_url opens, and its
	// data for the end-to-end tests
	mux.HandleFunc("GET /{owner}/{repo}/pull/{number}", s.pullHTML)
	mux.HandleFunc("GET /_mock/repos/{owner}/{repo}/pulls/{number}", s.pullJSON)
	return mux
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
