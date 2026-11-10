package userauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CSRFHeader is the header state-changing requests must carry.
const CSRFHeader = "X-CSRF-Token"

// Login failure codes the UI understands (/login?error=<code>).
const (
	ErrCodeAccessDenied  = "access_denied"
	ErrCodeNotMember     = "not_member"
	ErrCodeNotInTeam     = "not_in_team"
	ErrCodeStateMismatch = "state_mismatch"
	ErrCodeGitHub        = "github_error"
)

const (
	callbackPath = "/api/v1/auth/callback"
	stateTTL     = 10 * time.Minute
)

// HandlerOptions configures a Handler.
type HandlerOptions struct {
	Sessions *Sessions
	GitHub   *GitHub
	// PublicURL is this deployment's external URL; the OAuth redirect URI is
	// derived from it, and https turns on Secure, __Host- cookies.
	PublicURL string
	// AuthorizeURL is GitHub's authorize page, normally
	// https://github.com/login/oauth/authorize.
	AuthorizeURL string
	ClientID     string
	// Org is the GitHub organization users must belong to.
	Org string
	// Envs are the envs this deployment serves, in the order people see
	// them, with who may use and administer each.
	Envs   []EnvPolicy
	Logger *slog.Logger
}

// EnvPolicy says who may use an env and who administers it.
type EnvPolicy struct {
	Name string
	// Teams, when set, limit the env to members of at least one of these
	// teams of Org; otherwise every member of Org may use it.
	Teams []string
	// AdminTeams are teams of Org whose members administer the env: they
	// may see its fleet.
	AdminTeams []string
}

// Handler serves sign-in, sign-out and /me, and authenticates requests.
type Handler struct {
	opts          HandlerOptions
	secure        bool
	sessionCookie string
	stateCookie   string
}

// NewHandler returns a Handler. It makes no network calls.
func NewHandler(opts HandlerOptions) *Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	secure := strings.HasPrefix(opts.PublicURL, "https://")
	h := &Handler{opts: opts, secure: secure, sessionCookie: "sealer_session", stateCookie: "sealer_oauth_state"}
	if secure {
		// __Host- cookies must be Secure, host-only and at path /, so a
		// sibling subdomain can neither set nor read them
		h.sessionCookie = "__Host-sealer_session"
	}
	return h
}

// Login starts the OAuth flow: a random state in a short-lived cookie, then
// a redirect to GitHub.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state := randomHex(32)
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	http.SetCookie(w, &http.Cookie{
		Name:     h.stateCookie,
		Value:    state + "." + base64.RawURLEncoding.EncodeToString([]byte(returnTo)),
		Path:     callbackPath,
		MaxAge:   int(stateTTL / time.Second),
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	q := url.Values{
		"client_id":    {h.opts.ClientID},
		"redirect_uri": {h.callbackURL()},
		"scope":        {"read:org"},
		"state":        {state},
		"allow_signup": {"false"},
	}
	http.Redirect(w, r, h.opts.AuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

// Callback finishes the OAuth flow: it checks the state, exchanges the code,
// checks org (and team) membership, and sets the session cookie.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := h.opts.Logger
	q := r.URL.Query()

	cookie, err := r.Cookie(h.stateCookie)
	http.SetCookie(w, &http.Cookie{Name: h.stateCookie, Path: callbackPath, MaxAge: -1, HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode})
	var returnTo string
	if err == nil {
		state, rt, _ := strings.Cut(cookie.Value, ".")
		if b, err := base64.RawURLEncoding.DecodeString(rt); err == nil {
			returnTo = safeReturnTo(string(b))
		}
		if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(q.Get("state"))) != 1 {
			err = http.ErrNoCookie
		}
	}
	if err != nil {
		log.WarnContext(ctx, "sign-in rejected: oauth state mismatch", "event", "user.login_rejected", "reason", ErrCodeStateMismatch)
		h.fail(w, r, ErrCodeStateMismatch)
		return
	}
	if ghErr := q.Get("error"); ghErr != "" {
		code := ErrCodeGitHub
		if ghErr == "access_denied" {
			code = ErrCodeAccessDenied
		}
		log.InfoContext(ctx, "sign-in cancelled at github", "event", "user.login_rejected", "reason", code)
		h.fail(w, r, code)
		return
	}

	token, err := h.opts.GitHub.Exchange(ctx, q.Get("code"), h.callbackURL())
	if err != nil {
		log.WarnContext(ctx, "sign-in failed", "event", "user.login_failed", "error", err)
		h.fail(w, r, ErrCodeGitHub)
		return
	}
	user, err := h.opts.GitHub.User(ctx, token)
	if err != nil {
		log.WarnContext(ctx, "sign-in failed", "event", "user.login_failed", "error", err)
		h.fail(w, r, ErrCodeGitHub)
		return
	}
	grants, code, err := h.authorize(r, token, user.Login)
	if err != nil || code != "" {
		if err != nil {
			log.WarnContext(ctx, "sign-in failed", "event", "user.login_failed", "user", user.Login, "error", err)
			code = ErrCodeGitHub
		} else {
			log.WarnContext(ctx, "sign-in rejected", "event", "user.login_rejected", "user", user.Login, "reason", code)
		}
		h.fail(w, r, code)
		return
	}

	session, exp, err := h.opts.Sessions.Issue(*user, grants)
	if err != nil {
		log.ErrorContext(ctx, "failed to issue user session", "user", user.Login, "error", err)
		h.fail(w, r, ErrCodeGitHub)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookie,
		Value:    session,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	log.InfoContext(ctx, "user signed in", "event", "user.login", "user", user.Login, "github_id", user.ID, "envs", grants)
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// authorize returns the envs the user may use, each with whether they
// administer it, or a failure code when they may use none.
func (h *Handler) authorize(r *http.Request, token, login string) (Grants, string, error) {
	member, err := h.opts.GitHub.OrgMember(r.Context(), token, h.opts.Org, login)
	if err != nil {
		return nil, "", err
	}
	if !member {
		return nil, ErrCodeNotMember, nil
	}
	// envs often share teams: each is looked up once
	teams := map[string]bool{}
	anyTeam := func(names []string) (bool, error) {
		for _, team := range names {
			ok, seen := teams[team]
			if !seen {
				if ok, err = h.opts.GitHub.TeamMember(r.Context(), token, h.opts.Org, team, login); err != nil {
					return false, err
				}
				teams[team] = ok
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	grants := Grants{}
	for _, env := range h.opts.Envs {
		allowed := len(env.Teams) == 0
		if !allowed {
			if allowed, err = anyTeam(env.Teams); err != nil {
				return nil, "", err
			}
		}
		if !allowed {
			continue
		}
		admin, err := anyTeam(env.AdminTeams)
		if err != nil {
			return nil, "", err
		}
		grants[env.Name] = admin
	}
	if len(grants) == 0 {
		return nil, ErrCodeNotInTeam, nil
	}
	return grants, "", nil
}

// EnvAccess is an env a user may use, as /me lists it.
type EnvAccess struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// Me returns the signed-in user, the envs they may use (in the order the
// deployment lists them) and the CSRF token for their session.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	token, user, grants := h.session(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	envs := []EnvAccess{}
	for _, env := range h.opts.Envs {
		if admin, ok := grants[env.Name]; ok {
			envs = append(envs, EnvAccess{Name: env.Name, Admin: admin})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       user,
		"envs":       envs,
		"csrf_token": h.opts.Sessions.CSRFToken(token),
	})
}

// Logout clears the session cookie. It must run behind RequireUser and
// RequireCSRF.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: h.sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode})
	if u := UserFrom(r.Context()); u != nil {
		h.opts.Logger.InfoContext(r.Context(), "user signed out", "event", "user.logout", "user", u.Login)
	}
	w.WriteHeader(http.StatusNoContent)
}

// RequireUser rejects requests without a valid session and puts the user in
// the request context, as no env in particular sees them.
func (h *Handler) RequireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, user, _ := h.session(r)
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r.WithContext(WithUser(r.Context(), user)))
	}
}

// Env returns the guard for one env's routes.
func (h *Handler) Env(name string) *EnvGuard {
	return &EnvGuard{h: h, env: name}
}

// EnvGuard admits people to one env: those whose session grants it.
type EnvGuard struct {
	h   *Handler
	env string
}

// RequireUser rejects requests without a valid session, and with one that
// does not grant the env, and puts the user, as the env sees them, in the
// request context.
func (g *EnvGuard) RequireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, user, grants := g.h.session(r)
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		admin, ok := grants[g.env]
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "you may not use the " + g.env + " env"})
			return
		}
		user.Admin = admin
		next(w, r.WithContext(WithUser(r.Context(), user)))
	}
}

// RequireCSRF is Handler.RequireCSRF.
func (g *EnvGuard) RequireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return g.h.RequireCSRF(next)
}

// RequireAdmin is Handler.RequireAdmin: the user must administer the env.
// It must run behind the guard's RequireUser.
func (g *EnvGuard) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return g.h.RequireAdmin(next)
}

// RequireAdmin rejects users who are not admins. Admin is per env, set only
// by EnvGuard.RequireUser, so it must run behind that; behind
// Handler.RequireUser it refuses everyone.
func (h *Handler) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := UserFrom(r.Context()); u == nil || !u.Admin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "only admins can see this"})
			return
		}
		next(w, r)
	}
}

// RequireCSRF rejects state-changing requests whose X-CSRF-Token does not
// match the session. Safe methods pass through.
func (h *Handler) RequireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
			return
		}
		token, user, _ := h.session(r)
		header := r.Header.Get(CSRFHeader)
		if user == nil || header == "" ||
			subtle.ConstantTimeCompare([]byte(header), []byte(h.opts.Sessions.CSRFToken(token))) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf token missing or invalid"})
			return
		}
		next(w, r)
	}
}

func (h *Handler) session(r *http.Request) (string, *User, Grants) {
	c, err := r.Cookie(h.sessionCookie)
	if err != nil || c.Value == "" {
		return "", nil, nil
	}
	user, grants, err := h.opts.Sessions.Verify(c.Value)
	if err != nil {
		return "", nil, nil
	}
	return c.Value, user, grants
}

func (h *Handler) callbackURL() string {
	return strings.TrimSuffix(h.opts.PublicURL, "/") + callbackPath
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
}

// safeReturnTo keeps only same-origin paths, so a sign-in link cannot send
// the user to another site afterwards. Browsers treat "//host" and "/\host"
// as other origins, so the second character may be neither slash.
func safeReturnTo(p string) string {
	if p == "" || len(p) > 512 || p[0] != '/' {
		return ""
	}
	if len(p) > 1 && (p[1] == '/' || p[1] == '\\') {
		return ""
	}
	if strings.ContainsAny(p, "\\\r\n\t") || strings.HasPrefix(p, "/api/") {
		return ""
	}
	return p
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
