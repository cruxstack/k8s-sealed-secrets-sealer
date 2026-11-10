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
	Env          string
	// Org is the GitHub organization users must belong to.
	Org string
	// Teams, when set, also require membership in at least one of these
	// teams of Org.
	Teams  []string
	Logger *slog.Logger
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
	if code, err := h.authorize(r, token, user.Login); err != nil || code != "" {
		if err != nil {
			log.WarnContext(ctx, "sign-in failed", "event", "user.login_failed", "user", user.Login, "error", err)
			code = ErrCodeGitHub
		} else {
			log.WarnContext(ctx, "sign-in rejected", "event", "user.login_rejected", "user", user.Login, "reason", code)
		}
		h.fail(w, r, code)
		return
	}

	session, exp, err := h.opts.Sessions.Issue(*user)
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
	log.InfoContext(ctx, "user signed in", "event", "user.login", "user", user.Login, "github_id", user.ID)
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// authorize returns a failure code when the user may not sign in.
func (h *Handler) authorize(r *http.Request, token, login string) (string, error) {
	member, err := h.opts.GitHub.OrgMember(r.Context(), token, h.opts.Org, login)
	if err != nil {
		return "", err
	}
	if !member {
		return ErrCodeNotMember, nil
	}
	if len(h.opts.Teams) == 0 {
		return "", nil
	}
	for _, team := range h.opts.Teams {
		ok, err := h.opts.GitHub.TeamMember(r.Context(), token, h.opts.Org, team, login)
		if err != nil {
			return "", err
		}
		if ok {
			return "", nil
		}
	}
	return ErrCodeNotInTeam, nil
}

// Me returns the signed-in user and the CSRF token for their session.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	token, user := h.session(r)
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       user,
		"csrf_token": h.opts.Sessions.CSRFToken(token),
		"env":        h.opts.Env,
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
// the request context.
func (h *Handler) RequireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, user := h.session(r)
		if user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r.WithContext(WithUser(r.Context(), user)))
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
		token, user := h.session(r)
		header := r.Header.Get(CSRFHeader)
		if user == nil || header == "" ||
			subtle.ConstantTimeCompare([]byte(header), []byte(h.opts.Sessions.CSRFToken(token))) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf token missing or invalid"})
			return
		}
		next(w, r)
	}
}

func (h *Handler) session(r *http.Request) (string, *User) {
	c, err := r.Cookie(h.sessionCookie)
	if err != nil || c.Value == "" {
		return "", nil
	}
	user, err := h.opts.Sessions.Verify(c.Value)
	if err != nil {
		return "", nil
	}
	return c.Value, user
}

func (h *Handler) callbackURL() string {
	return strings.TrimSuffix(h.opts.PublicURL, "/") + callbackPath
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
}

// safeReturnTo keeps only same-origin paths, so a sign-in link cannot send
// the user to another site afterwards.
func safeReturnTo(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") ||
		strings.HasPrefix(p, "/api/") || len(p) > 512 {
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
