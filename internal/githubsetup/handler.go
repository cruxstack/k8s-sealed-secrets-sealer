package githubsetup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
)

// Error codes the setup page shows, sent back to it as /setup?error=code.
const (
	ErrCodeState        = "state"
	ErrCodeGitHub       = "github"
	ErrCodeWrongOwner   = "wrong_owner"
	ErrCodeAlreadySetUp = "already_set_up"
	ErrCodeStore        = "store"
	ErrCodeBusy         = "busy"
)

const (
	// stateTTL is how long a setup may take: GitHub's code lasts an hour.
	stateTTL = time.Hour
	// exchangeTimeout bounds turning a code into the App's credentials.
	exchangeTimeout = 30 * time.Second
	// maxResponseBytes bounds GitHub's answer, which holds a private key.
	maxResponseBytes = 1 << 20
	// maxExchanges bounds the codes an instance exchanges a minute: each is
	// a GitHub call made without credentials, which GitHub rate-limits by
	// address.
	maxExchanges = 10
)

// Options configures a Handler.
type Options struct {
	Store Store
	// Org is the GitHub organization the App is created in and must be
	// owned by.
	Org string
	// PublicURL is the control plane's URL; the App sends people back to
	// it and signs them in there.
	PublicURL string
	// GitHubURL is GitHub's web host (where the App is created and
	// installed); APIURL its API (where the code is exchanged).
	GitHubURL string
	APIURL    string
	// Client calls GitHub; nil means one with a 30-second timeout.
	Client *http.Client
	// OnCreated is called once the credentials are stored, before the
	// person is sent on to install the App: the control plane starts
	// using them. Its error is logged; the credentials stay stored.
	OnCreated func(ctx context.Context, c Credentials) error
	Logger    *slog.Logger
	Now       func() time.Time
}

// Handler serves the setup API under /api/v1/setup:
//
//   - GET /api/v1/setup: what the setup page shows (the org, the App's
//     name and permissions);
//   - POST /api/v1/setup/github-app: starts creating the App: a random
//     state in a short-lived cookie, and the form the page posts to GitHub;
//   - GET /api/v1/setup/github-app/callback: GitHub's redirect once the App
//     is created. It checks the state, exchanges the code for the App's
//     credentials, refuses an App not owned by the org, stores the
//     credentials once, and sends the person on to install the App.
//
// It is mounted only while the App is not set up.
type Handler struct {
	opts        Options
	secure      bool
	stateCookie string
	mux         *http.ServeMux

	mu        sync.Mutex
	window    time.Time
	exchanges int
}

// New returns a Handler. It makes no network calls.
func New(opts Options) *Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: exchangeTimeout}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.PublicURL = strings.TrimSuffix(opts.PublicURL, "/")
	opts.GitHubURL = strings.TrimSuffix(opts.GitHubURL, "/")
	opts.APIURL = strings.TrimSuffix(opts.APIURL, "/")
	h := &Handler{opts: opts, stateCookie: "sealer_setup_state"}
	if strings.HasPrefix(opts.PublicURL, "https://") {
		// as the sign-in state is: a sibling subdomain cannot plant a
		// state of its own and finish its own setup in someone's browser
		h.secure = true
		h.stateCookie = "__Host-sealer_setup_state"
	}
	h.mux = http.NewServeMux()
	h.mux.HandleFunc("GET /api/v1/setup", h.status)
	h.mux.HandleFunc("POST /api/v1/setup/github-app", h.start)
	h.mux.HandleFunc("GET "+CallbackPath, h.callback)
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, pattern := h.mux.Handler(r); pattern == "" {
		httpserver.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	h.mux.ServeHTTP(w, r)
}

// FormAction is the origin the setup page's form posts to, for the page's
// Content-Security-Policy.
func (h *Handler) FormAction() string {
	u, err := url.Parse(h.opts.GitHubURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type permission struct {
	Name   string `json:"name"`
	Access string `json:"access"`
}

func (h *Handler) status(w http.ResponseWriter, _ *http.Request) {
	perms := make([]permission, 0, len(Permissions))
	for _, name := range []string{"contents", "pull_requests", "metadata", "members"} {
		perms = append(perms, permission{Name: name, Access: Permissions[name]})
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]any{
		"org":         h.opts.Org,
		"github_url":  h.opts.GitHubURL,
		"public_url":  h.opts.PublicURL,
		"app_name":    defaultAppName(h.opts.Org),
		"permissions": perms,
	})
}

func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	// only the setup page's script starts a setup: another site's page
	// cannot send the header without CORS, which is never allowed, so it
	// cannot replace someone's state mid-setup
	if r.Header.Get("X-Requested-With") == "" {
		httpserver.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "send X-Requested-With"})
		return
	}
	b, err := json.Marshal(newManifest(h.opts.Org, h.opts.PublicURL))
	if err != nil {
		httpserver.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	state := randomHex(32)
	http.SetCookie(w, h.stateCookieValue(state, int(stateTTL/time.Second)))
	action := fmt.Sprintf("%s/organizations/%s/settings/apps/new?state=%s",
		h.opts.GitHubURL, url.PathEscape(h.opts.Org), url.QueryEscape(state))
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"action": action, "manifest": string(b)})
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := h.opts.Logger
	q := r.URL.Query()

	cookie, err := r.Cookie(h.stateCookie)
	http.SetCookie(w, h.stateCookieValue("", -1))
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(q.Get("state"))) != 1 {
		log.WarnContext(ctx, "github app setup refused: state mismatch", "event", "github_app.setup_refused", "reason", ErrCodeState)
		h.fail(w, r, ErrCodeState)
		return
	}
	code := q.Get("code")
	if !validCode(code) {
		log.WarnContext(ctx, "github app setup refused: invalid code", "event", "github_app.setup_refused", "reason", ErrCodeGitHub)
		h.fail(w, r, ErrCodeGitHub)
		return
	}
	if !h.admitExchange() {
		log.WarnContext(ctx, "github app setup refused: too many codes this minute", "event", "github_app.setup_refused", "reason", ErrCodeBusy)
		h.fail(w, r, ErrCodeBusy)
		return
	}

	app, err := h.exchange(ctx, code)
	if err != nil {
		log.WarnContext(ctx, "github app setup failed", "event", "github_app.setup_failed", "error", err)
		h.fail(w, r, ErrCodeGitHub)
		return
	}
	// an App made in another account (someone's own org, posting the same
	// form there) must never become this control plane's
	if app.Owner.Type != "Organization" || !strings.EqualFold(app.Owner.Login, h.opts.Org) {
		log.WarnContext(ctx, "github app setup refused: the app is owned by another account",
			"event", "github_app.setup_refused", "reason", ErrCodeWrongOwner,
			"org", h.opts.Org, "owner", app.Owner.Login, "owner_type", app.Owner.Type, "app_id", app.ID, "app_slug", app.Slug)
		h.fail(w, r, ErrCodeWrongOwner)
		return
	}
	creds := Credentials{
		AppID:        strconv.FormatInt(app.ID, 10),
		Slug:         app.Slug,
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		PrivateKey:   app.PEM,
	}
	if err := creds.Validate(); err != nil {
		log.WarnContext(ctx, "github app setup failed: github returned unusable credentials", "event", "github_app.setup_failed", "error", err)
		h.fail(w, r, ErrCodeGitHub)
		return
	}
	// the request may end before the write does; the write must not
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exchangeTimeout)
	defer cancel()
	switch err := h.opts.Store.Create(saveCtx, creds); {
	case errors.Is(err, ErrAlreadySetUp):
		log.WarnContext(ctx, "github app setup refused: another app is set up already",
			"event", "github_app.setup_refused", "reason", ErrCodeAlreadySetUp, "app_id", creds.AppID, "app_slug", creds.Slug)
		h.fail(w, r, ErrCodeAlreadySetUp)
		return
	case err != nil:
		log.ErrorContext(ctx, "github app setup failed: could not store its credentials",
			"event", "github_app.setup_failed", "app_id", creds.AppID, "app_slug", creds.Slug, "error", err)
		h.fail(w, r, ErrCodeStore)
		return
	}
	log.WarnContext(ctx, "github app created and stored", "event", "github_app.created",
		"org", h.opts.Org, "app_id", creds.AppID, "app_slug", creds.Slug)
	if h.opts.OnCreated != nil {
		if err := h.opts.OnCreated(saveCtx, creds); err != nil {
			log.ErrorContext(ctx, "failed to start using the new github app; it is used once an instance reads it",
				"event", "github_app.setup_failed", "app_id", creds.AppID, "error", err)
		}
	}
	// installing is GitHub's own page: whoever installs picks the
	// repositories, and GitHub sends them back to the control plane
	http.Redirect(w, r, h.opts.GitHubURL+"/apps/"+url.PathEscape(creds.Slug)+"/installations/new", http.StatusFound)
}

// conversion is GitHub's answer to a manifest code: the new App and its
// credentials.
type conversion struct {
	ID    int64  `json:"id"`
	Slug  string `json:"slug"`
	Owner struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	PEM          string `json:"pem"`
}

// exchange turns a manifest code into the new App's credentials. GitHub
// takes no credentials for it: the code is the proof.
func (h *Handler) exchange(ctx context.Context, code string) (conversion, error) {
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	endpoint := h.opts.APIURL + "/app-manifests/" + url.PathEscape(code) + "/conversions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return conversion{}, fmt.Errorf("failed to exchange the github app manifest code: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := h.opts.Client.Do(req)
	if err != nil {
		return conversion{}, fmt.Errorf("failed to exchange the github app manifest code: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return conversion{}, fmt.Errorf("failed to read the github app manifest conversion: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		// GitHub's error body holds no credentials; keep it short
		return conversion{}, fmt.Errorf("failed to exchange the github app manifest code: github answered %d: %.200s", resp.StatusCode, body)
	}
	var out conversion
	if err := json.Unmarshal(body, &out); err != nil {
		return conversion{}, errors.New("failed to read the github app manifest conversion: not json")
	}
	return out, nil
}

// admitExchange counts an exchange against this minute's maxExchanges.
func (h *Handler) admitExchange() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.opts.Now()
	if now.Sub(h.window) >= time.Minute {
		h.window, h.exchanges = now, 0
	}
	if h.exchanges >= maxExchanges {
		return false
	}
	h.exchanges++
	return true
}

// fail sends the person back to the setup page with an error code.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/setup?error="+url.QueryEscape(code), http.StatusFound)
}

// stateCookieValue returns the state cookie; a negative maxAge clears it.
// It is at path /, as __Host- cookies must be, and lives for one setup.
func (h *Handler) stateCookieValue(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     h.stateCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secure,
		// GitHub's redirect back is a top-level navigation, which Lax
		// cookies go with
		SameSite: http.SameSiteLaxMode,
	}
}

// validCode reports whether a manifest code looks like GitHub's: letters
// and digits only, so it cannot change the path it is put in.
func validCode(code string) bool {
	if len(code) < 8 || len(code) > 100 {
		return false
	}
	for _, c := range code {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
