package mockgithub

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// installationTokenTTL is how long a mock installation token lives, as on
// GitHub.
const installationTokenTTL = time.Hour

// App configures the mock GitHub App.
type App struct {
	ID             string
	PublicKey      *rsa.PublicKey
	InstallationID int64
	// TokenTTL is the installation token lifetime; GitHub's hour by default.
	TokenTTL time.Duration
}

// installationToken is a minted installation token and what it may do.
type installationToken struct {
	permissions map[string]string
	expires     time.Time
}

// registeredApp is a GitHub App the mock knows: the one Options configures,
// or one created from a manifest. Each signs people in with its own client
// and is installed on its owner org, once installed.
type registeredApp struct {
	id           string
	name         string
	slug         string
	owner        string
	publicKey    *rsa.PublicKey
	clientID     string
	clientSecret string
	callbackURLs []string
	setupURL     string
	permissions  map[string]string
	// installationID is 0 until the App is installed
	installationID int64
	tokenTTL       time.Duration
}

// grants reports whether the App holds a permission at level: write
// covers read.
func (a *registeredApp) grants(name, level string) bool {
	held := a.permissions[name]
	return held == "write" || (held == "read" && level == "read")
}

// app returns the App whose field matches, or nil; s.mu must not be held.
func (s *Server) app(match func(*registeredApp) bool) *registeredApp {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps {
		if match(a) {
			return a
		}
	}
	return nil
}

// verifyAppJWT checks an App JWT the way GitHub does: RS256 under the key
// of the App that issued it, and valid for at most ten minutes. It returns
// that App.
func (s *Server) verifyAppJWT(r *http.Request) (*registeredApp, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, errors.New("missing bearer token")
	}
	var claims jwt.RegisteredClaims
	var app *registeredApp
	_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		iss, _ := t.Claims.GetIssuer()
		app = s.app(func(a *registeredApp) bool { return a.id == iss && a.publicKey != nil })
		if app == nil {
			return nil, errors.New("no such app")
		}
		return app.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, err
	}
	if claims.IssuedAt == nil || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 10*time.Minute+time.Second {
		return nil, errors.New("token lifetime exceeds ten minutes")
	}
	return app, nil
}

func (s *Server) withApp(next func(http.ResponseWriter, *http.Request, *registeredApp)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, err := s.verifyAppJWT(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
			return
		}
		next(w, r, app)
	}
}

func (s *Server) orgInstallation(w http.ResponseWriter, r *http.Request, app *registeredApp) {
	s.mu.Lock()
	id := app.installationID
	s.mu.Unlock()
	if !strings.EqualFold(r.PathValue("org"), app.owner) || id == 0 {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "account": map[string]string{"login": app.owner}})
}

func (s *Server) accessTokens(w http.ResponseWriter, r *http.Request, app *registeredApp) {
	s.mu.Lock()
	id := app.installationID
	s.mu.Unlock()
	if id == 0 || r.PathValue("id") != strconv.FormatInt(id, 10) {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	var in struct {
		Permissions map[string]string `json:"permissions"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "Invalid request")
			return
		}
	}
	if len(in.Permissions) == 0 {
		// like an unrestricted token: every repository permission the
		// App was granted
		in.Permissions = map[string]string{}
		for name, level := range app.permissions {
			if name != "members" {
				in.Permissions[name] = level
			}
		}
	}
	for name, level := range in.Permissions {
		if (level != "read" && level != "write") || !app.grants(name, level) {
			writeError(w, http.StatusUnprocessableEntity, "The permissions requested are not granted to this installation.")
			return
		}
	}
	tok := "ghs_mock_" + random()
	ttl := app.tokenTTL
	if ttl <= 0 {
		ttl = installationTokenTTL
	}
	expires := time.Now().Add(ttl).UTC().Truncate(time.Second)
	s.mu.Lock()
	s.installTokens[tok] = installationToken{permissions: in.Permissions, expires: expires}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": expires, "permissions": in.Permissions})
}

// defaultRateLimit is GitHub's hourly budget for an installation.
const defaultRateLimit = 5000

// withInstallation requires an installation token holding permission at
// level: read accepts read or write, write only write. Each call counts
// against the rate limit, as on GitHub.
func (s *Server) withInstallation(permission, level string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		tok, ok := s.installTokens[raw]
		limit, remaining, reset := s.rateLimit(), -1, s.window.Add(time.Hour)
		if ok {
			s.calls++
			remaining = limit - s.calls
		}
		s.mu.Unlock()
		if !ok || time.Now().After(tok.expires) {
			writeError(w, http.StatusUnauthorized, "Bad credentials")
			return
		}
		h := w.Header()
		h.Set("X-RateLimit-Limit", strconv.Itoa(limit))
		h.Set("X-RateLimit-Remaining", strconv.Itoa(max(remaining, 0)))
		h.Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		h.Set("X-RateLimit-Resource", "core")
		if remaining < 0 {
			writeError(w, http.StatusForbidden, "API rate limit exceeded for installation.")
			return
		}
		if held := tok.permissions[permission]; held == "" || (level == "write" && held != "write") {
			writeError(w, http.StatusForbidden, "Resource not accessible by integration")
			return
		}
		next(w, r)
	}
}

// rateLimit is the budget of the current window; s.mu must be held.
func (s *Server) rateLimit() int {
	if s.opts.RateLimit > 0 {
		return s.opts.RateLimit
	}
	// never used up
	return defaultRateLimit + s.calls + 1
}

// ResetRateLimit starts the next rate limit window, as GitHub does every
// hour.
func (s *Server) ResetRateLimit() {
	s.mu.Lock()
	s.calls, s.window = 0, s.window.Add(time.Hour)
	s.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"message": msg})
}
