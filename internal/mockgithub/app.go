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

// verifyAppJWT checks an App JWT the way GitHub does: RS256 under the App's
// key, issued by the App, and valid for at most ten minutes.
func (s *Server) verifyAppJWT(r *http.Request) error {
	if s.opts.App.PublicKey == nil {
		return errors.New("no app configured")
	}
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return errors.New("missing bearer token")
	}
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return s.opts.App.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.opts.App.ID), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return err
	}
	if claims.IssuedAt == nil || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 10*time.Minute+time.Second {
		return errors.New("token lifetime exceeds ten minutes")
	}
	return nil
}

func (s *Server) withApp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.verifyAppJWT(r); err != nil {
			writeError(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
			return
		}
		next(w, r)
	}
}

func (s *Server) orgInstallation(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("org") != s.opts.Org {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": s.opts.App.InstallationID, "account": map[string]string{"login": s.opts.Org}})
}

func (s *Server) accessTokens(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") != strconv.FormatInt(s.opts.App.InstallationID, 10) {
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
		// like an unrestricted token: everything the app was granted
		in.Permissions = map[string]string{"contents": "write", "metadata": "read", "pull_requests": "write"}
	}
	for name, level := range in.Permissions {
		if (level != "read" && level != "write") || !granted(name, level) {
			writeError(w, http.StatusUnprocessableEntity, "The permissions requested are not granted to this installation.")
			return
		}
	}
	tok := "ghs_mock_" + random()
	ttl := s.opts.App.TokenTTL
	if ttl <= 0 {
		ttl = installationTokenTTL
	}
	expires := time.Now().Add(ttl).UTC().Truncate(time.Second)
	s.mu.Lock()
	s.installTokens[tok] = installationToken{permissions: in.Permissions, expires: expires}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": expires, "permissions": in.Permissions})
}

// granted reports whether the mock App holds a permission: what the sealer
// needs, nothing more.
func granted(name, level string) bool {
	switch name {
	case "metadata":
		return level == "read"
	case "contents", "pull_requests":
		return true
	}
	return false
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
