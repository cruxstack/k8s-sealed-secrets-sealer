// Package userauth signs people in to the control plane with GitHub OAuth.
// A signed-in user holds an HttpOnly session cookie (an HS256 JWT bound to
// this deployment's URL and env); state-changing requests must also carry a
// CSRF token derived from that cookie, which only this deployment can
// compute and only a page that can read /me can learn.
package userauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MinSessionKeyBytes is the shortest session signing key accepted.
const MinSessionKeyBytes = 32

const sessionIssuer = "k8s-sealed-secrets-sealer/user"

// ErrUnauthorized is returned for any session that is missing or invalid.
var ErrUnauthorized = errors.New("unauthorized")

// User is a signed-in GitHub user.
type User struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

type userKey struct{}

// WithUser returns ctx carrying u.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// UserFrom returns the signed-in user in ctx, or nil.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(userKey{}).(*User)
	return u
}

// Sessions issues and verifies session JWTs and derives CSRF tokens.
type Sessions struct {
	key      []byte
	csrfKey  []byte
	audience string
	env      string
	ttl      time.Duration
	now      func() time.Time
}

type claims struct {
	Env       string `json:"env"`
	GitHubID  int64  `json:"ghid"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar,omitempty"`
	jwt.RegisteredClaims
}

// NewSessions returns a Sessions. audience is this deployment's public URL.
func NewSessions(key []byte, audience, env string, ttl time.Duration, now func() time.Time) (*Sessions, error) {
	if len(key) < MinSessionKeyBytes {
		return nil, fmt.Errorf("failed to create user sessions: key must be at least %d bytes", MinSessionKeyBytes)
	}
	if audience == "" || env == "" || ttl <= 0 {
		return nil, errors.New("failed to create user sessions: audience, env and ttl are required")
	}
	if now == nil {
		now = time.Now
	}
	// a separate key for CSRF tokens, so they can never verify as a session
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sessionIssuer + "/csrf/v1"))
	return &Sessions{key: key, csrfKey: mac.Sum(nil), audience: audience, env: env, ttl: ttl, now: now}, nil
}

// Issue returns a session token for u and when it expires.
func (s *Sessions) Issue(u User) (string, time.Time, error) {
	now := s.now().UTC().Truncate(time.Second)
	exp := now.Add(s.ttl)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Env:       s.env,
		GitHubID:  u.ID,
		Name:      u.Name,
		AvatarURL: u.AvatarURL,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    sessionIssuer,
			Subject:   u.Login,
			Audience:  jwt.ClaimStrings{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}).SignedString(s.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign session for %s: %w", u.Login, err)
	}
	return token, exp, nil
}

// Verify checks a session token and returns its user.
func (s *Sessions) Verify(token string) (*User, error) {
	var c claims
	_, err := jwt.ParseWithClaims(token, &c,
		func(*jwt.Token) (any, error) { return s.key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(sessionIssuer),
		jwt.WithAudience(s.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(s.now),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	if c.Env != s.env || c.GitHubID == 0 || c.Subject == "" {
		return nil, fmt.Errorf("%w: session is for another env or has no user", ErrUnauthorized)
	}
	return &User{ID: c.GitHubID, Login: c.Subject, Name: c.Name, AvatarURL: c.AvatarURL}, nil
}

// CSRFToken derives the CSRF token for a session token. It is tied to the
// session, so a token for one session is useless with another.
func (s *Sessions) CSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	mac.Write([]byte(sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}
