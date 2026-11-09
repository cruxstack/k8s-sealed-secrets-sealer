package agentauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MinSessionKeyBytes is the shortest session signing key accepted.
const MinSessionKeyBytes = 32

// SessionTTL is how long an agent session token is valid.
const SessionTTL = 15 * time.Minute

// sessionAudience scopes session tokens to the agent API, so they are never
// accepted anywhere else.
const sessionAudience = "k8s-sealed-secrets-sealer/agent-api"

// Sessions issues and verifies agent session tokens: HS256 JWTs bound to one
// agent, one env and this control plane.
type Sessions struct {
	key    []byte
	issuer string
	env    string
	now    func() time.Time
}

type sessionClaims struct {
	Env string `json:"env"`
	jwt.RegisteredClaims
}

// NewSessions returns a Sessions that signs with key. issuer identifies this
// control plane (its public URL).
func NewSessions(key []byte, issuer, env string, now func() time.Time) (*Sessions, error) {
	if len(key) < MinSessionKeyBytes {
		return nil, fmt.Errorf("failed to create session signer: key must be at least %d bytes", MinSessionKeyBytes)
	}
	if issuer == "" || env == "" {
		return nil, errors.New("failed to create session signer: issuer and env are required")
	}
	if now == nil {
		now = time.Now
	}
	return &Sessions{key: key, issuer: issuer, env: env, now: now}, nil
}

// Issue returns a session token for agentID and when it expires.
func (s *Sessions) Issue(agentID string) (string, time.Time, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate session id: %w", err)
	}
	now := s.now().UTC().Truncate(time.Second)
	exp := now.Add(SessionTTL)
	claims := sessionClaims{
		Env: s.env,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   agentID,
			Audience:  jwt.ClaimStrings{sessionAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        hex.EncodeToString(id[:]),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign session for agent %s: %w", agentID, err)
	}
	return token, exp, nil
}

// Verify checks a session token and returns its agent ID.
func (s *Sessions) Verify(token string) (string, error) {
	var claims sessionClaims
	_, err := jwt.ParseWithClaims(token, &claims,
		func(*jwt.Token) (any, error) { return s.key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(sessionAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(s.now),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	if claims.Env != s.env {
		return "", fmt.Errorf("%w: session is for env %q", ErrUnauthorized, claims.Env)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("%w: session has no agent", ErrUnauthorized)
	}
	return claims.Subject, nil
}
