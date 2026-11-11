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

// RenewalLimit is how long after an agent last logged in with its identity
// its sessions can still be renewed. Renewal carries the login's time over,
// so a session taken from an agent lasts this long at most, and the agent
// proves its identity again twice a day: for aws-sts, two calls to STS, far
// inside the STS call limits. A shorter limit would make more of those
// calls, each one a moment an attacker emptying the limits can lock the
// agent out at; a longer one would let a taken session last longer.
const RenewalLimit = 12 * time.Hour

// sessionAudience scopes session tokens to the agent API, so they are never
// accepted anywhere else.
const sessionAudience = "k8s-sealed-secrets-sealer/agent-api"

// Sessions issues and verifies agent session tokens: HS256 JWTs bound to one
// agent, as the registry has it, one env and this control plane.
type Sessions struct {
	key    []byte
	issuer string
	env    string
	now    func() time.Time
}

type sessionClaims struct {
	Env string `json:"env"`
	// Binding is the agent's registry.Registry.Binding when the session was
	// issued: the session is good only while the registry still has it.
	Binding string `json:"binding,omitempty"`
	// AuthTime is when the agent last logged in with its identity; a
	// renewed session carries it over.
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	jwt.RegisteredClaims
}

// Session is a verified agent session.
type Session struct {
	AgentID string
	// Binding is the agent's registry.Registry.Binding when the session was
	// issued.
	Binding string
	// LoggedInAt is when the agent last logged in with its identity. It is
	// zero for a session that does not say.
	LoggedInAt time.Time
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

// Issue returns a session token for agentID, registered with binding
// (registry.Registry.Binding), and when it expires. loggedInAt is when the
// agent last logged in with its identity: now for a login, the old
// session's for a renewal.
func (s *Sessions) Issue(agentID, binding string, loggedInAt time.Time) (string, time.Time, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate session id: %w", err)
	}
	now := s.now().UTC().Truncate(time.Second)
	exp := now.Add(SessionTTL)
	claims := sessionClaims{
		Env:      s.env,
		Binding:  binding,
		AuthTime: jwt.NewNumericDate(loggedInAt),
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

// Verify checks a session token and returns it. The caller compares its
// binding with the registry in force.
func (s *Sessions) Verify(token string) (Session, error) {
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
		return Session{}, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	if claims.Env != s.env {
		return Session{}, fmt.Errorf("%w: session is for env %q", ErrUnauthorized, claims.Env)
	}
	if claims.Subject == "" {
		return Session{}, fmt.Errorf("%w: session has no agent", ErrUnauthorized)
	}
	sess := Session{AgentID: claims.Subject, Binding: claims.Binding}
	if claims.AuthTime != nil {
		sess.LoggedInAt = claims.AuthTime.Time
	}
	return sess, nil
}

// Renewable reports whether a session may be renewed: its agent logged in
// with its identity within RenewalLimit.
func (s *Sessions) Renewable(sess Session) bool {
	return !sess.LoggedInAt.IsZero() && s.now().Sub(sess.LoggedInAt) < RenewalLimit
}
