package agentauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var sessionKey = []byte("0123456789abcdef0123456789abcdef")

func newSessions(t *testing.T, now func() time.Time) *Sessions {
	t.Helper()
	s, err := NewSessions(sessionKey, "https://sealer.dev.example.com", "dev", now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSessions_RoundTrip(t *testing.T) {
	s := newSessions(t, nil)
	token, exp, err := s.Issue("use1-blue")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < SessionTTL-time.Minute || d > SessionTTL {
		t.Errorf("expires in %s", d)
	}
	id, err := s.Verify(token)
	if err != nil || id != "use1-blue" {
		t.Fatalf("Verify = %q, %v", id, err)
	}
}

func TestSessions_Rejects(t *testing.T) {
	base := time.Now()
	s := newSessions(t, func() time.Time { return base })
	good, _, err := s.Issue("use1-blue")
	if err != nil {
		t.Fatal(err)
	}

	later := newSessions(t, func() time.Time { return base.Add(SessionTTL + time.Minute) })
	otherKey, _ := NewSessions([]byte("ffffffffffffffffffffffffffffffff"), "https://sealer.dev.example.com", "dev", nil)
	otherEnv, _ := NewSessions(sessionKey, "https://sealer.dev.example.com", "prod", nil)
	otherIssuer, _ := NewSessions(sessionKey, "https://sealer.prod.example.com", "dev", nil)

	// alg none, and a token whose audience is not the agent API
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, sessionClaims{Env: "dev", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "https://sealer.dev.example.com", Subject: "use1-blue", Audience: jwt.ClaimStrings{sessionAudience},
		ExpiresAt: jwt.NewNumericDate(base.Add(time.Minute)),
	}}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	wrongAud, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{Env: "dev", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "https://sealer.dev.example.com", Subject: "use1-blue", Audience: jwt.ClaimStrings{"something-else"},
		ExpiresAt: jwt.NewNumericDate(base.Add(time.Minute)),
	}}).SignedString(sessionKey)
	noExp, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{Env: "dev", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "https://sealer.dev.example.com", Subject: "use1-blue", Audience: jwt.ClaimStrings{sessionAudience},
	}}).SignedString(sessionKey)

	cases := map[string]struct {
		verifier *Sessions
		token    string
	}{
		"expired":        {later, good},
		"other key":      {otherKey, good},
		"other env":      {otherEnv, good},
		"other issuer":   {otherIssuer, good},
		"alg none":       {s, none},
		"other audience": {s, wrongAud},
		"no expiry":      {s, noExp},
		"garbage":        {s, "not.a.token"},
		"tampered":       {s, good[:len(good)-2] + "xx"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.verifier.Verify(tc.token); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Verify = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestNewSessions_RequiresStrongKey(t *testing.T) {
	_, err := NewSessions([]byte("short"), "https://x", "dev", nil)
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("err = %v", err)
	}
}
