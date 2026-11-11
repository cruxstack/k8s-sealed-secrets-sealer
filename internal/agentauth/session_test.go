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
	loggedIn := time.Now().Add(-time.Hour).Truncate(time.Second)
	token, exp, err := s.Issue("use1-blue", "binding", loggedIn)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < SessionTTL-time.Minute || d > SessionTTL {
		t.Errorf("expires in %s", d)
	}
	sess, err := s.Verify(token)
	if err != nil || sess.AgentID != "use1-blue" || sess.Binding != "binding" || !sess.LoggedInAt.Equal(loggedIn) {
		t.Fatalf("Verify = %+v, %v", sess, err)
	}
}

// A session is renewed for RenewalLimit after its agent last logged in
// with its identity, and not after.
func TestSessions_Renewable(t *testing.T) {
	now := time.Now()
	s := newSessions(t, func() time.Time { return now })
	for name, tc := range map[string]struct {
		loggedIn time.Time
		want     bool
	}{
		"just logged in":   {now, true},
		"within the limit": {now.Add(-RenewalLimit + time.Minute), true},
		"at the limit":     {now.Add(-RenewalLimit), false},
		"past the limit":   {now.Add(-RenewalLimit - time.Hour), false},
		"no login time":    {time.Time{}, false},
	} {
		if got := s.Renewable(Session{AgentID: "a", LoggedInAt: tc.loggedIn}); got != tc.want {
			t.Errorf("%s: Renewable = %v, want %v", name, got, tc.want)
		}
	}
}

func TestSessions_Rejects(t *testing.T) {
	base := time.Now()
	s := newSessions(t, func() time.Time { return base })
	good, _, err := s.Issue("use1-blue", "binding", base)
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
