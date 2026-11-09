package agentauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

const (
	issuerURL = "https://kubernetes.default.svc.cluster.local"
	audience  = "https://sealer.dev.example.com"
	agentSub  = "system:serviceaccount:use1-blue-sealer:sealer-agent"
)

type tokenSpec struct {
	issuer, subject string
	audience        []string
	expiry          time.Time
}

func goodSpec() tokenSpec {
	return tokenSpec{issuer: issuerURL, subject: agentSub, audience: []string{audience}, expiry: time.Now().Add(10 * time.Minute)}
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string, spec tokenSpec) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   spec.issuer,
		Subject:  spec.subject,
		Audience: spec.audience,
		Expiry:   jwt.NewNumericDate(spec.expiry),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func jwksJSON(t *testing.T, key *rsa.PrivateKey, kid string) []byte {
	t.Helper()
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func registryWith(t *testing.T, issuer string) *registry.Registry {
	t.Helper()
	r, err := registry.Parse([]byte(issuer+`
agents:
  - id: use1-blue
    cluster: blue
    region: use1
    capabilities: [seal]
    identity:
      k8s: {issuer: local, subject: "`+agentSub+`"}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fileVerifier(t *testing.T, key *rsa.PrivateKey) *K8sVerifier {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwksJSON(t, key, "k1"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := registryWith(t, "issuers: [{name: local, url: \""+issuerURL+"\", jwksFile: \""+path+"\"}]")
	v, err := NewK8sVerifier(K8sOptions{Registry: reg, Audience: audience})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestK8sVerifier_AcceptsRegisteredServiceAccount(t *testing.T) {
	key := testcerts.RSA(t, 2048)
	v := fileVerifier(t, key)
	agent, err := v.Verify(context.Background(), sign(t, key, "k1", goodSpec()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if agent.ID != "use1-blue" {
		t.Errorf("agent = %q", agent.ID)
	}
}

func TestK8sVerifier_Rejects(t *testing.T) {
	key := testcerts.RSA(t, 2048)
	other := testcerts.RSA(t, 2048)
	v := fileVerifier(t, key)

	mutate := func(f func(*tokenSpec)) tokenSpec {
		s := goodSpec()
		f(&s)
		return s
	}
	cases := map[string]string{
		"other signing key": sign(t, other, "k1", goodSpec()),
		"wrong audience":    sign(t, key, "k1", mutate(func(s *tokenSpec) { s.audience = []string{"https://other.example.com"} })),
		"unknown issuer":    sign(t, key, "k1", mutate(func(s *tokenSpec) { s.issuer = "https://evil.example.com" })),
		"expired":           sign(t, key, "k1", mutate(func(s *tokenSpec) { s.expiry = time.Now().Add(-time.Minute) })),
		"unregistered sa":   sign(t, key, "k1", mutate(func(s *tokenSpec) { s.subject = "system:serviceaccount:default:rogue" })),
		"not a jwt":         "garbage",
		"empty":             "",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), token); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("Verify = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestK8sVerifier_RemoteJWKS(t *testing.T) {
	key := testcerts.RSA(t, 2048)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, key, "k1"))
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, testcerts.PEM(srv.Certificate()), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := registryWith(t, "issuers: [{name: local, url: \""+issuerURL+"\", jwksURL: \""+srv.URL+"/keys\", caFile: \""+caPath+"\"}]")
	v, err := NewK8sVerifier(K8sOptions{Registry: reg, Audience: audience})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), sign(t, key, "k1", goodSpec())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
