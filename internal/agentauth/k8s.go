// Package agentauth authenticates agents: it verifies the identity an agent
// logs in with and issues and checks the short-lived session tokens agents
// use for every other call.
package agentauth

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
)

// ErrUnauthorized is returned for every failed login. The reason is logged,
// never returned to the caller.
var ErrUnauthorized = errors.New("unauthorized")

// maxTokenBytes bounds a projected service-account token.
const maxTokenBytes = 16 << 10

// K8sVerifier verifies projected service-account tokens against the issuers
// in the agent registry and maps them to registered agents.
type K8sVerifier struct {
	reg       *registry.Registry
	verifiers map[string]*oidc.IDTokenVerifier // by issuer URL
	names     map[string]string                // issuer URL -> registry name
}

// K8sOptions configures a K8sVerifier.
type K8sOptions struct {
	Registry *registry.Registry
	// Audience is the aud claim tokens must carry: this control plane's URL.
	Audience string
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// NewK8sVerifier builds a verifier for every issuer in the registry. It reads
// JWKS files now; remote JWKS are fetched on first use and cached.
func NewK8sVerifier(opts K8sOptions) (*K8sVerifier, error) {
	if opts.Audience == "" {
		return nil, errors.New("failed to create token verifier: audience is required")
	}
	v := &K8sVerifier{
		reg:       opts.Registry,
		verifiers: map[string]*oidc.IDTokenVerifier{},
		names:     map[string]string{},
	}
	for _, is := range opts.Registry.Issuers {
		keySet, err := keySetFor(is)
		if err != nil {
			return nil, err
		}
		v.verifiers[is.URL] = oidc.NewVerifier(is.URL, keySet, &oidc.Config{
			ClientID:             opts.Audience,
			SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
			Now:                  opts.Now,
		})
		v.names[is.URL] = is.Name
	}
	return v, nil
}

// Verify checks a token's signature, issuer, audience and expiry, and returns
// the agent registered for its subject.
func (v *K8sVerifier) Verify(ctx context.Context, token string) (*registry.Agent, error) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return nil, fmt.Errorf("%w: token is empty or too large", ErrUnauthorized)
	}
	// The issuer only selects which verifier to use; that verifier checks
	// the claim again against the signed token.
	iss, err := unverifiedIssuer(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	verifier, ok := v.verifiers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: unknown issuer %q", ErrUnauthorized, iss)
	}
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	agent, ok := v.reg.AgentByK8s(v.names[iss], idToken.Subject)
	if !ok {
		return nil, fmt.Errorf("%w: subject %q is not a registered agent", ErrUnauthorized, idToken.Subject)
	}
	return agent, nil
}

func unverifiedIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("token is not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("token payload is not base64url")
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("token payload is not JSON")
	}
	return claims.Issuer, nil
}

func keySetFor(is registry.Issuer) (oidc.KeySet, error) {
	if is.JWKSFile != "" {
		data, err := os.ReadFile(is.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read jwks for issuer %s: %w", is.Name, err)
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(data, &set); err != nil {
			return nil, fmt.Errorf("failed to parse jwks for issuer %s: %w", is.Name, err)
		}
		var pub []crypto.PublicKey
		for _, k := range set.Keys {
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if !k.IsPublic() {
				return nil, fmt.Errorf("failed to parse jwks for issuer %s: key %q is not a public key", is.Name, k.KeyID)
			}
			pub = append(pub, k.Key)
		}
		if len(pub) == 0 {
			return nil, fmt.Errorf("failed to parse jwks for issuer %s: no signing keys", is.Name)
		}
		return &oidc.StaticKeySet{PublicKeys: pub}, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if is.CAFile != "" {
		pem, err := os.ReadFile(is.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read ca bundle for issuer %s: %w", is.Name, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to parse ca bundle for issuer %s", is.Name)
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	// the key set keeps this context for every later fetch, so it must not
	// be a request's context
	return oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), is.JWKSURL), nil
}
