package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// jwksRefetchInterval is the least time between two fetches of one issuer's
// JWKS. A token naming a key the control plane has not seen makes it fetch
// the set again, as issuers rotate keys, and anyone can send such a token:
// without a floor, every forged token would be a request to the issuer.
const jwksRefetchInterval = 30 * time.Second

// maxJWKSBytes bounds an issuer's JWKS response.
const maxJWKSBytes = 1 << 20

// signingAlgs are the algorithms projected service-account tokens are signed
// with.
var signingAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// remoteKeySet verifies tokens against an issuer's JWKS, fetched on first
// use and again when a token names a key it does not hold, at most once per
// jwksRefetchInterval. It replaces go-oidc's RemoteKeySet, which refetches
// on every such token.
type remoteKeySet struct {
	url    string
	client *http.Client
	now    func() time.Time

	// fetchMu lets one fetch run at a time; tokens waiting on it then see
	// its result instead of fetching again
	fetchMu sync.Mutex
	mu      sync.RWMutex
	keys    []jose.JSONWebKey
	// fetched is when the last fetch started, successful or not
	fetched time.Time
}

func newRemoteKeySet(url string, client *http.Client, now func() time.Time) *remoteKeySet {
	if now == nil {
		now = time.Now
	}
	return &remoteKeySet{url: url, client: client, now: now}
}

// VerifySignature implements oidc.KeySet. The verifier calling it has
// already checked the token's algorithm and claims.
func (s *remoteKeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(token, signingAlgs)
	if err != nil {
		return nil, fmt.Errorf("malformed token: %w", err)
	}
	kid := ""
	if len(jws.Signatures) > 0 {
		kid = jws.Signatures[0].Header.KeyID
	}
	s.mu.RLock()
	keys := s.keys
	s.mu.RUnlock()
	if payload, ok := verifyWith(keys, kid, jws); ok {
		return payload, nil
	}
	keys, err = s.refresh(ctx)
	if err != nil {
		return nil, err
	}
	if payload, ok := verifyWith(keys, kid, jws); ok {
		return payload, nil
	}
	return nil, errors.New("failed to verify token signature")
}

// refresh fetches the key set again, unless a fetch started less than
// jwksRefetchInterval ago; then it returns the keys held.
func (s *remoteKeySet) refresh(ctx context.Context) ([]jose.JSONWebKey, error) {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	now := s.now()
	s.mu.RLock()
	keys, fetched := s.keys, s.fetched
	s.mu.RUnlock()
	if !fetched.IsZero() && now.Sub(fetched) < jwksRefetchInterval {
		return keys, nil
	}
	// the fetch serves every token waiting on it, so one caller giving up
	// must not fail it; the client's timeout bounds it
	fresh, err := s.fetch(context.WithoutCancel(ctx))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetched = now
	if err != nil {
		return nil, err
	}
	s.keys = fresh
	return fresh, nil
}

func (s *remoteKeySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks %s: %w", s.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch jwks %s: status %d", s.url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks %s: %w", s.url, err)
	}
	if len(data) > maxJWKSBytes {
		return nil, fmt.Errorf("failed to read jwks %s: larger than %d bytes", s.url, maxJWKSBytes)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("failed to parse jwks %s: %w", s.url, err)
	}
	var keys []jose.JSONWebKey
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		// keys of a type go-jose cannot read are skipped, as RFC 7517 asks
		if err := json.Unmarshal(raw, &k); err != nil || !k.IsPublic() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("failed to parse jwks %s: no signing keys", s.url)
	}
	return keys, nil
}

// verifyWith returns the token's payload when one of keys, the one it names
// if it names one, verifies its signature.
func verifyWith(keys []jose.JSONWebKey, kid string, jws *jose.JSONWebSignature) ([]byte, bool) {
	for i := range keys {
		if kid != "" && keys[i].KeyID != kid {
			continue
		}
		if payload, err := jws.Verify(&keys[i]); err == nil {
			return payload, true
		}
	}
	return nil, false
}
