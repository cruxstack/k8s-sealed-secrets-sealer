package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sort"
	"strings"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// A sealed value is sealed-secrets' HybridEncrypt output: a 2-byte
// big-endian length, an RSA-OAEP (SHA-256) encryption of a one-time AES-256
// key under the value's label, then the value encrypted with AES-GCM under
// that key, with a zero nonce and no additional data. The label binds only
// the RSA part. Resealing rewraps: the agent decrypts the RSA part with the
// key that sealed it, encrypts the same one-time key to the env key with
// the same label, and keeps the AES-GCM part as it is. The value itself is
// never decrypted, not even in memory, and the one-time key is cleared at
// once. Keeping the one-time key is sound: it was only ever used for this
// value, which the old ciphertext, kept in git history, already opens to
// with the old key; the new one opens to nothing more.
//
// The label comes from the item's namespace, name and scope, as the
// controller derives it, and only that label is tried: the new value has
// the label the old one opened with, so a reseal can never move a value to
// another namespace, name or wider scope.

// sealedTagBytes is the AES-GCM tag every sealed value ends with.
const sealedTagBytes = 16

// Resealer runs reseal.v1. It trusts nothing in the command it can check
// itself: the env key must be in its own controller's key set and among
// the cluster's key Secrets, each value keeps the label its own namespace,
// name and scope give, and cluster-wide values are refused, as for a seal.
// It needs the keys capability's RBAC (list Secrets).
type Resealer struct {
	keys      Collector
	kube      kubernetes.Interface
	namespace string
	env       string
	logger    *slog.Logger
	rand      io.Reader
}

// ResealerOptions configures a Resealer.
type ResealerOptions struct {
	// Keys reads the controller's key set, which must hold the env key.
	Keys Collector
	// Kube reads the key Secrets in Namespace, the controller's.
	Kube      kubernetes.Interface
	Namespace string
	Env       string
	Logger    *slog.Logger
	// Rand overrides the randomness rewrapping uses, for tests.
	Rand io.Reader
}

// NewResealer returns a Resealer. It makes no network calls.
func NewResealer(opts ResealerOptions) *Resealer {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	rnd := opts.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	return &Resealer{keys: opts.Keys, kube: opts.Kube, namespace: opts.Namespace, env: opts.Env, logger: logger, rand: rnd}
}

// Reseal runs reseal.v1: for each item it finds the key that sealed it,
// with the item's own label, and rewraps it to the env key. A value the env
// key opens is current; one no key opens is failed. It returns ciphertexts
// only.
func (r *Resealer) Reseal(ctx context.Context, cmd protocol.Command) (any, error) {
	var p protocol.ResealPayload
	if err := strictDecode(cmd.Payload, &p); err != nil {
		return nil, err
	}
	if err := checkResealPayload(p); err != nil {
		return nil, err
	}
	if err := r.controllerHolds(ctx, p.EnvKey); err != nil {
		return nil, err
	}
	ring, err := readKeyRing(ctx, r.kube, r.namespace, r.logger, "values sealed with its key are not resealed")
	if err != nil {
		return nil, err
	}
	ring, err = resealOrder(ring, p.EnvKey)
	if err != nil {
		return nil, err
	}

	res := protocol.ResealResult{Items: make([]protocol.ResealedItem, 0, len(p.Items))}
	counts := map[string]int{}
	for _, it := range p.Items {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("failed to reseal every value in time: %w", err)
		}
		out := resealItem(r.rand, it, ring)
		counts[out.Status]++
		res.Items = append(res.Items, out)
	}
	r.logger.InfoContext(ctx, "values resealed",
		"event", "reseal.done", "env", r.env, "command_id", cmd.ID, "env_key", p.EnvKey,
		"resealed", counts[protocol.ResealResealed], "current", counts[protocol.ResealCurrent], "failed", counts[protocol.ResealFailed])
	return res, nil
}

// controllerHolds checks that the controller's own key set has the key, as
// a seal does: values move only to a key this cluster decrypts with.
func (r *Resealer) controllerHolds(ctx context.Context, fingerprint string) error {
	report, err := r.keys.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to read the controller's keys: %w", err)
	}
	for _, k := range report.Keys {
		if k.Fingerprint != fingerprint {
			continue
		}
		got, _, err := keys.ParseCert([]byte(k.Certificate))
		if err != nil {
			return fmt.Errorf("failed to use certificate of key %s: %w", fingerprint, err)
		}
		if got.Fingerprint != fingerprint {
			return fmt.Errorf("certificate of key %s has fingerprint %s", fingerprint, got.Fingerprint)
		}
		return nil
	}
	return fmt.Errorf("refusing to reseal: key %s is not in this cluster's key set", fingerprint)
}

// resealOrder returns the ring with the env key first, so a value already
// on it is found at once, then the newest keys. The env key must be in it:
// its private key checks every rewrapped value.
func resealOrder(ring []sealingKey, envKey string) ([]sealingKey, error) {
	ring = append([]sealingKey(nil), ring...)
	sort.SliceStable(ring, func(i, j int) bool {
		a, b := ring[i], ring[j]
		if (a.fingerprint == envKey) != (b.fingerprint == envKey) {
			return a.fingerprint == envKey
		}
		if !a.notBefore.Equal(b.notBefore) {
			return a.notBefore.After(b.notBefore)
		}
		return a.fingerprint > b.fingerprint
	})
	if len(ring) == 0 || ring[0].fingerprint != envKey {
		return nil, fmt.Errorf("refusing to reseal: key %s is not among this cluster's key Secrets", envKey)
	}
	return ring, nil
}

// checkResealPayload validates what a reseal asks for. A malformed payload
// is refused as a whole; a value that is not a sealed value fails alone.
func checkResealPayload(p protocol.ResealPayload) error {
	switch {
	case !strings.HasPrefix(p.EnvKey, "SHA256:") || len(p.EnvKey) > 128:
		return errors.New("invalid payload: env_key is not a key fingerprint")
	case len(p.Items) == 0 || len(p.Items) > protocol.MaxResealItems:
		return fmt.Errorf("invalid payload: 1 to %d items required", protocol.MaxResealItems)
	}
	seen := map[string]bool{}
	budget := 0
	for _, it := range p.Items {
		switch {
		case it.ID == "" || len(it.ID) > protocol.MaxResealIDBytes:
			return errors.New("invalid payload: an item has no usable id")
		case seen[it.ID]:
			return fmt.Errorf("invalid payload: item %q is listed twice", it.ID)
		case len(validation.IsDNS1123Label(it.Namespace)) > 0:
			return fmt.Errorf("invalid payload: %q is not a namespace", it.Namespace)
		case len(validation.IsDNS1123Subdomain(it.Name)) > 0:
			return fmt.Errorf("invalid payload: %q is not a Secret name", it.Name)
		case it.Scope != protocol.ScopeStrict && it.Scope != protocol.ScopeNamespaceWide && it.Scope != protocol.ScopeClusterWide:
			return fmt.Errorf("invalid payload: %q is not a scope", it.Scope)
		}
		seen[it.ID] = true
		budget += protocol.ResealItemCost(len(it.Ciphertext))
	}
	if budget > protocol.ResealBudgetBytes {
		return fmt.Errorf("invalid payload: the items are larger than %d KiB", protocol.ResealBudgetBytes>>10)
	}
	return nil
}

// resealItem reseals one value with the keys in ring, the env key first.
func resealItem(rnd io.Reader, it protocol.ResealItem, ring []sealingKey) protocol.ResealedItem {
	failed := func(msg string) protocol.ResealedItem {
		return protocol.ResealedItem{ID: it.ID, Status: protocol.ResealFailed, Error: msg}
	}
	if it.Scope == protocol.ScopeClusterWide {
		return failed("refusing to reseal a cluster-wide value: it decrypts into any namespace; seal it again as strict or namespace-wide")
	}
	raw, err := base64.StdEncoding.DecodeString(it.Ciphertext)
	if err != nil {
		return failed("not a sealed value: it is not base64")
	}
	wrapped, sealed, ok := splitSealed(raw)
	if !ok {
		return failed("not a sealed value: it is too short")
	}
	scope := ssv1alpha1.StrictScope
	if it.Scope == protocol.ScopeNamespaceWide {
		scope = ssv1alpha1.NamespaceWideScope
	}
	label := ssv1alpha1.EncryptionLabel(it.Namespace, it.Name, scope)
	envKey := ring[0]
	for _, k := range ring {
		// an RSA ciphertext is as long as its key's modulus
		if k.priv.Size() != len(wrapped) {
			continue
		}
		sessionKey, err := rsa.DecryptOAEP(sha256.New(), nil, k.priv, wrapped, label)
		if err != nil {
			continue
		}
		if k.fingerprint == envKey.fingerprint {
			clear(sessionKey)
			return protocol.ResealedItem{ID: it.ID, Status: protocol.ResealCurrent}
		}
		out, err := rewrap(rnd, envKey, sessionKey, label, sealed)
		clear(sessionKey)
		if err != nil {
			return failed("failed to reseal it: " + err.Error())
		}
		return protocol.ResealedItem{ID: it.ID, Status: protocol.ResealResealed, Ciphertext: base64.StdEncoding.EncodeToString(out), From: k.fingerprint}
	}
	return failed(fmt.Sprintf("no key in this cluster opens it as a %s value of %s/%s", it.Scope, it.Namespace, it.Name))
}

// splitSealed splits a sealed value into its RSA part and the AES-GCM part
// after it, as HybridDecrypt does.
func splitSealed(raw []byte) (wrapped, sealed []byte, ok bool) {
	if len(raw) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(raw))
	if n == 0 || len(raw) < 2+n+sealedTagBytes {
		return nil, nil, false
	}
	return raw[2 : 2+n], raw[2+n:], true
}

// rewrap encrypts a value's one-time key to the env key with the same
// label, and puts the value's AES-GCM part after it unchanged. Before it
// returns, it checks that the env key opens the new RSA part to the same
// one-time key.
func rewrap(rnd io.Reader, envKey sealingKey, sessionKey, label, sealed []byte) ([]byte, error) {
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rnd, &envKey.priv.PublicKey, sessionKey, label)
	if err != nil {
		return nil, err
	}
	check, err := rsa.DecryptOAEP(sha256.New(), nil, envKey.priv, wrapped, label)
	same := err == nil && subtle.ConstantTimeCompare(check, sessionKey) == 1
	clear(check)
	if !same {
		return nil, errors.New("the env key does not open the resealed value")
	}
	if len(wrapped) > math.MaxUint16 {
		return nil, errors.New("the env key is too large")
	}
	out := make([]byte, 2, 2+len(wrapped)+len(sealed))
	binary.BigEndian.PutUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	return append(out, sealed...), nil
}
