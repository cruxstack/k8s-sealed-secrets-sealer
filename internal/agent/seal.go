package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Sealer runs seal.v1. It trusts nothing in the command it can check
// itself: the targets must be well formed and never cluster-wide, the key
// must be in its own controller's key set (the certificate comes from the
// cluster, never from the command), and the value must open under the
// transit key for this command and this agent.
type Sealer struct {
	keys    Collector
	kms     envelope.Decrypter
	keyID   string
	env     string
	agentID func() string
	logger  *slog.Logger
	rand    io.Reader
}

// SealerOptions configures a Sealer.
type SealerOptions struct {
	// Keys reads the controller's key set; it is read fresh for every seal.
	Keys Collector
	// KMS decrypts values under TransitKeyID.
	KMS          envelope.Decrypter
	TransitKeyID string
	Env          string
	// AgentID returns this agent's ID, which values are encrypted for.
	AgentID func() string
	Logger  *slog.Logger
	// Rand overrides the randomness sealing uses, for tests.
	Rand io.Reader
}

// NewSealer returns a Sealer. It makes no network calls.
func NewSealer(opts SealerOptions) *Sealer {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	rnd := opts.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	return &Sealer{
		keys:    opts.Keys,
		kms:     opts.KMS,
		keyID:   opts.TransitKeyID,
		env:     opts.Env,
		agentID: opts.AgentID,
		logger:  logger,
		rand:    rnd,
	}
}

// Seal runs seal.v1: it decrypts the value, seals it for each target with
// the requested key's certificate, and returns only the ciphertexts.
func (s *Sealer) Seal(ctx context.Context, cmd protocol.Command) (any, error) {
	var p protocol.SealPayload
	if err := strictDecode(cmd.Payload, &p); err != nil {
		return nil, err
	}
	if err := checkSealPayload(p); err != nil {
		return nil, err
	}
	agentID := s.agentID()
	if agentID == "" {
		return nil, errors.New("refusing to seal: this agent has not logged in")
	}

	pub, err := s.certificate(ctx, p.Fingerprint)
	if err != nil {
		return nil, err
	}
	value, err := envelope.Open(ctx, s.kms, s.keyID, *p.Value, protocol.SealContext(s.env, cmd.ID, agentID))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt the value: %w", err)
	}
	defer clear(value)

	res := protocol.SealResult{Fingerprint: p.Fingerprint, Targets: make([]protocol.SealedTarget, 0, len(p.Targets))}
	for _, t := range p.Targets {
		label := ssv1alpha1.EncryptionLabel(t.Namespace, t.Name, scopeOf(t.Scope))
		ct, err := sscrypto.HybridEncrypt(s.rand, pub, value, label)
		if err != nil {
			return nil, fmt.Errorf("failed to seal for %s/%s: %w", t.Namespace, t.Name, err)
		}
		res.Targets = append(res.Targets, protocol.SealedTarget{
			Namespace:  t.Namespace,
			Name:       t.Name,
			Ciphertext: base64.StdEncoding.EncodeToString(ct),
		})
	}
	s.logger.InfoContext(ctx, "value sealed",
		"event", "seal.sealed", "env", s.env, "command_id", cmd.ID, "key", p.Key,
		"fingerprint", p.Fingerprint, "targets", len(res.Targets))
	return res, nil
}

// certificate returns the public key of fingerprint from the controller's
// own key set.
func (s *Sealer) certificate(ctx context.Context, fingerprint string) (*rsa.PublicKey, error) {
	report, err := s.keys.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read the controller's keys: %w", err)
	}
	for _, k := range report.Keys {
		if k.Fingerprint != fingerprint {
			continue
		}
		got, pub, err := keys.ParseCert([]byte(k.Certificate))
		if err != nil {
			return nil, fmt.Errorf("failed to use certificate of key %s: %w", fingerprint, err)
		}
		if got.Fingerprint != fingerprint {
			return nil, fmt.Errorf("certificate of key %s has fingerprint %s", fingerprint, got.Fingerprint)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("refusing to seal: key %s is not in this cluster's key set", fingerprint)
}

// checkSealPayload validates what a seal asks for. Cluster-wide scope is
// refused outright: such ciphertext decrypts into any namespace.
func checkSealPayload(p protocol.SealPayload) error {
	switch {
	case len(validation.IsConfigMapKey(p.Key)) > 0:
		return errors.New("invalid payload: key is not a valid Secret key")
	case !strings.HasPrefix(p.Fingerprint, "SHA256:") || len(p.Fingerprint) > 128:
		return errors.New("invalid payload: not a key fingerprint")
	case len(p.Targets) == 0 || len(p.Targets) > protocol.MaxSealTargets:
		return fmt.Errorf("invalid payload: 1 to %d targets required", protocol.MaxSealTargets)
	case p.Value == nil:
		return errors.New("invalid payload: no value")
	}
	for _, t := range p.Targets {
		if len(validation.IsDNS1123Label(t.Namespace)) > 0 {
			return fmt.Errorf("invalid payload: %q is not a namespace", t.Namespace)
		}
		if len(validation.IsDNS1123Subdomain(t.Name)) > 0 {
			return fmt.Errorf("invalid payload: %q is not a Secret name", t.Name)
		}
		if t.Scope != protocol.ScopeStrict && t.Scope != protocol.ScopeNamespaceWide {
			return fmt.Errorf("refusing to seal: scope %q is not strict or namespace-wide", t.Scope)
		}
	}
	return nil
}

func scopeOf(scope string) ssv1alpha1.SealingScope {
	if scope == protocol.ScopeNamespaceWide {
		return ssv1alpha1.NamespaceWideScope
	}
	return ssv1alpha1.StrictScope
}
