package agent

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/keyutil"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Annotations the agent sets on key Secrets it restores.
const (
	annotationFingerprint  = "sealer.cruxstack.io/fingerprint"
	annotationRestoredFrom = "sealer.cruxstack.io/restored-from"
	annotationRestoredAt   = "sealer.cruxstack.io/restored-at"
)

// The controller's key label and the value it loads keys with.
const (
	keyLabel                  = "sealedsecrets.bitnami.com/sealed-secrets-key"
	keyLabelActive            = "active"
	escrowedRestoredFromValue = "escrow"
)

// EscrowClient is the part of the control plane API key sync uses.
type EscrowClient interface {
	PutEscrow(ctx context.Context, fingerprint string, in protocol.EscrowUpload) error
	GetEscrow(ctx context.Context, fingerprint string) (protocol.EscrowRecord, error)
}

// KMS is the part of KMS key sync uses. Agent roles may generate data keys
// under the escrow key and decrypt them.
type KMS interface {
	envelope.DataKeyGenerator
	envelope.Decrypter
}

// KeySync escrows the controller's sealing keys and restores keys the
// controller is missing. It needs the keys capability's RBAC.
type KeySync struct {
	kube        kubernetes.Interface
	namespace   string
	deployment  string
	kms         KMS
	escrowKeyID string
	env         string
	escrow      EscrowClient
	logger      *slog.Logger
	now         func() time.Time

	// restartMu serializes controller restarts, from restores and from the
	// check-in loop, and guards the fields below
	restartMu      sync.Mutex
	nextRestart    time.Time
	restartBackoff time.Duration
	// lastCreate is when this agent last created a key Secret, by the
	// monotonic clock; a restart waits settle after it
	lastCreate time.Time
	settle     time.Duration
}

// KeySyncOptions configures a KeySync.
type KeySyncOptions struct {
	Kube       kubernetes.Interface
	Namespace  string
	Deployment string
	KMS        KMS
	// EscrowKeyID is the KMS key escrowed keys are sealed under. Restores
	// open only envelopes made under this key.
	EscrowKeyID string
	// Env is this agent's env; it is part of every escrow's encryption
	// context.
	Env    string
	Escrow EscrowClient
	Logger *slog.Logger
	Now    func() time.Time
}

// NewKeySync returns a KeySync. It makes no network calls.
func NewKeySync(opts KeySyncOptions) *KeySync {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &KeySync{
		kube:        opts.Kube,
		namespace:   opts.Namespace,
		deployment:  opts.Deployment,
		kms:         opts.KMS,
		escrowKeyID: opts.EscrowKeyID,
		env:         opts.Env,
		escrow:      opts.Escrow,
		logger:      logger,
		now:         now,

		restartBackoff: restartRetry,
		settle:         time.Second,
	}
}

// escrowedKey is the plaintext of an escrow envelope: the key Secret's data.
type escrowedKey struct {
	Certificate string `json:"tls.crt"`
	PrivateKey  string `json:"tls.key"`
}

func escrowContext(env, fingerprint string) map[string]string {
	return map[string]string{
		protocol.ContextEnv:         env,
		protocol.ContextFingerprint: fingerprint,
		protocol.ContextPurpose:     protocol.PurposeKeyEscrow,
	}
}

// Escrow encrypts the named keys under the escrow KMS key and uploads them.
// Failures are logged; the control plane asks again on the next check-in.
func (k *KeySync) Escrow(ctx context.Context, fingerprints []string) {
	secrets, err := k.keySecrets(ctx, keyLabelSelector)
	if err != nil {
		k.logger.WarnContext(ctx, "failed to read key secrets for escrow",
			"event", "key.sync_failed", "env", k.env, "error", err)
		return
	}
	for _, fp := range fingerprints {
		s, ok := secrets[fp]
		if !ok {
			// reported by the controller but not a labeled key Secret
			continue
		}
		if err := k.escrowOne(ctx, fp, s); err != nil {
			k.logger.WarnContext(ctx, "failed to escrow sealing key",
				"event", "key.sync_failed", "env", k.env, "fingerprint", fp, "secret", s.Name, "error", err)
			continue
		}
		k.logger.InfoContext(ctx, "sealing key escrowed",
			"event", "key.escrow_uploaded", "env", k.env, "fingerprint", fp, "secret", s.Name)
	}
}

func (k *KeySync) escrowOne(ctx context.Context, fp string, s *corev1.Secret) error {
	// the first upload wins and the control plane cannot check the private
	// key, so a bad one would block every restore of this key
	if err := checkKeyPair(s.Data[corev1.TLSCertKey], s.Data[corev1.TLSPrivateKeyKey], fp); err != nil {
		return fmt.Errorf("refusing to escrow key secret %s: %w", s.Name, err)
	}
	plaintext, err := json.Marshal(escrowedKey{
		Certificate: string(s.Data[corev1.TLSCertKey]),
		PrivateKey:  string(s.Data[corev1.TLSPrivateKeyKey]),
	})
	if err != nil {
		return fmt.Errorf("failed to encode key secret: %w", err)
	}
	defer clear(plaintext)
	env, err := envelope.Seal(ctx, k.kms, k.escrowKeyID, plaintext, escrowContext(k.env, fp))
	if err != nil {
		return err
	}
	return k.escrow.PutEscrow(ctx, fp, protocol.EscrowUpload{
		Certificate: string(s.Data[corev1.TLSCertKey]),
		Envelope:    env,
	})
}

// keySecrets returns the key Secrets that selector selects by fingerprint.
func (k *KeySync) keySecrets(ctx context.Context, selector string) (map[string]*corev1.Secret, error) {
	list, err := k.listKeySecrets(ctx, selector)
	if err != nil {
		return nil, err
	}
	out := map[string]*corev1.Secret{}
	for i := range list {
		s := &list[i]
		fp, ok := secretFingerprint(s)
		if !ok {
			continue
		}
		if _, dup := out[fp]; !dup {
			out[fp] = s
		}
	}
	return out, nil
}

func (k *KeySync) listKeySecrets(ctx context.Context, selector string) ([]corev1.Secret, error) {
	list, err := k.kube.CoreV1().Secrets(k.namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("failed to list key secrets in %s: %w", k.namespace, err)
	}
	return list.Items, nil
}

// secretFingerprint returns the fingerprint of the key a Secret holds, from
// its certificate or else its private key.
func secretFingerprint(s *corev1.Secret) (string, bool) {
	if parsed, _, err := keys.ParseCert(s.Data[corev1.TLSCertKey]); err == nil {
		return parsed.Fingerprint, true
	}
	key, err := keyutil.ParsePrivateKeyPEM(s.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return "", false
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", false
	}
	fp, err := sscrypto.PublicKeyFingerprint(&priv.PublicKey)
	return fp, err == nil
}

// Restore runs keys.restore.v1: it restores each escrowed key the controller
// is missing, then restarts the controller so it loads them, deleting the
// pods that started before them.
func (k *KeySync) Restore(ctx context.Context, cmd protocol.Command) (any, error) {
	var p protocol.KeysRestorePayload
	if err := strictDecode(cmd.Payload, &p); err != nil {
		return nil, err
	}
	if len(p.Fingerprints) == 0 || len(p.Fingerprints) > protocol.MaxKeys {
		return nil, fmt.Errorf("invalid payload: 1 to %d fingerprints required", protocol.MaxKeys)
	}
	for _, fp := range p.Fingerprints {
		if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 128 {
			return nil, fmt.Errorf("invalid payload: %q is not a key fingerprint", fp)
		}
	}

	d, err := k.kube.AppsV1().Deployments(k.namespace).Get(ctx, k.deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get controller deployment %s/%s: %w", k.namespace, k.deployment, err)
	}
	settings := readSettings(d)
	switch settings.keyOrderPriority {
	case orderCertNotBefore:
	case orderSecretCreationTime:
		// a restored old key would become this controller's newest
		return nil, fmt.Errorf("refusing to restore keys: controller orders keys by %s", orderSecretCreationTime)
	default:
		return nil, errors.New("refusing to restore keys: cannot tell how the controller orders keys (its key order is set where the agent cannot read it)")
	}
	prefix := settings.keyPrefix

	// a key held under any label value is present: one relabeled (as
	// compromised, say) must not come back as active
	present, err := k.keySecrets(ctx, keyLabel)
	if err != nil {
		return nil, err
	}
	res := protocol.KeysRestoreResult{Restored: []string{}, AlreadyPresent: []string{}, Failed: []protocol.KeyFailure{}}
	for _, fp := range p.Fingerprints {
		if s, ok := present[fp]; ok {
			if label := s.Labels[keyLabel]; label != keyLabelActive {
				k.logger.WarnContext(ctx, "not restoring a sealing key held under another label",
					"event", "key.restore_skipped", "env", k.env, "fingerprint", fp, "secret", s.Name, "label", label)
			}
			res.AlreadyPresent = append(res.AlreadyPresent, fp)
			continue
		}
		name, err := k.restoreOne(ctx, fp, prefix)
		if err != nil {
			k.logger.ErrorContext(ctx, "failed to restore sealing key",
				"event", "key.sync_failed", "env", k.env, "fingerprint", fp, "error", err)
			res.Failed = append(res.Failed, protocol.KeyFailure{Fingerprint: fp, Error: err.Error()})
			continue
		}
		k.logger.WarnContext(ctx, "sealing key restored from escrow",
			"event", "key.restored", "env", k.env, "fingerprint", fp, "secret", name)
		present[fp] = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{keyLabel: keyLabelActive}}}
		res.Restored = append(res.Restored, fp)
	}

	// load the keys just restored, and any restored before that the
	// controller has not loaded, as after a failed restart
	restarted, err := k.restart(ctx, "", "keys restored", true)
	res.ControllerRestarted = restarted
	if err != nil {
		return res, err
	}
	if len(res.Failed) > 0 {
		return res, fmt.Errorf("failed to restore %d of %d keys", len(res.Failed), len(p.Fingerprints))
	}
	return res, nil
}

// restoreOne downloads, decrypts and checks one escrowed key, and creates its
// key Secret. It returns the Secret's name.
func (k *KeySync) restoreOne(ctx context.Context, fp, prefix string) (string, error) {
	rec, err := k.escrow.GetEscrow(ctx, fp)
	if err != nil {
		return "", err
	}
	plaintext, err := envelope.Open(ctx, k.kms, k.escrowKeyID, rec.Envelope, escrowContext(k.env, fp))
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	var ek escrowedKey
	if err := json.Unmarshal(plaintext, &ek); err != nil {
		return "", errors.New("failed to decode escrowed key")
	}
	if err := checkKeyPair([]byte(ek.Certificate), []byte(ek.PrivateKey), fp); err != nil {
		return "", fmt.Errorf("escrowed key is unusable: %w", err)
	}

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: prefix,
			Namespace:    k.namespace,
			Labels:       map[string]string{keyLabel: keyLabelActive},
			Annotations: map[string]string{
				annotationFingerprint:  fp,
				annotationRestoredFrom: escrowedRestoredFromValue,
				annotationRestoredAt:   k.now().UTC().Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(ek.Certificate),
			corev1.TLSPrivateKeyKey: []byte(ek.PrivateKey),
		},
	}
	created, err := k.kube.CoreV1().Secrets(k.namespace).Create(ctx, s, metav1.CreateOptions{})
	k.restartMu.Lock()
	k.lastCreate = time.Now()
	k.restartMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("failed to create key secret in %s: %w", k.namespace, err)
	}
	return created.Name, nil
}

// checkKeyPair checks a key Secret's data the way the controller reads it
// (readKeyPair), that the certificate is the key named fp, and that the
// private key is the certificate's: the controller serves the certificate
// and decrypts with the private key without checking they match.
func checkKeyPair(certPEM, keyPEM []byte, fp string) error {
	priv, err := readKeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	parsed, pub, err := keys.ParseCert(certPEM)
	if err != nil {
		return err
	}
	if parsed.Fingerprint != fp {
		return fmt.Errorf("certificate is %s, not the requested key", parsed.Fingerprint)
	}
	if !priv.PublicKey.Equal(pub) {
		return errors.New("private key does not match its certificate")
	}
	return nil
}

// strictDecode decodes a command payload, refusing unknown fields.
func strictDecode(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	return nil
}
