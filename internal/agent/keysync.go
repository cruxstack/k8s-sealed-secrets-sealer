package agent

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Annotations the agent sets on key Secrets it restores, and on the
// controller's pod template when it restarts the controller.
const (
	annotationFingerprint  = "sealer.cruxstack.io/fingerprint"
	annotationRestoredFrom = "sealer.cruxstack.io/restored-from"
	annotationRestoredAt   = "sealer.cruxstack.io/restored-at"
	annotationRestartedAt  = "kubectl.kubernetes.io/restartedAt"
)

// Controller flag values the agent works with.
const (
	defaultKeyPrefix          = "sealed-secrets-key"
	orderSecretCreationTime   = "SecretCreationTimestamp"
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
	secrets, err := k.keySecrets(ctx)
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

// keySecrets returns the controller's key Secrets by fingerprint.
func (k *KeySync) keySecrets(ctx context.Context) (map[string]*corev1.Secret, error) {
	list, err := k.kube.CoreV1().Secrets(k.namespace).List(ctx, metav1.ListOptions{LabelSelector: keyLabelSelector})
	if err != nil {
		return nil, fmt.Errorf("failed to list key secrets in %s: %w", k.namespace, err)
	}
	out := map[string]*corev1.Secret{}
	for i := range list.Items {
		s := &list.Items[i]
		parsed, _, err := keys.ParseCert(s.Data[corev1.TLSCertKey])
		if err != nil {
			continue
		}
		if _, dup := out[parsed.Fingerprint]; !dup {
			out[parsed.Fingerprint] = s
		}
	}
	return out, nil
}

// Restore runs keys.restore.v1: it restores each escrowed key the controller
// is missing, then restarts the controller once so it loads them.
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
	args := controllerArgs(d)
	if order, _ := flagValue(args, "key-order-priority"); order == orderSecretCreationTime {
		// a restored old key would become this controller's newest
		return nil, fmt.Errorf("refusing to restore keys: controller orders keys by %s", orderSecretCreationTime)
	}
	prefix := defaultKeyPrefix
	if v, ok := flagValue(args, "key-prefix"); ok && v != "" {
		prefix = v
	}

	present, err := k.keySecrets(ctx)
	if err != nil {
		return nil, err
	}
	res := protocol.KeysRestoreResult{Restored: []string{}, AlreadyPresent: []string{}, Failed: []protocol.KeyFailure{}}
	for _, fp := range p.Fingerprints {
		if _, ok := present[fp]; ok {
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
		present[fp] = nil
		res.Restored = append(res.Restored, fp)
	}

	if len(res.Restored) > 0 {
		if err := k.restartController(ctx); err != nil {
			return res, err
		}
		res.ControllerRestarted = true
		k.logger.WarnContext(ctx, "controller restarted to load restored keys",
			"event", "controller.restarted", "env", k.env, "deployment", k.namespace+"/"+k.deployment,
			"reason", "keys restored", "fingerprints", res.Restored)
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
		return "", err
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
	if err != nil {
		return "", fmt.Errorf("failed to create key secret in %s: %w", k.namespace, err)
	}
	return created.Name, nil
}

// checkKeyPair checks that a certificate is the key named fp and that the
// private key is its private half.
func checkKeyPair(certPEM, keyPEM []byte, fp string) error {
	parsed, pub, err := keys.ParseCert(certPEM)
	if err != nil {
		return err
	}
	if parsed.Fingerprint != fp {
		return fmt.Errorf("escrowed certificate is %s, not the requested key", parsed.Fingerprint)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("escrowed private key is not PEM")
	}
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else if k8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return errors.New("escrowed private key is not RSA")
		}
		priv = rk
	} else {
		return errors.New("escrowed private key does not parse")
	}
	if !priv.PublicKey.Equal(pub) {
		return errors.New("escrowed private key does not match its certificate")
	}
	return nil
}

// restartController rolls the controller's pods by stamping its pod
// template, as kubectl rollout restart does. The controller reads key
// Secrets only at startup.
func (k *KeySync) restartController(ctx context.Context) error {
	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
			"annotations": map[string]string{annotationRestartedAt: k.now().UTC().Format(time.RFC3339Nano)},
		}}},
	})
	if err != nil {
		return err
	}
	_, err = k.kube.AppsV1().Deployments(k.namespace).Patch(ctx, k.deployment, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("failed to restart controller %s/%s: %w", k.namespace, k.deployment, err)
	}
	return nil
}

// controllerArgs returns the command and arguments of the controller's
// containers.
func controllerArgs(d *appsv1.Deployment) []string {
	var args []string
	for _, c := range d.Spec.Template.Spec.Containers {
		args = append(append(args, c.Command...), c.Args...)
	}
	return args
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
