package agent

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/keyutil"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Cleanup runs keys.delete.v1: it removes keys an admin deleted from the
// controller, after counting again that no value in the controller's
// SealedSecrets is sealed with them. A key any value is sealed with is
// never removed, whatever the control plane says. It needs the cleanup
// capability's RBAC (delete Secrets, list SealedSecrets) and keys'.
type Cleanup struct {
	keys   *KeySync
	usage  *Usage
	certs  CertSource
	logger *slog.Logger
}

// NewCleanup returns a Cleanup that removes keys from the controller keys
// syncs, counting with usage. certs reads the key the controller seals
// with. It makes no network calls.
func NewCleanup(keys *KeySync, usage *Usage, certs CertSource, logger *slog.Logger) *Cleanup {
	if logger == nil {
		logger = slog.Default()
	}
	return &Cleanup{keys: keys, usage: usage, certs: certs, logger: logger}
}

// Delete runs keys.delete.v1. For each key it counts the values sealed with
// it now, refuses the key when there are any, and otherwise deletes every
// Secret in the controller's namespace that holds the key, under any value
// of the key label, each only as it was read. A key no Secret holds is
// absent. The controller holds its keys in memory until it restarts, so it
// is restarted when any Secret was deleted, as after a restore. The command
// succeeds when every key was removed or absent.
func (c *Cleanup) Delete(ctx context.Context, cmd protocol.Command) (any, error) {
	var p protocol.KeysDeletePayload
	if err := strictDecode(cmd.Payload, &p); err != nil {
		return nil, err
	}
	if len(p.Fingerprints) == 0 || len(p.Fingerprints) > protocol.MaxRestoreKeys {
		return nil, fmt.Errorf("invalid payload: 1 to %d fingerprints required", protocol.MaxRestoreKeys)
	}
	var fingerprints []string
	for _, fp := range p.Fingerprints {
		if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 128 {
			return nil, fmt.Errorf("invalid payload: %q is not a key fingerprint", fp)
		}
		if !slices.Contains(fingerprints, fp) {
			fingerprints = append(fingerprints, fp)
		}
	}

	res := protocol.KeysDeleteResult{Keys: []protocol.KeyDeletion{}}
	refuse := func(fp, reason string, use protocol.KeyUse) {
		c.logger.WarnContext(ctx, "refused to remove a deleted sealing key",
			"event", "key.remove_refused", "fingerprint", fp, "reason", reason, "values", use.Values, "sealed_secrets", use.SealedSecrets)
		res.Keys = append(res.Keys, protocol.KeyDeletion{
			Fingerprint: fp, Outcome: protocol.KeyRefused, Reason: reason, Values: use.Values, SealedSecrets: use.SealedSecrets,
		})
	}

	// the counts must be now's, not the last report's: values may have been
	// applied since
	usage, counted, err := c.usage.count(ctx)
	if err != nil {
		for _, fp := range fingerprints {
			refuse(fp, "could not count the values sealed with it: "+err.Error(), protocol.KeyUse{})
		}
		return res, fmt.Errorf("refusing to remove keys: failed to count the values sealed with them: %w", err)
	}
	secrets, err := c.keys.listKeySecrets(ctx, keyLabel)
	if err != nil {
		return nil, err
	}
	// the controller names a key by its private key; a Secret whose
	// certificate names another key is held under both, so neither is
	// removed on the other's word
	held := map[string][]heldSecret{}
	for _, s := range secrets {
		h := heldSecret{Secret: s, key: privateKeyFingerprint(&s), cert: certFingerprint(&s)}
		for _, fp := range []string{h.key, h.cert} {
			if fp != "" && !slices.ContainsFunc(held[fp], func(o heldSecret) bool { return o.UID == s.UID && o.Name == s.Name }) {
				held[fp] = append(held[fp], h)
			}
		}
	}

	restart := false
	for _, fp := range fingerprints {
		if use := usage.Keys[fp]; use.Values > 0 {
			refuse(fp, fmt.Sprintf("%s in %s %s it", count(use.Values, "value"), count(use.SealedSecrets, "SealedSecret"),
				plural(use.Values, "uses", "use")), use)
			continue
		}
		found := held[fp]
		if len(found) == 0 {
			if c.servesKey(ctx, fp) {
				// no Secret holds it, so only pods that started before it was
				// deleted can: they still seal with it
				restart = true
			}
			res.Keys = append(res.Keys, protocol.KeyDeletion{Fingerprint: fp, Outcome: protocol.KeyAbsent})
			continue
		}
		if reason := unsure(found, fp, counted); reason != "" {
			refuse(fp, reason, protocol.KeyUse{})
			continue
		}
		names, err := c.deleteSecrets(ctx, found)
		if len(names) > 0 {
			restart = true
		}
		if err != nil {
			refuse(fp, err.Error(), protocol.KeyUse{})
			continue
		}
		c.logger.WarnContext(ctx, "deleted sealing key removed from the controller",
			"event", "key.removed", "fingerprint", fp, "secrets", names)
		res.Keys = append(res.Keys, protocol.KeyDeletion{Fingerprint: fp, Outcome: protocol.KeyRemoved})
	}

	var errs []error
	if restart {
		res.ControllerRestarted, err = c.keys.unloadDeleted(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}
	refused := 0
	for _, k := range res.Keys {
		if k.Outcome == protocol.KeyRefused {
			refused++
		}
	}
	if refused > 0 {
		errs = append(errs, fmt.Errorf("refused to remove %d of %d keys", refused, len(fingerprints)))
	}
	return res, errors.Join(errs...)
}

// heldSecret is a key Secret, with the fingerprints of its private key and
// of its certificate, each "" when it does not parse.
type heldSecret struct {
	corev1.Secret
	key, cert string
}

// unsure says why the values sealed with key fp, which secrets hold, cannot
// be told: a Secret that does not load, whose values the count could not
// match, or whose certificate is another key than its private key, which
// the controller goes by. It returns "" when they can.
func unsure(secrets []heldSecret, fp string, counted map[string]bool) string {
	for _, s := range secrets {
		switch {
		case s.key == "":
			return fmt.Sprintf("key Secret %s does not load, so the values sealed with it cannot be counted", s.Name)
		case s.cert != "" && s.cert != s.key:
			return fmt.Sprintf("key Secret %s holds the certificate of one key and the private key of another", s.Name)
		}
	}
	if !counted[fp] {
		return "its key Secret does not load, so the values sealed with it cannot be counted"
	}
	return ""
}

// privateKeyFingerprint names the key a Secret holds as the controller does,
// by its private key; "" when that does not parse as RSA.
func privateKeyFingerprint(s *corev1.Secret) string {
	key, err := keyutil.ParsePrivateKeyPEM(s.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return ""
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return ""
	}
	fp, err := sscrypto.PublicKeyFingerprint(&priv.PublicKey)
	if err != nil {
		return ""
	}
	return fp
}

// certFingerprint names the key of a Secret's certificate; "" when it does
// not parse.
func certFingerprint(s *corev1.Secret) string {
	parsed, _, err := keys.ParseCert(s.Data[corev1.TLSCertKey])
	if err != nil {
		return ""
	}
	return parsed.Fingerprint
}

// deleteSecrets deletes key Secrets, each only while it is as it was read
// (its UID and resourceVersion), and returns the names of those it deleted.
// One already gone counts as deleted.
func (c *Cleanup) deleteSecrets(ctx context.Context, secrets []heldSecret) ([]string, error) {
	var names []string
	for _, s := range secrets {
		uid, version := s.UID, s.ResourceVersion
		err := c.keys.kube.CoreV1().Secrets(c.keys.namespace).Delete(ctx, s.Name, metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version},
		})
		switch {
		case err == nil || apierrors.IsNotFound(err):
			names = append(names, s.Name)
		case apierrors.IsConflict(err):
			return names, fmt.Errorf("key secret %s changed while it was being deleted", s.Name)
		default:
			return names, fmt.Errorf("failed to delete key secret %s: %w", s.Name, err)
		}
	}
	return names, nil
}

// servesKey reports whether the controller seals with fp. Not knowing
// counts as no: the restart it would call for is only to drop a key no
// Secret holds any more.
func (c *Cleanup) servesKey(ctx context.Context, fp string) bool {
	if c.certs == nil {
		return false
	}
	pem, err := c.certs.ActiveCert(ctx)
	if err != nil {
		return false
	}
	k, err := toProtocolKey(pem)
	return err == nil && k.Fingerprint == fp
}

// count is n and a noun, plural unless n is 1.
func count(n int, noun string) string {
	return fmt.Sprintf("%d %s", n, plural(n, noun, noun+"s"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
