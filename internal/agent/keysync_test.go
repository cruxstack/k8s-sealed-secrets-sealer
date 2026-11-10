package agent

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

// memEscrow is an in-memory control plane escrow API.
type memEscrow struct {
	mu      sync.Mutex
	records map[string]protocol.EscrowRecord
}

func (m *memEscrow) PutEscrow(_ context.Context, fp string, in protocol.EscrowUpload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.records[fp]; !ok {
		m.records[fp] = protocol.EscrowRecord{Fingerprint: fp, Certificate: in.Certificate, Envelope: in.Envelope}
	}
	return nil
}

func (m *memEscrow) GetEscrow(_ context.Context, fp string) (protocol.EscrowRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[fp]
	if !ok {
		return protocol.EscrowRecord{}, fmt.Errorf("control plane /agent/v1/escrow: %w", errNotFound)
	}
	return rec, nil
}

// pair is a sealing key: certificate and private key.
type pair struct {
	fp   string
	cert []byte
	key  []byte
}

func newPair(t *testing.T, notBefore time.Time) pair {
	t.Helper()
	priv := testcerts.RSA(t, 2048)
	return pairFor(t, priv, testcerts.SelfSigned(t, priv, notBefore))
}

func pairFor(t *testing.T, priv *rsa.PrivateKey, cert []byte) pair {
	t.Helper()
	k, _, err := keys.ParseCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	return pair{
		fp:   k.Fingerprint,
		cert: cert,
		key:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}),
	}
}

func (p pair) secret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{keyLabel: keyLabelActive}},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": p.cert, "tls.key": p.key},
	}
}

// cluster is one simulated cluster: a fake API server with a controller.
type cluster struct {
	kube *fake.Clientset
	sync *KeySync
}

func newCluster(t *testing.T, kms *envelope.FakeKMS, escrow *memEscrow, env string, objs ...runtime.Object) *cluster {
	t.Helper()
	kube := fake.NewClientset(objs...)
	// the fake API server does not generate names
	var n atomic.Int32
	kube.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		s := action.(k8stesting.CreateAction).GetObject().(*corev1.Secret)
		if s.Name == "" && s.GenerateName != "" {
			s.Name = fmt.Sprintf("%s%05d", s.GenerateName, n.Add(1))
		}
		return false, nil, nil
	})
	return &cluster{kube: kube, sync: NewKeySync(KeySyncOptions{
		Kube:        kube,
		Namespace:   ns,
		Deployment:  "sealed-secrets-controller",
		KMS:         kms,
		EscrowKeyID: "escrow",
		Env:         env,
		Escrow:      escrow,
	})}
}

func (c *cluster) keySecrets(t *testing.T) []corev1.Secret {
	t.Helper()
	list, err := c.kube.CoreV1().Secrets(ns).List(context.Background(), metav1.ListOptions{LabelSelector: keyLabelSelector})
	if err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func (c *cluster) restartedAt(t *testing.T) string {
	t.Helper()
	d, err := c.kube.AppsV1().Deployments(ns).Get(context.Background(), "sealed-secrets-controller", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d.Spec.Template.Annotations[annotationRestartedAt]
}

func restorePayload(fps ...string) json.RawMessage {
	b, _ := json.Marshal(protocol.KeysRestorePayload{Fingerprints: fps})
	return b
}

func TestKeySync_EscrowThenRestoreInAnotherCluster(t *testing.T) {
	kms := envelope.NewFakeKMS("escrow")
	escrow := &memEscrow{records: map[string]protocol.EscrowRecord{}}
	k1 := newPair(t, time.Now().Add(-48*time.Hour))
	k2 := newPair(t, time.Now().Add(-time.Hour))

	src := newCluster(t, kms, escrow, "dev", k1.secret("sealed-secrets-keyaaaaa"), k2.secret("sealed-secrets-keybbbbb"), controllerDeployment())
	src.sync.Escrow(context.Background(), []string{k1.fp, k2.fp, "SHA256:not-here"})
	if len(escrow.records) != 2 {
		t.Fatalf("escrowed %d keys, want 2", len(escrow.records))
	}
	rec := escrow.records[k1.fp]
	if !maps.Equal(rec.Envelope.Context, escrowContext("dev", k1.fp)) || strings.Contains(rec.Envelope.Ciphertext, "PRIVATE") {
		t.Fatalf("escrow record = %+v", rec)
	}

	// dst holds k2 only, and names its keys with another prefix
	dst := newCluster(t, kms, escrow, "dev", k2.secret("custom-k2"), controllerDeployment("--key-prefix", "custom-"))
	out, err := dst.sync.Restore(context.Background(), protocol.Command{Payload: restorePayload(k1.fp, k2.fp)})
	if err != nil {
		t.Fatal(err)
	}
	res := out.(protocol.KeysRestoreResult)
	if len(res.Restored) != 1 || res.Restored[0] != k1.fp || len(res.AlreadyPresent) != 1 || !res.ControllerRestarted {
		t.Fatalf("result = %+v", res)
	}
	secrets := dst.keySecrets(t)
	if len(secrets) != 2 {
		t.Fatalf("dst has %d key secrets, want 2", len(secrets))
	}
	var restored *corev1.Secret
	for i := range secrets {
		if secrets[i].Annotations[annotationRestoredFrom] == "escrow" {
			restored = &secrets[i]
		}
	}
	if restored == nil || !strings.HasPrefix(restored.Name, "custom-") || restored.Type != corev1.SecretTypeTLS ||
		restored.Annotations[annotationFingerprint] != k1.fp || string(restored.Data["tls.key"]) != string(k1.key) {
		t.Fatalf("restored secret = %+v", restored)
	}
	if dst.restartedAt(t) == "" {
		t.Fatal("controller was not restarted")
	}

	// running it again changes nothing and does not restart
	again := newCluster(t, kms, escrow, "dev", k1.secret("a"), k2.secret("b"), controllerDeployment())
	out, err = again.sync.Restore(context.Background(), protocol.Command{Payload: restorePayload(k1.fp)})
	if err != nil {
		t.Fatal(err)
	}
	if res := out.(protocol.KeysRestoreResult); len(res.Restored) != 0 || res.ControllerRestarted || again.restartedAt(t) != "" {
		t.Fatalf("second restore = %+v", res)
	}
}

func TestKeySync_RestoreRefuses(t *testing.T) {
	ctx := context.Background()
	kms := envelope.NewFakeKMS("escrow", "other")
	k1 := newPair(t, time.Now().Add(-time.Hour))
	k2 := newPair(t, time.Now().Add(-time.Hour))

	seal := func(keyID, env, fp string, ek escrowedKey) protocol.Envelope {
		t.Helper()
		b, _ := json.Marshal(ek)
		e, err := envelope.Seal(ctx, kms, keyID, b, escrowContext(env, fp))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	good := escrowedKey{Certificate: string(k1.cert), PrivateKey: string(k1.key)}
	cases := map[string]struct {
		env  protocol.Envelope
		args []string
		want string
	}{
		// another cluster's escrow, or another env's, does not open here
		"other env":     {seal("escrow", "prod", k1.fp, good), nil, "sealed for another context"},
		"other kms key": {seal("other", "dev", k1.fp, good), nil, "failed to unwrap"},
		// a record stored under k1 that holds k2
		"swapped key": {seal("escrow", "dev", k1.fp, escrowedKey{Certificate: string(k2.cert), PrivateKey: string(k2.key)}), nil, "not the requested key"},
		// k1's certificate with k2's private key
		"mismatched pair":   {seal("escrow", "dev", k1.fp, escrowedKey{Certificate: string(k1.cert), PrivateKey: string(k2.key)}), nil, "does not match its certificate"},
		"garbage key":       {seal("escrow", "dev", k1.fp, escrowedKey{Certificate: string(k1.cert), PrivateKey: "nope"}), nil, "not PEM"},
		"newest-first keys": {seal("escrow", "dev", k1.fp, good), []string{"--key-order-priority=SecretCreationTimestamp"}, "refusing to restore"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			escrow := &memEscrow{records: map[string]protocol.EscrowRecord{k1.fp: {Fingerprint: k1.fp, Envelope: tc.env}}}
			c := newCluster(t, kms, escrow, "dev", controllerDeployment(tc.args...))
			out, err := c.sync.Restore(ctx, protocol.Command{Payload: restorePayload(k1.fp)})
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if res, ok := out.(protocol.KeysRestoreResult); ok && len(res.Failed) == 1 {
				msg += " " + res.Failed[0].Error
			}
			if err == nil || !strings.Contains(msg, tc.want) {
				t.Fatalf("error = %q, want it to contain %q", msg, tc.want)
			}
			if n := len(c.keySecrets(t)); n != 0 || c.restartedAt(t) != "" {
				t.Fatalf("refused restore created %d secrets or restarted the controller", n)
			}
		})
	}

	// payload validation
	c := newCluster(t, kms, &memEscrow{records: map[string]protocol.EscrowRecord{}}, "dev", controllerDeployment())
	for _, raw := range []string{`{}`, `{"fingerprints":["md5:x"]}`, `{"fingerprints":["SHA256:x"],"extra":true}`, `not json`} {
		if _, err := c.sync.Restore(ctx, protocol.Command{Payload: json.RawMessage(raw)}); err == nil || !strings.Contains(err.Error(), "invalid payload") {
			t.Errorf("payload %s: err = %v", raw, err)
		}
	}
	// a key with no escrow record fails, and is reported
	out, err := c.sync.Restore(ctx, protocol.Command{Payload: restorePayload("SHA256:missing")})
	if res := out.(protocol.KeysRestoreResult); err == nil || len(res.Failed) != 1 || !strings.Contains(res.Failed[0].Error, "not found") {
		t.Fatalf("missing escrow: err = %v, result = %+v", err, res)
	}
}

// A restored old key would become the controller's newest unless it orders
// keys by NotBefore, so restore refuses unless it can tell that it does.
func TestKeySync_RestoreNeedsKnownKeyOrder(t *testing.T) {
	ctx := context.Background()
	kms := envelope.NewFakeKMS("escrow")
	cases := map[string][]corev1.EnvVar{
		"newest-first by variable": {{Name: "SEALED_SECRETS_KEY_ORDER_PRIORITY", Value: "SecretCreationTimestamp"}},
		"order from a ConfigMap":   {{Name: "SEALED_SECRETS_KEY_ORDER_PRIORITY", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "order"}}}},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			d := controllerDeployment()
			d.Spec.Template.Spec.Containers[0].Env = env
			c := newCluster(t, kms, &memEscrow{records: map[string]protocol.EscrowRecord{}}, "dev", d)
			if _, err := c.sync.Restore(ctx, protocol.Command{Payload: restorePayload("SHA256:k")}); err == nil || !strings.Contains(err.Error(), "refusing to restore") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
