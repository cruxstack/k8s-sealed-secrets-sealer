package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

// resealKey is a sealing key with its private half, for tests that seal
// with HybridEncrypt and open with HybridDecrypt, as kubeseal and the
// controller do.
type resealKey struct {
	pair
	priv *rsa.PrivateKey
}

func newResealKey(t *testing.T, bits int, notBefore time.Time) resealKey {
	t.Helper()
	priv := testcerts.RSA(t, bits)
	return resealKey{pair: pairFor(t, priv, testcerts.SelfSigned(t, priv, notBefore)), priv: priv}
}

// sealWith seals plaintext with k as kubeseal does, for a SealedSecret
// namespace/name of the given scope.
func (k resealKey) sealWith(t *testing.T, plaintext, namespace, name string, scope ssv1alpha1.SealingScope) string {
	t.Helper()
	ct, err := sscrypto.HybridEncrypt(rand.Reader, &k.priv.PublicKey, []byte(plaintext), ssv1alpha1.EncryptionLabel(namespace, name, scope))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// open decrypts a value as the controller does, with only the given keys,
// and reports whether any opened it.
func open(t *testing.T, b64 string, label []byte, with ...resealKey) (string, bool) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	privs := map[string]*rsa.PrivateKey{}
	for _, k := range with {
		privs[k.fp] = k.priv
	}
	out, err := sscrypto.HybridDecrypt(rand.Reader, privs, raw, label)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// resealCluster is a cluster whose controller holds the given keys, as key
// Secrets and in its key set, and seals with the first, the env key.
func resealCluster(t *testing.T, held ...resealKey) *Resealer {
	t.Helper()
	var objs []runtime.Object
	var set []protocol.Key
	for i, k := range held {
		objs = append(objs, k.secret("key-"+string(rune('a'+i))))
		set = append(set, protocol.Key{Fingerprint: k.fp, Certificate: string(k.cert)})
	}
	active := ""
	if len(held) > 0 {
		active = held[0].fp
	}
	return NewResealer(ResealerOptions{
		Keys:      &fakeInventory{report: Report{Controller: protocol.Controller{ActiveFingerprint: active}, Keys: set, Complete: true}},
		Kube:      fake.NewClientset(objs...),
		Namespace: ns,
		Env:       "dev",
	})
}

func resealCommand(t *testing.T, envKey string, items ...protocol.ResealItem) protocol.Command {
	t.Helper()
	raw, err := json.Marshal(protocol.ResealPayload{EnvKey: envKey, Items: items})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{ID: "01J00000000000000000000RSL", Type: protocol.CommandReseal, ExpiresAt: time.Now().Add(time.Minute), Payload: raw}
}

func runReseal(t *testing.T, r *Resealer, cmd protocol.Command) protocol.ResealResult {
	t.Helper()
	out, err := r.Reseal(context.Background(), cmd)
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	return out.(protocol.ResealResult)
}

func TestReseal_RewrapsAValueFromAnOldKeyOntoTheEnvKey(t *testing.T) {
	old := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	env := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	r := resealCluster(t, env, old)
	label := ssv1alpha1.EncryptionLabel("apps", "billing", ssv1alpha1.StrictScope)
	before := old.sealWith(t, "s3cret", "apps", "billing", ssv1alpha1.StrictScope)

	res := runReseal(t, r, resealCommand(t, env.fp,
		protocol.ResealItem{ID: "0/api-token", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: before}))
	if len(res.Items) != 1 {
		t.Fatalf("items = %+v", res.Items)
	}
	got := res.Items[0]
	if got.ID != "0/api-token" || got.Status != protocol.ResealResealed || got.From != old.fp || got.Error != "" {
		t.Fatalf("item = %+v", got)
	}
	// the controller opens it with the env key, to the same value, under
	// the same label
	if v, ok := open(t, got.Ciphertext, label, env); !ok || v != "s3cret" {
		t.Fatalf("the env key opens it to %q, %v", v, ok)
	}
	if _, ok := open(t, got.Ciphertext, label, old); ok {
		t.Fatal("the old key still opens the resealed value")
	}
	// only the RSA part changed: the AES-GCM part is the old one, byte for
	// byte, so the value was never re-encrypted
	if !bytes.Equal(sealedPart(t, got.Ciphertext), sealedPart(t, before)) {
		t.Fatal("the AES-GCM part changed")
	}
	if strings.Contains(got.Ciphertext, "s3cret") {
		t.Fatal("the result holds the value")
	}
}

// sealedPart is a value's AES-GCM part, after its RSA part.
func sealedPart(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint16(raw))
	return raw[2+n:]
}

func TestReseal_KeepsTheLabel(t *testing.T) {
	old := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	// an env key larger than the old one: the RSA part grows
	env := newResealKey(t, 3072, time.Now().Add(-time.Hour))
	r := resealCluster(t, env, old)
	strict := old.sealWith(t, "one", "apps", "billing", ssv1alpha1.StrictScope)
	wide := old.sealWith(t, "two", "apps", "billing", ssv1alpha1.NamespaceWideScope)

	res := runReseal(t, r, resealCommand(t, env.fp,
		protocol.ResealItem{ID: "strict", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: strict},
		protocol.ResealItem{ID: "wide", Namespace: "apps", Name: "billing", Scope: protocol.ScopeNamespaceWide, Ciphertext: wide},
	))
	labels := map[string][]byte{
		"strict":         ssv1alpha1.EncryptionLabel("apps", "billing", ssv1alpha1.StrictScope),
		"other-name":     ssv1alpha1.EncryptionLabel("apps", "other", ssv1alpha1.StrictScope),
		"other-ns":       ssv1alpha1.EncryptionLabel("prod", "billing", ssv1alpha1.StrictScope),
		"namespace-wide": ssv1alpha1.EncryptionLabel("apps", "billing", ssv1alpha1.NamespaceWideScope),
		"other-ns-wide":  ssv1alpha1.EncryptionLabel("prod", "billing", ssv1alpha1.NamespaceWideScope),
		"cluster-wide":   ssv1alpha1.EncryptionLabel("apps", "billing", ssv1alpha1.ClusterWideScope),
	}
	for _, tc := range []struct {
		item  protocol.ResealedItem
		value string
		opens string
	}{
		{res.Items[0], "one", "strict"},
		{res.Items[1], "two", "namespace-wide"},
	} {
		if tc.item.Status != protocol.ResealResealed {
			t.Fatalf("item = %+v", tc.item)
		}
		// the output opens under its own label and no other
		for name, label := range labels {
			v, ok := open(t, tc.item.Ciphertext, label, env, old)
			if name == tc.opens && (!ok || v != tc.value) {
				t.Errorf("%s: does not open under its own label", tc.item.ID)
			}
			if name != tc.opens && ok {
				t.Errorf("%s: opens under the %s label", tc.item.ID, name)
			}
		}
	}
}

func TestReseal_RefusesToChangeALabel(t *testing.T) {
	old := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	env := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	r := resealCluster(t, env, old)
	strict := old.sealWith(t, "v", "apps", "billing", ssv1alpha1.StrictScope)
	clusterWide := old.sealWith(t, "v", "apps", "billing", ssv1alpha1.ClusterWideScope)

	// a control plane that names another namespace, name or a wider scope
	// for a ciphertext gets nothing: the value opens under its own label
	// only, and the agent tries no other
	res := runReseal(t, r, resealCommand(t, env.fp,
		protocol.ResealItem{ID: "other-ns", Namespace: "prod", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: strict},
		protocol.ResealItem{ID: "other-name", Namespace: "apps", Name: "payroll", Scope: protocol.ScopeStrict, Ciphertext: strict},
		protocol.ResealItem{ID: "wider", Namespace: "apps", Name: "billing", Scope: protocol.ScopeNamespaceWide, Ciphertext: strict},
		protocol.ResealItem{ID: "cluster-wide", Namespace: "apps", Name: "billing", Scope: protocol.ScopeClusterWide, Ciphertext: strict},
		// a value that is cluster-wide is refused even under its own label
		protocol.ResealItem{ID: "is-cluster-wide", Namespace: "apps", Name: "billing", Scope: protocol.ScopeClusterWide, Ciphertext: clusterWide},
	))
	for _, it := range res.Items {
		if it.Status != protocol.ResealFailed || it.Ciphertext != "" || it.Error == "" {
			t.Errorf("item = %+v, want failed without a ciphertext", it)
		}
	}
	if !strings.Contains(res.Items[4].Error, "cluster-wide") {
		t.Errorf("cluster-wide error = %q", res.Items[4].Error)
	}
}

func TestReseal_LeavesValuesOnTheEnvKeyAndFailsTheRest(t *testing.T) {
	old := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	env := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	stranger := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	r := resealCluster(t, env, old)
	current := env.sealWith(t, "v", "apps", "billing", ssv1alpha1.StrictScope)

	res := runReseal(t, r, resealCommand(t, env.fp,
		protocol.ResealItem{ID: "current", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: current},
		protocol.ResealItem{ID: "stranger", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict,
			Ciphertext: stranger.sealWith(t, "v", "apps", "billing", ssv1alpha1.StrictScope)},
		protocol.ResealItem{ID: "not-base64", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: "not base64!"},
		protocol.ResealItem{ID: "placeholder", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict,
			Ciphertext: "AgBplaceholderDevCiphertext00000000000000000000000000000000000=="},
		protocol.ResealItem{ID: "empty", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict},
	))
	want := map[string]string{
		"current":     protocol.ResealCurrent,
		"stranger":    protocol.ResealFailed,
		"not-base64":  protocol.ResealFailed,
		"placeholder": protocol.ResealFailed,
		"empty":       protocol.ResealFailed,
	}
	for i, it := range res.Items {
		if it.Status != want[it.ID] || it.Ciphertext != "" || it.From != "" {
			t.Errorf("item %d = %+v, want %s", i, it, want[it.ID])
		}
	}
}

func TestReseal_RefusesWithoutTheEnvKey(t *testing.T) {
	old := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	env := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	item := protocol.ResealItem{ID: "a", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict,
		Ciphertext: old.sealWith(t, "v", "apps", "billing", ssv1alpha1.StrictScope)}

	sealsWith := func(fp string, keys ...protocol.Key) *fakeInventory {
		return &fakeInventory{report: Report{Controller: protocol.Controller{ActiveFingerprint: fp}, Keys: keys}}
	}
	// the controller's key set lacks it
	r := resealCluster(t, old)
	r.keys = sealsWith(env.fp, protocol.Key{Fingerprint: old.fp, Certificate: string(old.cert)})
	if _, err := r.Reseal(context.Background(), resealCommand(t, env.fp, item)); err == nil || !strings.Contains(err.Error(), "not in this cluster's key set") {
		t.Fatalf("err = %v", err)
	}
	// its key set names it, but no key Secret holds its private key
	r = resealCluster(t, old)
	r.keys = sealsWith(env.fp, protocol.Key{Fingerprint: env.fp, Certificate: string(env.cert)})
	if _, err := r.Reseal(context.Background(), resealCommand(t, env.fp, item)); err == nil || !strings.Contains(err.Error(), "key Secrets") {
		t.Fatalf("err = %v", err)
	}
	// a certificate under another key's fingerprint
	r = resealCluster(t, env, old)
	r.keys = sealsWith(env.fp, protocol.Key{Fingerprint: env.fp, Certificate: string(old.cert)})
	if _, err := r.Reseal(context.Background(), resealCommand(t, env.fp, item)); err == nil {
		t.Fatal("resealed to a key whose certificate is another key's")
	}
	// the controller cannot be read for its active key
	r = resealCluster(t, env, old)
	r.keys = sealsWith("", protocol.Key{Fingerprint: env.fp, Certificate: string(env.cert)})
	if _, err := r.Reseal(context.Background(), resealCommand(t, env.fp, item)); err == nil || !strings.Contains(err.Error(), "cannot tell") {
		t.Fatalf("err = %v", err)
	}
}

// A control plane that names an older key the cluster still holds, one it
// revoked because it may be exposed, say, gets nothing: values move only
// onto the key the controller seals with, never back.
func TestReseal_NeverOntoAnOlderKey(t *testing.T) {
	older := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	newest := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	// the controller holds both and seals with the newest
	r := resealCluster(t, newest, older)
	onNewest := newest.sealWith(t, "rotated-after-incident", "apps", "billing", ssv1alpha1.StrictScope)
	_, err := r.Reseal(context.Background(), resealCommand(t, older.fp,
		protocol.ResealItem{ID: "0/0/k", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: onNewest}))
	if err == nil || !strings.Contains(err.Error(), "seals with "+newest.fp) {
		t.Fatalf("err = %v", err)
	}
}

// Values that are not sealed values fail alone, whatever their length field
// says.
func TestReseal_OddValues(t *testing.T) {
	env := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	r := resealCluster(t, env)
	for name, ct := range map[string]string{
		"empty":       "",
		"short":       "AAA=",
		"length only": "AAE=",
		"zero length": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"not base64":  "!!!",
	} {
		res := runReseal(t, r, resealCommand(t, env.fp,
			protocol.ResealItem{ID: "0/0/k", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: ct}))
		if res.Items[0].Status != protocol.ResealFailed {
			t.Errorf("%s: %+v", name, res.Items[0])
		}
	}
}

func TestReseal_RefusesInvalidPayloads(t *testing.T) {
	env := newResealKey(t, 2048, time.Now().Add(-time.Hour))
	r := resealCluster(t, env)
	ok := protocol.ResealItem{ID: "a", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict, Ciphertext: "AAAA"}
	many := make([]protocol.ResealItem, protocol.MaxResealItems+1)
	for i := range many {
		many[i] = ok
		many[i].ID = fmt.Sprintf("item-%d", i)
	}
	for name, cmd := range map[string]protocol.Command{
		"unknown field": {ID: "c", Type: protocol.CommandReseal, Payload: json.RawMessage(`{"env_key":"` + env.fp + `","items":[],"extra":1}`)},
		"not a key":     resealCommand(t, "abc", ok),
		"no items":      resealCommand(t, env.fp),
		"too many":      resealCommand(t, env.fp, many...),
		"twice":         resealCommand(t, env.fp, ok, ok),
		"no id":         resealCommand(t, env.fp, protocol.ResealItem{Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict}),
		"namespace":     resealCommand(t, env.fp, protocol.ResealItem{ID: "a", Namespace: "Apps!", Name: "billing", Scope: protocol.ScopeStrict}),
		"name":          resealCommand(t, env.fp, protocol.ResealItem{ID: "a", Namespace: "apps", Name: "", Scope: protocol.ScopeStrict}),
		"scope":         resealCommand(t, env.fp, protocol.ResealItem{ID: "a", Namespace: "apps", Name: "billing", Scope: "wide"}),
		"too large": resealCommand(t, env.fp, protocol.ResealItem{ID: "a", Namespace: "apps", Name: "billing", Scope: protocol.ScopeStrict,
			Ciphertext: strings.Repeat("A", protocol.ResealBudgetBytes)}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Reseal(context.Background(), cmd); err == nil || !strings.Contains(err.Error(), "invalid payload") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestReseal_SkipsKeySecretsThatDoNotLoad(t *testing.T) {
	// a key Secret that does not load is skipped, and an env key larger
	// than the key a value came from takes it
	small := newResealKey(t, 2048, time.Now().Add(-90*24*time.Hour))
	env := newResealKey(t, 3072, time.Now().Add(-time.Hour))
	broken := small.secret("broken")
	broken.Data["tls.key"] = []byte("not a key")
	r := NewResealer(ResealerOptions{
		Keys: &fakeInventory{report: Report{Controller: protocol.Controller{ActiveFingerprint: env.fp},
			Keys: []protocol.Key{{Fingerprint: env.fp, Certificate: string(env.cert)}}}},
		Kube:      fake.NewClientset(env.secret("env"), small.secret("small"), broken),
		Namespace: ns,
	})
	res := runReseal(t, r, resealCommand(t, env.fp, protocol.ResealItem{ID: "a", Namespace: "apps", Name: "billing",
		Scope: protocol.ScopeStrict, Ciphertext: small.sealWith(t, "v", "apps", "billing", ssv1alpha1.StrictScope)}))
	if it := res.Items[0]; it.Status != protocol.ResealResealed || it.From != small.fp {
		t.Fatalf("item = %+v", it)
	}
}
