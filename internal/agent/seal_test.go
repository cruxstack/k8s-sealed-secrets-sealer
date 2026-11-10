package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

const sealCommandID = "01J00000000000000000000SEA"

type sealFixture struct {
	sealer *Sealer
	kms    *envelope.FakeKMS
	fp     string
	priv   *rsa.PrivateKey
}

func newSealFixture(t *testing.T) sealFixture {
	t.Helper()
	priv := testcerts.RSA(t, 2048)
	certPEM := testcerts.SelfSigned(t, priv, time.Now().Add(-time.Hour))
	k, _, err := keys.ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// the controller also holds an unrelated older key
	other := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now().Add(-48*time.Hour))
	otherKey, _, _ := keys.ParseCert(other)
	kms := envelope.NewFakeKMS("transit")
	return sealFixture{
		sealer: NewSealer(SealerOptions{
			Keys: &fakeInventory{report: Report{Keys: []protocol.Key{
				{Fingerprint: otherKey.Fingerprint, Certificate: string(other)},
				{Fingerprint: k.Fingerprint, Certificate: string(certPEM)},
			}}},
			KMS:          kms,
			TransitKeyID: "transit",
			Env:          "dev",
			AgentID:      func() string { return "use1-blue" },
		}),
		kms:  kms,
		fp:   k.Fingerprint,
		priv: priv,
	}
}

// command builds a seal.v1 command whose value was encrypted for encCtx.
func (f sealFixture) command(t *testing.T, value string, encCtx map[string]string, edit func(*protocol.SealPayload)) protocol.Command {
	t.Helper()
	env, err := envelope.Seal(context.Background(), f.kms, "transit", []byte(value), encCtx)
	if err != nil {
		t.Fatal(err)
	}
	p := protocol.SealPayload{
		Key:         "api-token",
		Fingerprint: f.fp,
		Targets: []protocol.SealTarget{
			{Namespace: "dev-use1-blue-apps", Name: "billing", Scope: protocol.ScopeStrict},
			{Namespace: "dev-use2-blue-apps", Name: "billing", Scope: protocol.ScopeNamespaceWide},
		},
		Value: &env,
	}
	if edit != nil {
		edit(&p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{ID: sealCommandID, Type: protocol.CommandSeal, Payload: raw}
}

func TestSealer_SealsForEachTargetsLabel(t *testing.T) {
	f := newSealFixture(t)
	cmd := f.command(t, "s3cr3t-value", protocol.SealContext("dev", sealCommandID, "use1-blue"), nil)
	out, err := f.sealer.Seal(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	res := out.(protocol.SealResult)
	if res.Fingerprint != f.fp || len(res.Targets) != 2 {
		t.Fatalf("result = %+v", res)
	}
	privs := map[string]*rsa.PrivateKey{"": f.priv}
	labels := [][]byte{
		ssv1alpha1.EncryptionLabel("dev-use1-blue-apps", "billing", ssv1alpha1.StrictScope),
		ssv1alpha1.EncryptionLabel("dev-use2-blue-apps", "billing", ssv1alpha1.NamespaceWideScope),
	}
	for i, target := range res.Targets {
		ct, err := base64.StdEncoding.DecodeString(target.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		got, err := sscrypto.HybridDecrypt(rand.Reader, privs, ct, labels[i])
		if err != nil || string(got) != "s3cr3t-value" {
			t.Fatalf("target %d decrypts to %q, %v", i, got, err)
		}
		// strict ciphertext is bound to its name too
		if _, err := sscrypto.HybridDecrypt(rand.Reader, privs, ct, []byte("dev-use1-blue-apps/other")); err == nil {
			t.Fatalf("target %d decrypts under another label", i)
		}
	}
	if strings.Contains(string(mustJSON(t, res)), "s3cr3t") {
		t.Fatal("the result contains the value")
	}
}

func TestSealer_Refuses(t *testing.T) {
	f := newSealFixture(t)
	good := protocol.SealContext("dev", sealCommandID, "use1-blue")
	cases := map[string]struct {
		encCtx map[string]string
		edit   func(*protocol.SealPayload)
		want   string
	}{
		"cluster-wide scope": {good, func(p *protocol.SealPayload) { p.Targets[0].Scope = "cluster-wide" }, "not strict or namespace-wide"},
		"unknown scope":      {good, func(p *protocol.SealPayload) { p.Targets[0].Scope = "" }, "not strict or namespace-wide"},
		"bad namespace":      {good, func(p *protocol.SealPayload) { p.Targets[0].Namespace = "Not_A_Namespace" }, "not a namespace"},
		"bad name":           {good, func(p *protocol.SealPayload) { p.Targets[1].Name = "" }, "not a Secret name"},
		"bad key":            {good, func(p *protocol.SealPayload) { p.Key = "a/b" }, "not a valid Secret key"},
		"no targets":         {good, func(p *protocol.SealPayload) { p.Targets = nil }, "targets required"},
		"no value":           {good, func(p *protocol.SealPayload) { p.Value = nil }, "no value"},
		"key not held":       {good, func(p *protocol.SealPayload) { p.Fingerprint = "SHA256:not-in-this-cluster" }, "not in this cluster's key set"},
		"another agent's":    {protocol.SealContext("dev", sealCommandID, "use2-blue"), nil, "failed to decrypt"},
		"another command's":  {protocol.SealContext("dev", "01J00000000000000000000OTH", "use1-blue"), nil, "failed to decrypt"},
		"another env's":      {protocol.SealContext("prod", sealCommandID, "use1-blue"), nil, "failed to decrypt"},
		"an escrow envelope": {map[string]string{"env": "dev", "fingerprint": "x", "purpose": "key-escrow"}, nil, "failed to decrypt"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.sealer.Seal(context.Background(), f.command(t, "v", tc.encCtx, tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// an envelope relabeled with this command's context still does not open
	cmd := f.command(t, "v", protocol.SealContext("dev", sealCommandID, "use2-blue"), nil)
	var p protocol.SealPayload
	_ = json.Unmarshal(cmd.Payload, &p)
	p.Value.Context = good
	cmd.Payload = mustJSON(t, p)
	if _, err := f.sealer.Seal(context.Background(), cmd); err == nil {
		t.Fatal("a relabeled envelope opened")
	}

	// unknown payload fields are refused
	cmd = f.command(t, "v", good, nil)
	cmd.Payload = json.RawMessage(strings.Replace(string(cmd.Payload), `{"key"`, `{"certificate":"x","key"`, 1))
	if _, err := f.sealer.Seal(context.Background(), cmd); err == nil || !strings.Contains(err.Error(), "invalid payload") {
		t.Fatalf("unknown field: %v", err)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
