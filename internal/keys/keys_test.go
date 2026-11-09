package keys

import (
	"strings"
	"testing"
	"time"

	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

func TestParseCert_UsesControllerFingerprint(t *testing.T) {
	priv := testcerts.RSA(t, 2048)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second).UTC()

	key, pub, err := ParseCert(testcerts.SelfSigned(t, priv, notBefore))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, err := sscrypto.PublicKeyFingerprint(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if key.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", key.Fingerprint, want)
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint %q is not SSH-style", key.Fingerprint)
	}
	if !key.NotBefore.Equal(notBefore) || key.Bits != 2048 {
		t.Errorf("key = %+v", key)
	}
	if pub.N.Cmp(priv.N) != 0 {
		t.Error("returned public key does not match")
	}
}

func TestParseCert_Rejects(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		pem  []byte
		want string
	}{
		"garbage":   {[]byte("not a certificate"), "failed to parse certificate pem"},
		"ecdsa key": {testcerts.SelfSigned(t, testcerts.ECDSA(t), now), "expected an rsa public key"},
		"small key": {testcerts.SelfSigned(t, testcerts.RSA(t, 1024), now), "need at least 2048"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseCert(tc.pem)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
