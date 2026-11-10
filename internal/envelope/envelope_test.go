package envelope

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

var escrowCtx = map[string]string{"env": "dev", "fingerprint": "SHA256:abc", "purpose": "key-escrow"}

// kmsUnderTest returns the KMS to test against: the fake, and also local KMS
// when SEALER_TEST_KMS_ENDPOINT is set (atmos test integration).
func kmsUnderTest(t *testing.T) map[string]struct {
	k interface {
		DataKeyGenerator
		Decrypter
	}
	keyID string
	// otherKeyID is another key the same caller may use
	otherKeyID string
} {
	t.Helper()
	out := map[string]struct {
		k interface {
			DataKeyGenerator
			Decrypter
		}
		keyID      string
		otherKeyID string
	}{"fake": {NewFakeKMS("escrow", "transit"), "escrow", "transit"}}
	if endpoint := os.Getenv("SEALER_TEST_KMS_ENDPOINT"); endpoint != "" {
		client := kms.New(kms.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(endpoint),
			Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
		})
		out["local-kms"] = struct {
			k interface {
				DataKeyGenerator
				Decrypter
			}
			keyID      string
			otherKeyID string
		}{client, "alias/sealer-escrow", "alias/sealer-transit"}
	}
	return out
}

func TestSealOpen_RoundTrip(t *testing.T) {
	for name, tc := range kmsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			plaintext := []byte("-----BEGIN RSA PRIVATE KEY-----\nsecret\n")
			env, err := Seal(ctx, tc.k, tc.keyID, plaintext, escrowCtx)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(env.Ciphertext, base64.StdEncoding.EncodeToString(plaintext)[:12]) {
				t.Fatal("ciphertext contains the plaintext")
			}
			if env.KeyID == "" || env.Context["fingerprint"] != "SHA256:abc" {
				t.Fatalf("envelope = %+v", env)
			}
			got, err := Open(ctx, tc.k, tc.keyID, env, escrowCtx)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(plaintext) {
				t.Fatalf("Open = %q", got)
			}
		})
	}
}

func TestOpen_Refuses(t *testing.T) {
	for name, tc := range kmsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			env, err := Seal(ctx, tc.k, tc.keyID, []byte("key material"), escrowCtx)
			if err != nil {
				t.Fatal(err)
			}
			otherCtx := map[string]string{"env": "dev", "fingerprint": "SHA256:other", "purpose": "key-escrow"}

			// asked for another context
			if _, err := Open(ctx, tc.k, tc.keyID, env, otherCtx); err == nil {
				t.Error("opened for another context")
			}
			// opened as if under another key
			if _, err := Open(ctx, tc.k, tc.otherKeyID, env, escrowCtx); err == nil {
				t.Error("opened under another key")
			}
			// relabeled with another key ID: the caller's key is used
			relabeledKey := env
			relabeledKey.KeyID = tc.otherKeyID
			if _, err := Open(ctx, tc.k, tc.keyID, relabeledKey, escrowCtx); err != nil {
				t.Errorf("stored key ID was trusted over the caller's: %v", err)
			}
			// relabeled to another context: KMS refuses the data key
			relabeled := env
			relabeled.Context = otherCtx
			if _, err := Open(ctx, tc.k, tc.keyID, relabeled, otherCtx); err == nil {
				t.Error("opened an envelope relabeled with another context")
			}
			// tampered ciphertext: GCM refuses
			tampered := env
			b, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
			b[0] ^= 0xff
			tampered.Ciphertext = base64.StdEncoding.EncodeToString(b)
			if _, err := Open(ctx, tc.k, tc.keyID, tampered, escrowCtx); err == nil {
				t.Error("opened a tampered ciphertext")
			}
		})
	}
}

func TestSeal_RequiresContextAndOpenNeedsDecrypt(t *testing.T) {
	f := NewFakeKMS("transit")
	if _, err := Seal(context.Background(), f, "transit", []byte("x"), nil); err == nil {
		t.Error("sealed without a context")
	}
	env, err := Seal(context.Background(), f, "transit", []byte("x"), map[string]string{"command": "c1"})
	if err != nil {
		t.Fatal(err)
	}
	f.NoDecrypt = true
	if _, err := Open(context.Background(), f, "transit", env, map[string]string{"command": "c1"}); err == nil {
		t.Error("opened without decrypt permission")
	}
	f.NoDecrypt = false
	if _, err := Open(context.Background(), f, "", env, map[string]string{"command": "c1"}); err == nil {
		t.Error("opened without naming a key")
	}
}
