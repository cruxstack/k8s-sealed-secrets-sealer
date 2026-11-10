package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// FakeKMS is an in-memory KMS for tests. Like KMS, it binds each wrapped data
// key to its key and encryption context: Decrypt fails if the context
// differs, or if the caller names another key.
// It can be told to refuse Decrypt, to stand in for a principal whose key
// policy allows only GenerateDataKey.
type FakeKMS struct {
	mu        sync.Mutex
	master    map[string][]byte
	NoDecrypt bool
}

// NewFakeKMS returns a FakeKMS with the given key IDs.
func NewFakeKMS(keyIDs ...string) *FakeKMS {
	f := &FakeKMS{master: map[string][]byte{}}
	for _, id := range keyIDs {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		f.master[id] = k
	}
	return f
}

type fakeWrapped struct {
	KeyID string `json:"k"`
	Nonce []byte `json:"n"`
	Box   []byte `json:"b"`
}

func (f *FakeKMS) gcm(keyID string) (cipher.AEAD, error) {
	f.mu.Lock()
	k, ok := f.master[keyID]
	f.mu.Unlock()
	if !ok {
		return nil, errors.New("NotFoundException: key " + keyID)
	}
	block, _ := aes.NewCipher(k)
	return cipher.NewGCM(block)
}

// GenerateDataKey returns a random data key wrapped under the master key.
func (f *FakeKMS) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	keyID := aws.ToString(in.KeyId)
	g, err := f.gcm(keyID)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 32)
	_, _ = rand.Read(plaintext)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	aad, _ := json.Marshal(in.EncryptionContext)
	wrapped, _ := json.Marshal(fakeWrapped{KeyID: keyID, Nonce: nonce, Box: g.Seal(nil, nonce, plaintext, aad)})
	return &kms.GenerateDataKeyOutput{
		KeyId:          aws.String(fakeARN(keyID)),
		Plaintext:      plaintext,
		CiphertextBlob: wrapped,
	}, nil
}

// Decrypt unwraps a data key; it fails for any other encryption context.
func (f *FakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if f.NoDecrypt {
		return nil, errors.New("AccessDeniedException: not allowed to decrypt")
	}
	var w fakeWrapped
	if err := json.Unmarshal(in.CiphertextBlob, &w); err != nil {
		return nil, errors.New("InvalidCiphertextException")
	}
	if id := aws.ToString(in.KeyId); id != "" && id != w.KeyID && id != fakeARN(w.KeyID) {
		return nil, errors.New("IncorrectKeyException: the ciphertext was made under another key")
	}
	g, err := f.gcm(w.KeyID)
	if err != nil {
		return nil, err
	}
	aad, _ := json.Marshal(in.EncryptionContext)
	plaintext, err := g.Open(nil, w.Nonce, w.Box, aad)
	if err != nil {
		return nil, errors.New("InvalidCiphertextException")
	}
	return &kms.DecryptOutput{Plaintext: plaintext, KeyId: aws.String(fakeARN(w.KeyID))}, nil
}

func fakeARN(keyID string) string { return "arn:aws:kms:us-east-1:000000000000:key/" + keyID }
