// Package envelope encrypts data under a KMS data key: KMS issues a fresh
// AES-256 key per message, the data is sealed with AES-GCM, and only the
// KMS-wrapped key is kept. The encryption context is both the KMS encryption
// context and the GCM additional data, so a ciphertext opens only for the
// context it was sealed for, and KMS key policies can condition on it.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// DataKeyGenerator is the part of KMS that seals. A principal that may only
// seal (the control plane, for transit) needs nothing more.
type DataKeyGenerator interface {
	GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, opts ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

// Decrypter is the part of KMS that opens.
type Decrypter interface {
	Decrypt(ctx context.Context, in *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Seal encrypts plaintext under a new data key from keyID, bound to encCtx.
func Seal(ctx context.Context, k DataKeyGenerator, keyID string, plaintext []byte, encCtx map[string]string) (protocol.Envelope, error) {
	if len(encCtx) == 0 {
		return protocol.Envelope{}, errors.New("failed to seal envelope: an encryption context is required")
	}
	out, err := k.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:             aws.String(keyID),
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encCtx,
	})
	if err != nil {
		return protocol.Envelope{}, fmt.Errorf("failed to generate data key from %s: %w", keyID, err)
	}
	defer clear(out.Plaintext)

	gcm, err := newGCM(out.Plaintext)
	if err != nil {
		return protocol.Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return protocol.Envelope{}, fmt.Errorf("failed to generate nonce: %w", err)
	}
	aad, err := additionalData(encCtx)
	if err != nil {
		return protocol.Envelope{}, err
	}
	keyARN := aws.ToString(out.KeyId)
	if keyARN == "" {
		keyARN = keyID
	}
	return protocol.Envelope{
		KeyID:      keyARN,
		WrappedKey: base64.StdEncoding.EncodeToString(out.CiphertextBlob),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, aad)),
		Context:    maps.Clone(encCtx),
	}, nil
}

// Open decrypts an envelope that must have been sealed under keyID for
// wantCtx. Neither comes from the envelope: KMS is told which key to use, so
// an envelope made under any other key does not open, and the stored context
// is only compared, while KMS and GCM are always given wantCtx, so an
// envelope relabeled with another context does not open either.
func Open(ctx context.Context, k Decrypter, keyID string, env protocol.Envelope, wantCtx map[string]string) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("failed to open envelope: a KMS key is required")
	}
	if !maps.Equal(env.Context, wantCtx) {
		return nil, errors.New("failed to open envelope: it was sealed for another context")
	}
	wrapped, err1 := base64.StdEncoding.DecodeString(env.WrappedKey)
	nonce, err2 := base64.StdEncoding.DecodeString(env.Nonce)
	sealed, err3 := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("failed to decode envelope: %w", err)
	}
	out, err := k.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    wrapped,
		EncryptionContext: wantCtx,
		KeyId:             aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap data key: %w", err)
	}
	defer clear(out.Plaintext)

	gcm, err := newGCM(out.Plaintext)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("failed to open envelope: bad nonce")
	}
	aad, err := additionalData(wantCtx)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, errors.New("failed to open envelope: authentication failed")
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("failed to use data key: got %d bytes, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to use data key: %w", err)
	}
	return cipher.NewGCM(block)
}

// additionalData is the context as JSON, which orders map keys, so the same
// context always yields the same bytes.
func additionalData(encCtx map[string]string) ([]byte, error) {
	b, err := json.Marshal(encCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to encode encryption context: %w", err)
	}
	return b, nil
}
