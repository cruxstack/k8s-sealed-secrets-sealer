// Package keys describes sealed-secrets sealing keys by their public
// certificates. The agent and the control plane both use it, so they always
// agree on a key's fingerprint.
package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	"k8s.io/client-go/util/cert"
)

// MinBits is the smallest RSA key accepted.
const MinBits = 2048

// Key describes one sealing key by its public certificate.
type Key struct {
	// Fingerprint is the controller's own identifier for the key: the
	// SSH-style SHA-256 fingerprint of the public key.
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
	Bits        int
}

// ParseCert parses the first certificate in pemBytes and returns the key it
// describes. It accepts only RSA keys of at least MinBits.
func ParseCert(pemBytes []byte) (Key, *rsa.PublicKey, error) {
	certs, err := cert.ParseCertsPEM(pemBytes)
	if err != nil {
		return Key{}, nil, fmt.Errorf("failed to parse certificate pem: %w", err)
	}
	if len(certs) == 0 {
		return Key{}, nil, errors.New("failed to parse certificate pem: no certificates")
	}
	return describe(certs[0])
}

func describe(c *x509.Certificate) (Key, *rsa.PublicKey, error) {
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return Key{}, nil, fmt.Errorf("failed to use certificate: expected an rsa public key, got %T", c.PublicKey)
	}
	if bits := pub.N.BitLen(); bits < MinBits {
		return Key{}, nil, fmt.Errorf("failed to use certificate: rsa key has %d bits, need at least %d", bits, MinBits)
	}
	fp, err := sscrypto.PublicKeyFingerprint(pub)
	if err != nil {
		return Key{}, nil, fmt.Errorf("failed to fingerprint public key: %w", err)
	}
	return Key{
		Fingerprint: fp,
		NotBefore:   c.NotBefore.UTC(),
		NotAfter:    c.NotAfter.UTC(),
		Bits:        pub.N.BitLen(),
	}, pub, nil
}
