package store

import "time"

// Key statuses. A key is active until an admin revokes it; a revoked key is
// never the env key, never restored and never counted as missing, but its
// escrowed copies are kept so it can be reinstated.
const (
	KeyActive  = "active"
	KeyRevoked = "revoked"
)

// RevokedKey is a revoked key as the env lists it, with what the fleet view
// shows of a key no cluster reports any more.
type RevokedKey struct {
	Fingerprint string    `dynamodbav:"fingerprint" json:"fingerprint"`
	NotBefore   time.Time `dynamodbav:"not_before" json:"not_before"`
	NotAfter    time.Time `dynamodbav:"not_after" json:"not_after"`
	By          string    `dynamodbav:"revoked_by" json:"revoked_by"`
	At          time.Time `dynamodbav:"revoked_at" json:"revoked_at"`
}

// revokedKey is the record SetKeyStatus lists for a revoked key.
func revokedKey(k KeyRecord) RevokedKey {
	r := RevokedKey{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, NotAfter: k.NotAfter, By: k.StatusBy}
	if k.StatusAt != nil {
		r.At = *k.StatusAt
	}
	return r
}
