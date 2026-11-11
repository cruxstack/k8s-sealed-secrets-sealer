package store

import (
	"errors"
	"time"
)

// Key statuses. A key is active until an admin revokes it; a revoked key is
// never the env key, never restored and never counted as missing, but its
// escrowed copies are kept so it can be reinstated. An admin may then
// delete it: agents remove it from their clusters, and its escrowed copies
// expire at its purge time, until which it can still be reinstated. A
// deleted key is a revoked key for everything else.
const (
	KeyActive  = "active"
	KeyRevoked = "revoked"
	KeyDeleted = "deleted"
)

// ErrKeyChanged is returned by a key status change whose key changed
// status meanwhile, or whose escrowed copies changed while it was deleted.
var ErrKeyChanged = errors.New("the key changed meanwhile")

// Revoked reports whether the key is revoked, deleted or not.
func (k KeyRecord) Revoked() bool { return k.Status == KeyRevoked || k.Status == KeyDeleted }

// RevokedKey is a revoked key as the env lists it, with what the fleet view
// shows of a key no cluster reports any more. A deleted key keeps its
// record, with who deleted it and when its escrowed copies are purged.
type RevokedKey struct {
	Fingerprint string    `dynamodbav:"fingerprint" json:"fingerprint"`
	NotBefore   time.Time `dynamodbav:"not_before" json:"not_before"`
	NotAfter    time.Time `dynamodbav:"not_after" json:"not_after"`
	By          string    `dynamodbav:"revoked_by" json:"revoked_by"`
	At          time.Time `dynamodbav:"revoked_at" json:"revoked_at"`
	// Status is KeyDeleted for a deleted key; empty for one only revoked,
	// as in every record written before keys could be deleted.
	Status    string     `dynamodbav:"status,omitempty" json:"status,omitempty"`
	DeletedBy string     `dynamodbav:"deleted_by,omitempty" json:"deleted_by,omitempty"`
	DeletedAt *time.Time `dynamodbav:"deleted_at,omitempty" json:"deleted_at,omitempty"`
	PurgeAt   *time.Time `dynamodbav:"purge_at,omitempty" json:"purge_at,omitempty"`
}

// Deleted reports whether an admin deleted the key.
func (r RevokedKey) Deleted() bool { return r.Status == KeyDeleted }

// Purged reports whether a deleted key's escrowed copies are past their
// purge time at now: gone, or about to be, so it cannot come back.
func (r RevokedKey) Purged(now time.Time) bool {
	return r.Deleted() && r.PurgeAt != nil && !now.Before(*r.PurgeAt)
}

// revokedKey is the record SetKeyStatus lists for a revoked key.
func revokedKey(k KeyRecord) RevokedKey {
	r := RevokedKey{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, NotAfter: k.NotAfter, By: k.StatusBy}
	if k.StatusAt != nil {
		r.At = *k.StatusAt
	}
	return r
}

// ReinstatedRestoreWindow is how long a deleted key an admin reinstated is
// listed as reinstated (ReinstatedKey): key sync restores it to every
// cluster meanwhile, although no cluster may hold it any more.
const ReinstatedRestoreWindow = 7 * 24 * time.Hour

// ReinstatedKey is a deleted key an admin reinstated. Its clusters may
// all have removed it, and key sync restores only keys a cluster holds, so
// it is listed for ReinstatedRestoreWindow: until then every cluster
// without it is missing it.
type ReinstatedKey struct {
	Fingerprint string    `dynamodbav:"fingerprint" json:"fingerprint"`
	NotBefore   time.Time `dynamodbav:"not_before" json:"not_before"`
	NotAfter    time.Time `dynamodbav:"not_after" json:"not_after"`
	By          string    `dynamodbav:"reinstated_by" json:"reinstated_by"`
	At          time.Time `dynamodbav:"reinstated_at" json:"reinstated_at"`
}

// reinstatedKey is the record ReinstateDeletedKey lists for k.
func reinstatedKey(k KeyRecord) ReinstatedKey {
	r := ReinstatedKey{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, NotAfter: k.NotAfter, By: k.StatusBy}
	if k.StatusAt != nil {
		r.At = *k.StatusAt
	}
	return r
}

// KeyLists are the env's lists of keys, read together.
type KeyLists struct {
	// Revoked are the revoked keys, deleted ones included.
	Revoked map[string]RevokedKey
	// Reinstated are the deleted keys reinstated within
	// ReinstatedRestoreWindow.
	Reinstated map[string]ReinstatedKey
}

// KeyUsage is an agent's latest count of key references, as the control
// plane received it.
type KeyUsage struct {
	AgentID string `dynamodbav:"agent_id"`
	// CountedAt is when the control plane first received the report, by
	// its own clock; ScannedAt is when the agent finished it, by the
	// agent's.
	CountedAt time.Time `dynamodbav:"counted_at"`
	ScannedAt time.Time `dynamodbav:"scanned_at"`
	// Namespaces are those the controller watches; empty for every
	// namespace.
	Namespaces    []string `dynamodbav:"namespaces,omitempty"`
	SealedSecrets int      `dynamodbav:"sealed_secrets"`
	Values        int      `dynamodbav:"values"`
	Unmatched     int      `dynamodbav:"unmatched"`
	// Keys holds the keys that seal at least one value, by fingerprint.
	Keys map[string]KeyUse `dynamodbav:"keys,omitempty"`
	// Error says why the count failed; the counts are then absent.
	Error string `dynamodbav:"error,omitempty"`
}

// KeyUse is how many values one key seals in a cluster, and in how many
// SealedSecrets.
type KeyUse struct {
	Values        int `dynamodbav:"values"`
	SealedSecrets int `dynamodbav:"sealed_secrets"`
}
