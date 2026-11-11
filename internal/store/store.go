// Package store persists the control plane's state. DynamoDB is the store in
// every deployment; the in-memory store is for tests.
package store

import (
	"context"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// AgentState is what the control plane knows about an agent from its latest
// check-in.
type AgentState struct {
	AgentID      string              `dynamodbav:"agent_id"`
	LastCheckIn  time.Time           `dynamodbav:"last_checkin"`
	AgentVersion string              `dynamodbav:"agent_version"`
	Protocol     string              `dynamodbav:"protocol"`
	Capabilities []string            `dynamodbav:"capabilities"`
	Commands     []string            `dynamodbav:"commands"`
	Controller   protocol.Controller `dynamodbav:"controller"`
	// Keys holds no certificates; those are stored once per key. It holds
	// at most protocol.MaxKeys keys: the newest the agent reported.
	Keys         []KeyRef `dynamodbav:"keys"`
	KeysComplete bool     `dynamodbav:"keys_complete"`
	// CheckInIntervalSeconds is the agent's check-in interval, 0 when the
	// agent did not report it.
	CheckInIntervalSeconds int `dynamodbav:"checkin_interval_seconds,omitempty"`
	// KeysReported is how many keys the agent reported, more than Keys
	// holds when some were left out; zero in states stored before it was
	// recorded. DroppedUpTo is the newest NotBefore among the usable keys
	// left out (neither revoked nor dated in the future), nil when there
	// were none: a key no newer than that may be held although Keys does
	// not list it.
	KeysReported int        `dynamodbav:"keys_reported,omitempty"`
	DroppedUpTo  *time.Time `dynamodbav:"dropped_up_to,omitempty"`
	// JoinedAt is when the agent first checked in, or first checked in
	// holding none of the keys it held before (its cluster was rebuilt).
	// It is nil for agents first seen before it was recorded.
	JoinedAt *time.Time `dynamodbav:"joined_at,omitempty"`
	// UsageScannedAt is the scan time of the agent's latest key usage
	// report the control plane stored (KeyUsage), so a check-in carrying
	// the same report again writes nothing; UsageUnmatched is that report's
	// unmatched count. Both are unset until an agent reports usage.
	UsageScannedAt *time.Time `dynamodbav:"usage_scanned_at,omitempty"`
	UsageUnmatched int        `dynamodbav:"usage_unmatched,omitempty"`
}

// CheckInInterval is the agent's check-in interval, 0 when it did not report
// it.
func (s AgentState) CheckInInterval() time.Duration {
	return time.Duration(s.CheckInIntervalSeconds) * time.Second
}

// KeyRef identifies a key in an agent's key set.
type KeyRef struct {
	Fingerprint string    `dynamodbav:"fingerprint" json:"fingerprint"`
	NotBefore   time.Time `dynamodbav:"not_before" json:"not_before"`
	NotAfter    time.Time `dynamodbav:"not_after" json:"not_after"`
}

// KeyRecord is a sealing key the env has seen, kept from the first report.
type KeyRecord struct {
	Fingerprint    string    `dynamodbav:"fingerprint"`
	Certificate    string    `dynamodbav:"certificate"`
	NotBefore      time.Time `dynamodbav:"not_before"`
	NotAfter       time.Time `dynamodbav:"not_after"`
	FirstSeenAgent string    `dynamodbav:"first_seen_agent"`
	FirstSeenAt    time.Time `dynamodbav:"first_seen_at"`
	// Status is KeyActive (also when empty), KeyRevoked or KeyDeleted;
	// StatusBy and StatusAt say who set it and when. Who revoked a deleted
	// key is in its RevokedKey record.
	Status   string     `dynamodbav:"status,omitempty"`
	StatusBy string     `dynamodbav:"status_by,omitempty"`
	StatusAt *time.Time `dynamodbav:"status_at,omitempty"`
	// PurgeAt is when a deleted key's escrowed copies expire.
	PurgeAt *time.Time `dynamodbav:"purge_at,omitempty"`
}

// Store is the control plane's persistence.
type Store interface {
	// PutAgentState replaces an agent's state.
	PutAgentState(ctx context.Context, s AgentState) error
	// GetAgentStates returns the states of the given agents, keyed by agent
	// ID. Agents that never checked in are absent.
	GetAgentStates(ctx context.Context, agentIDs []string) (map[string]AgentState, error)
	// PutKeyIfAbsent records a key the first time any agent reports it and
	// reports whether this call created the record.
	PutKeyIfAbsent(ctx context.Context, k KeyRecord) (bool, error)
	// GetKey returns the env's record of a key.
	GetKey(ctx context.Context, fingerprint string) (KeyRecord, bool, error)
	// SetKeyStatus records k's Status (KeyActive or KeyRevoked), StatusBy
	// and StatusAt on its record and, in the same write, lists a revoked key
	// for RevokedKeys or takes a reinstated one off, and takes the key off
	// the reinstated keys. It reports whether the key has a record, and
	// fails with ErrKeyChanged when the key is deleted: DeleteKey and
	// ReinstateDeletedKey change those.
	SetKeyStatus(ctx context.Context, k KeyRecord) (bool, error)
	// DeleteKey marks a key revoked at revokedAt deleted, by k.StatusBy at
	// k.StatusAt, and sets its escrowed copies to expire at k.PurgeAt, all
	// in one write; its RevokedKey record keeps who revoked it. It fails
	// with ErrKeyChanged when the key is not that revocation any more (it
	// is active, already deleted, revoked again or has no record), or its
	// escrowed copies changed meanwhile.
	DeleteKey(ctx context.Context, k KeyRecord, revokedAt time.Time) error
	// UndeleteKey returns a deleted key to revoked, as r says it was
	// revoked: it takes the deletion off its records and the expiry off
	// whatever escrowed copies remain, all in one write. It fails with
	// ErrKeyChanged when the key is not deleted.
	UndeleteKey(ctx context.Context, r RevokedKey) error
	// ReinstateDeletedKey makes a deleted key active, by k.StatusBy at
	// k.StatusAt: it keeps its escrowed copies, takes it off the revoked
	// keys and lists it as reinstated (KeyLists), all in one write. It
	// fails with ErrKeyChanged when the key is not deleted. Whether its
	// copies were purged is the caller's to check.
	ReinstateDeletedKey(ctx context.Context, k KeyRecord) error
	// RevokedKeys returns the env's revoked keys, deleted ones included, by
	// fingerprint.
	RevokedKeys(ctx context.Context) (map[string]RevokedKey, error)
	// KeyLists returns the env's revoked keys and its reinstated ones,
	// with one read.
	KeyLists(ctx context.Context) (KeyLists, error)

	// PutKeyUsage stores an agent's key usage report, replacing the one
	// before, unless the stored report has the same ScannedAt: a report is
	// stored once, with the time it was first received (CountedAt). It
	// reports whether it stored this one.
	PutKeyUsage(ctx context.Context, u KeyUsage) (bool, error)
	// KeyUsages returns the given agents' latest key usage reports, by
	// agent ID; agents that never reported one are absent.
	KeyUsages(ctx context.Context, agentIDs []string) (map[string]KeyUsage, error)
	// PutReplayIfAbsent records a one-time key (such as a signed login
	// request's signature) until expires, and reports whether this call
	// recorded it. A false result means the key was already used.
	PutReplayIfAbsent(ctx context.Context, key string, expires time.Time) (bool, error)
	// CountRequest counts n requests, or calls a request made, against key
	// in the fixed window that ends at windowEnd, if fewer than limit are
	// counted, and reports whether it did. With n 0 it only reports whether
	// the limit is reached.
	CountRequest(ctx context.Context, key string, n, limit int, windowEnd time.Time) (bool, error)

	// PutCommand queues a command.
	PutCommand(ctx context.Context, c CommandRecord) error
	// Commands returns an agent's commands, oldest first.
	Commands(ctx context.Context, agentID string) ([]CommandRecord, error)
	// CommandsSince returns an agent's commands whose IDs (ULIDs) were made
	// at or after since, oldest first. It reads only those, not every
	// command kept.
	CommandsSince(ctx context.Context, agentID string, since time.Time) ([]CommandRecord, error)
	// Command returns one of an agent's commands.
	Command(ctx context.Context, agentID, id string) (CommandRecord, bool, error)
	// LeaseCommand moves a queued, unexpired command to leased, and reports
	// whether this call did; a command is leased at most once. Leasing
	// removes the command's secret.
	LeaseCommand(ctx context.Context, agentID, id string, now time.Time) (bool, error)
	// FinishCommand records the outcome of a leased, unexpired command, and
	// reports whether this call did; a result is accepted at most once.
	FinishCommand(ctx context.Context, agentID, id, status, result, errMsg string, now time.Time) (bool, error)

	// PutEscrow stores an agent's escrowed copy of a key: the first upload
	// as the key's primary record, a later one from another agent as a
	// further copy, up to maxCopies in all. It reports whether this call
	// stored one (not when the uploader has a copy already, the key has
	// maxCopies or the key is deleted), and whether it was the key's first.
	PutEscrow(ctx context.Context, rec protocol.EscrowRecord, maxCopies int) (stored, first bool, err error)
	// Escrow returns a key's escrowed copies, the primary record first and
	// the others by uploader; none when the key has no escrowed copy. Copies
	// of a deleted key past its purge time are gone, whether or not the
	// table's TTL has removed them yet.
	Escrow(ctx context.Context, fingerprint string) ([]protocol.EscrowRecord, error)
	// EscrowUploaders returns, for each of the fingerprints with an
	// escrowed copy, the agents that uploaded one, the primary's first.
	EscrowUploaders(ctx context.Context, fingerprints []string) (map[string][]string, error)

	// CreateSession stores a session unless its user already has a live
	// one for the repository, which it returns instead, reporting whether
	// this call created one. It fails with ErrTooManySessions when the user
	// already has max live sessions, even with concurrent calls.
	CreateSession(ctx context.Context, s Session, max int, now time.Time) (Session, bool, error)
	// Session returns a user's live session for a repository (RepoKey).
	Session(ctx context.Context, userID int64, repoKey string, now time.Time) (Session, bool, error)
	// Sessions returns a user's live sessions.
	Sessions(ctx context.Context, userID int64, now time.Time) ([]Session, error)
	// TouchSession marks a live session used at now and moves its expiry to
	// expires, and reports whether it did. The session must still be id. It
	// fails with ErrSessionBusy while the session is locked.
	TouchSession(ctx context.Context, userID int64, repoKey, id string, expires, now time.Time) (bool, error)
	// LockSession locks a live session (still id) until until, while a pull
	// request is opened from it, and reports whether it did: not when the
	// session is gone or already locked.
	LockSession(ctx context.Context, userID int64, repoKey, id string, until, now time.Time) (bool, error)
	// UnlockSession releases a session's lock.
	UnlockSession(ctx context.Context, userID int64, repoKey, id string) error
	// DeleteSession ends a session if it is still id, and reports whether
	// it did. Its seals and changes are left to expire.
	DeleteSession(ctx context.Context, userID int64, repoKey, id string) (bool, error)
	// DiscardSession ends a live session (still id) unless it is locked,
	// and reports whether it did. It fails with ErrSessionBusy while the
	// session is locked, so a pull request being opened from it is never
	// left with a session discarded under it.
	DiscardSession(ctx context.Context, userID int64, repoKey, id string, now time.Time) (bool, error)

	// PutSeal records a requested seal.
	PutSeal(ctx context.Context, s Seal) error
	// Seal returns a seal requested in a session.
	Seal(ctx context.Context, sessionID, commandID string) (Seal, bool, error)
	// ReserveChange holds a place among a session's at most max pending
	// changes for the change a seal (sealID, its command) is about to make,
	// until until, by when the seal has made it or expired. existing lists
	// the session's pending changes as just read. It fails with
	// ErrTooManyChanges when they and the places other seals hold come to
	// max without changeID, even with concurrent calls.
	ReserveChange(ctx context.Context, sessionID, changeID, sealID string, existing []string, max int, until, now time.Time) error
	// ReleaseChange gives up the place a seal holds, once its change is
	// stored (the change then counts itself, and removing it frees its
	// place) or the seal failed.
	ReleaseChange(ctx context.Context, sessionID, changeID, sealID string, now time.Time) error
	// PutChange stores a pending change, replacing the one for the same
	// file and key unless that came from a newer seal, and reports whether
	// it did.
	PutChange(ctx context.Context, c Change) (bool, error)
	// Changes returns a session's pending changes, with their ciphertexts
	// only when asked for.
	Changes(ctx context.Context, sessionID string, ciphertexts bool) ([]Change, error)
	// RemoveChange removes a pending change of a live session (still
	// sessionID) unless the session is locked, and reports whether the
	// change existed. It fails with ErrSessionBusy while the session is
	// locked: a pull request being opened may have read the change.
	RemoveChange(ctx context.Context, userID int64, repoKey, sessionID, id string, now time.Time) (bool, error)
	// PruneChange removes a pending change if it still holds the seal of
	// commandID, and reports whether it did. A change a newer seal
	// replaced in the meantime stays.
	PruneChange(ctx context.Context, sessionID, id, commandID string) (bool, error)
}
