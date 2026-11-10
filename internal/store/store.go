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
	// Keys holds no certificates; those are stored once per key.
	Keys         []KeyRef `dynamodbav:"keys"`
	KeysComplete bool     `dynamodbav:"keys_complete"`
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
	// PutReplayIfAbsent records a one-time key (such as a signed login
	// request's signature) until expires, and reports whether this call
	// recorded it. A false result means the key was already used.
	PutReplayIfAbsent(ctx context.Context, key string, expires time.Time) (bool, error)

	// PutCommand queues a command.
	PutCommand(ctx context.Context, c CommandRecord) error
	// Commands returns an agent's commands, oldest first.
	Commands(ctx context.Context, agentID string) ([]CommandRecord, error)
	// Command returns one of an agent's commands.
	Command(ctx context.Context, agentID, id string) (CommandRecord, bool, error)
	// LeaseCommand moves a queued, unexpired command to leased, and reports
	// whether this call did; a command is leased at most once. Leasing
	// removes the command's secret.
	LeaseCommand(ctx context.Context, agentID, id string, now time.Time) (bool, error)
	// FinishCommand records the outcome of a leased, unexpired command, and
	// reports whether this call did; a result is accepted at most once.
	FinishCommand(ctx context.Context, agentID, id, status, result, errMsg string, now time.Time) (bool, error)

	// PutEscrowIfAbsent stores an escrowed key unless one is stored already,
	// and reports whether this call stored it (the first upload wins).
	PutEscrowIfAbsent(ctx context.Context, rec protocol.EscrowRecord) (bool, error)
	// Escrow returns an escrowed key.
	Escrow(ctx context.Context, fingerprint string) (protocol.EscrowRecord, bool, error)
	// Escrowed reports which of the fingerprints have an escrowed key.
	Escrowed(ctx context.Context, fingerprints []string) (map[string]bool, error)

	// CreateSession stores a session unless its user already has a live
	// one for the repository, which it returns instead, reporting whether
	// this call created one. It fails with ErrTooManySessions when the user
	// already has max live sessions.
	CreateSession(ctx context.Context, s Session, max int, now time.Time) (Session, bool, error)
	// Session returns a user's live session for a repository (RepoKey).
	Session(ctx context.Context, userID int64, repoKey string, now time.Time) (Session, bool, error)
	// Sessions returns a user's live sessions.
	Sessions(ctx context.Context, userID int64, now time.Time) ([]Session, error)
	// TouchSession marks a live session used at now and moves its expiry to
	// expires, and reports whether it did. The session must still be id.
	TouchSession(ctx context.Context, userID int64, repoKey, id string, expires, now time.Time) (bool, error)
	// DeleteSession ends a session if it is still id, and reports whether
	// it did. Its seals and changes are left to expire.
	DeleteSession(ctx context.Context, userID int64, repoKey, id string) (bool, error)

	// PutSeal records a requested seal.
	PutSeal(ctx context.Context, s Seal) error
	// Seal returns a seal requested in a session.
	Seal(ctx context.Context, sessionID, commandID string) (Seal, bool, error)
	// PutChange stores a pending change, replacing the one for the same
	// file and key unless that came from a newer seal, and reports whether
	// it did.
	PutChange(ctx context.Context, c Change) (bool, error)
	// Changes returns a session's pending changes, with their ciphertexts
	// only when asked for.
	Changes(ctx context.Context, sessionID string, ciphertexts bool) ([]Change, error)
	// DeleteChange removes a pending change and reports whether it existed.
	DeleteChange(ctx context.Context, sessionID, id string) (bool, error)
}
