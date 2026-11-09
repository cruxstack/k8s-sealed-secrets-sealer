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
}
