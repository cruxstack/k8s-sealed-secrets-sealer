package store

import (
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Command statuses.
const (
	CommandQueued    = "queued"
	CommandLeased    = "leased"
	CommandSucceeded = protocol.CommandSucceeded
	CommandFailed    = protocol.CommandFailed
)

// commandRetention keeps finished and expired commands this long past their
// expiry, for the audit trail, before DynamoDB's TTL removes them.
const commandRetention = time.Hour

// CommandRecord is a command queued for one agent.
type CommandRecord struct {
	AgentID    string     `dynamodbav:"agent_id"`
	ID         string     `dynamodbav:"command_id"`
	Type       string     `dynamodbav:"type"`
	Status     string     `dynamodbav:"status"`
	CreatedAt  time.Time  `dynamodbav:"created_at"`
	ExpiresAt  time.Time  `dynamodbav:"command_expires_at"`
	LeasedAt   *time.Time `dynamodbav:"leased_at,omitempty"`
	FinishedAt *time.Time `dynamodbav:"finished_at,omitempty"`
	// Payload and Result are JSON.
	Payload string `dynamodbav:"payload"`
	Result  string `dynamodbav:"result,omitempty"`
	Error   string `dynamodbav:"error,omitempty"`
}

// Open reports whether the command is still waiting or running at now.
func (c CommandRecord) Open(now time.Time) bool {
	return (c.Status == CommandQueued || c.Status == CommandLeased) && now.Before(c.ExpiresAt)
}

// Protocol returns the command as sent to the agent.
func (c CommandRecord) Protocol() protocol.Command {
	return protocol.Command{
		ID:        c.ID,
		Type:      c.Type,
		CreatedAt: c.CreatedAt,
		ExpiresAt: c.ExpiresAt,
		Payload:   []byte(c.Payload),
	}
}
