package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"

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
// expiry, before DynamoDB's TTL removes them: a seal's outcome stays
// readable, and key sync sees work a command just did. The audit trail is
// the structured logs, not the table (docs/design.md, section 11).
const commandRetention = time.Hour

// commandIDCeiling sorts after every command ID: ULIDs use only digits and
// capital letters.
const commandIDCeiling = "~"

// commandIDFloor returns the lowest command ID made at or after since.
// Command IDs are ULIDs, which sort by the millisecond they were made in, so
// the commands made since then are a range of IDs.
func commandIDFloor(since time.Time) string {
	var id ulid.ULID
	// a time ULIDs cannot hold leaves the floor at zero: every command
	_ = id.SetTime(uint64(max(since.UnixMilli(), 0)))
	return id.String()
}

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
	// Secret is an encrypted value (a protocol.Envelope, as JSON) delivered
	// as the payload's "value" field. It is stored apart so leasing can
	// remove it: it reaches the agent once and is not kept after.
	Secret string `dynamodbav:"secret,omitempty"`
	// SessionID is the session a seal command's result is recorded in.
	SessionID string `dynamodbav:"session_id,omitempty"`
	Result    string `dynamodbav:"result,omitempty"`
	Error     string `dynamodbav:"error,omitempty"`
}

// Open reports whether the command is still waiting or running at now.
func (c CommandRecord) Open(now time.Time) bool {
	return (c.Status == CommandQueued || c.Status == CommandLeased) && now.Before(c.ExpiresAt)
}

// Expired reports whether the command ran out of time without a result.
func (c CommandRecord) Expired(now time.Time) bool {
	return (c.Status == CommandQueued || c.Status == CommandLeased) && !now.Before(c.ExpiresAt)
}

// Protocol returns the command as sent to the agent, with its secret, if
// any, as the payload's "value" field.
func (c CommandRecord) Protocol() (protocol.Command, error) {
	payload := json.RawMessage(c.Payload)
	if c.Secret != "" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &fields); err != nil {
			return protocol.Command{}, fmt.Errorf("failed to decode payload of command %s: %w", c.ID, err)
		}
		fields["value"] = json.RawMessage(c.Secret)
		merged, err := json.Marshal(fields)
		if err != nil {
			return protocol.Command{}, fmt.Errorf("failed to encode payload of command %s: %w", c.ID, err)
		}
		payload = merged
	}
	return protocol.Command{
		ID:        c.ID,
		Type:      c.Type,
		CreatedAt: c.CreatedAt,
		ExpiresAt: c.ExpiresAt,
		Payload:   payload,
	}, nil
}
