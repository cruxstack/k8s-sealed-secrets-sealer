// Package protocol defines the messages agents and the control plane
// exchange over /agent/v1. Both sides import it, so a change here is a
// protocol change; see docs/design.md, section 5.
package protocol

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// Version is the protocol version agents speak.
const Version = "v1"

// Capabilities an agent can have. They come from the agent's Helm values and
// the agent registry; the control plane never grants them.
const (
	CapabilitySeal    = "seal"
	CapabilityKeys    = "keys"
	CapabilityRenewal = "renewal"
)

// Capabilities lists every known capability.
var Capabilities = []string{CapabilitySeal, CapabilityKeys, CapabilityRenewal}

// IsCapability reports whether c is a known capability.
func IsCapability(c string) bool { return slices.Contains(Capabilities, c) }

// Limits on a check-in.
const (
	// MaxKeys bounds the key set one controller may report.
	MaxKeys = 100
	// MaxCertificateBytes bounds one PEM certificate.
	MaxCertificateBytes = 16 << 10
)

// Login methods for POST /agent/v1/session.
const (
	// MethodK8sOIDC logs in with a projected service-account token.
	MethodK8sOIDC = "k8s-oidc"
	// MethodAWSSTS logs in with a signed sts:GetCallerIdentity request,
	// proving the agent's IAM role without sending its credentials.
	MethodAWSSTS = "aws-sts"
)

// AWS login: the only request an agent may sign, and the signed header that
// names the control plane it is meant for, so a request signed for one
// control plane cannot be replayed against another.
const (
	AWSGetCallerIdentityBody = "Action=GetCallerIdentity&Version=2011-06-15"
	AWSAudienceHeader        = "X-K8s-Sealed-Secrets-Sealer-Audience"
)

// SessionRequest asks for an agent session token. Token is set for
// MethodK8sOIDC and AWS for MethodAWSSTS.
type SessionRequest struct {
	Method string         `json:"method"`
	Token  string         `json:"token,omitempty"`
	AWS    *SignedRequest `json:"aws,omitempty"`
}

// SignedRequest is a SigV4-signed sts:GetCallerIdentity request. The control
// plane checks it and forwards it to STS unchanged.
type SignedRequest struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// SessionResponse carries an agent session token, valid for the agent API
// only.
type SessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	AgentID   string    `json:"agent_id"`
	Env       string    `json:"env"`
}

// CheckIn reports an agent's state. Agents send one every check-in
// interval.
type CheckIn struct {
	Protocol     string     `json:"protocol"`
	AgentVersion string     `json:"agent_version"`
	Capabilities []string   `json:"capabilities"`
	Commands     []string   `json:"commands"`
	Controller   Controller `json:"controller"`
	Keys         []Key      `json:"keys"`
	// KeysComplete is false when the agent can see only the controller's
	// active certificate (it lacks the keys capability), so Keys may not be
	// the controller's whole key set.
	KeysComplete bool `json:"keys_complete"`
}

// Controller describes the sealed-secrets controller beside the agent.
type Controller struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// KeyRenewPeriod and KeyOrderPriority are the controller's flag values,
	// empty when the agent could not read them.
	KeyRenewPeriod   string `json:"key_renew_period,omitempty"`
	KeyOrderPriority string `json:"key_order_priority,omitempty"`
	// ActiveFingerprint is the key the controller itself seals with: its
	// newest key.
	ActiveFingerprint string `json:"active_fingerprint"`
}

// Key is one sealing key, described by its public certificate.
type Key struct {
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Certificate string    `json:"certificate"`
}

// CheckInResponse answers a check-in.
type CheckInResponse struct {
	NextCheckInSeconds int `json:"next_checkin_seconds"`
	// EscrowNeeded lists reported keys the env has no escrowed copy of yet.
	// An agent with the keys capability uploads them.
	EscrowNeeded []string `json:"escrow_needed,omitempty"`
}

// Command types. Each is versioned; an agent advertises the ones it handles
// in its check-in, and refuses any other.
const (
	CommandKeysRestore   = "keys.restore.v1"
	CommandRenewalEnable = "renewal.enable.v1"
)

// CommandCapability is the capability each command needs.
var CommandCapability = map[string]string{
	CommandKeysRestore:   CapabilityKeys,
	CommandRenewalEnable: CapabilityRenewal,
}

// Command is a unit of work queued for one agent.
type Command struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Payload   json.RawMessage `json:"payload"`
}

// CommandsResponse answers GET /agent/v1/commands: the commands just leased
// to the agent, possibly none.
type CommandsResponse struct {
	Commands []Command `json:"commands"`
}

// Command outcomes.
const (
	CommandSucceeded = "succeeded"
	CommandFailed    = "failed"
)

// CommandResult reports a command's outcome.
type CommandResult struct {
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// KeysRestorePayload asks an agent to add escrowed keys to its controller.
type KeysRestorePayload struct {
	Fingerprints []string `json:"fingerprints"`
}

// KeysRestoreResult reports a restore.
type KeysRestoreResult struct {
	Restored            []string     `json:"restored"`
	AlreadyPresent      []string     `json:"already_present"`
	Failed              []KeyFailure `json:"failed"`
	ControllerRestarted bool         `json:"controller_restarted"`
}

// KeyFailure is one key that could not be restored.
type KeyFailure struct {
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error"`
}

// RenewalEnablePayload asks an agent to turn on its controller's key
// renewal with the given period.
type RenewalEnablePayload struct {
	Period string `json:"period"`
}

// Envelope is data encrypted under a data key from KMS: AES-256-GCM, with
// the encryption context as additional authenticated data and as the KMS
// encryption context, so the ciphertext only opens for that context.
type Envelope struct {
	KeyID      string            `json:"key_id"`
	WrappedKey string            `json:"wrapped_key"`
	Nonce      string            `json:"nonce"`
	Ciphertext string            `json:"ciphertext"`
	Context    map[string]string `json:"context"`
}

// EscrowUpload is a sealing key encrypted under the escrow KMS key, with its
// public certificate so the control plane can check what it is.
type EscrowUpload struct {
	Certificate string   `json:"certificate"`
	Envelope    Envelope `json:"envelope"`
}

// EscrowRecord is an escrowed sealing key as the control plane stores it.
type EscrowRecord struct {
	Fingerprint string    `json:"fingerprint"`
	Certificate string    `json:"certificate"`
	Envelope    Envelope  `json:"envelope"`
	UploadedBy  string    `json:"uploaded_by"`
	UploadedAt  time.Time `json:"uploaded_at"`
}

// Escrow encryption context keys.
const (
	ContextEnv         = "env"
	ContextFingerprint = "fingerprint"
	ContextPurpose     = "purpose"
	PurposeKeyEscrow   = "key-escrow"
)

// fingerprintPath maps a fingerprint's base64 to the URL-safe alphabet, so a
// fingerprint is one path segment that no proxy decodes or splits.
var (
	fingerprintPath   = strings.NewReplacer("+", "-", "/", "_")
	fingerprintUnpath = strings.NewReplacer("-", "+", "_", "/")
)

// FingerprintPath returns a key fingerprint as a URL path segment.
func FingerprintPath(fp string) string { return fingerprintPath.Replace(fp) }

// ParseFingerprintPath returns the fingerprint a URL path segment names.
func ParseFingerprintPath(segment string) string { return fingerprintUnpath.Replace(segment) }

// Error is the body of every error response.
type Error struct {
	Error string `json:"error"`
}
