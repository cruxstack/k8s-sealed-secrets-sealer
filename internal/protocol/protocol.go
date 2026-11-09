// Package protocol defines the messages agents and the control plane
// exchange over /agent/v1. Both sides import it, so a change here is a
// protocol change; see docs/design.md, section 5.
package protocol

import (
	"slices"
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
}

// Error is the body of every error response.
type Error struct {
	Error string `json:"error"`
}
