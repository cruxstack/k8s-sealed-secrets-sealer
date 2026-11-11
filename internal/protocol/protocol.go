// Package protocol defines the messages agents and the control plane
// exchange over /agent/v1. Both sides import it, so a change here is a
// protocol change; see docs/design.md, section 5.
//
// Messages change compatibly: the control plane ignores fields it does not
// know in what agents send, and agents ignore them in responses, so either
// side can add a field the other can do without. A command payload is
// strict instead: changing one is a new command type, such as seal.v2.
package protocol

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// Version is the protocol version agents speak.
const Version = "v1"

// Versions lists the protocol versions this build speaks, newest first.
var Versions = []string{Version}

// MaxProtocols bounds the protocol versions one check-in may list.
const MaxProtocols = 16

// Capabilities an agent can have. They come from the agent's Helm values and
// the agent registry; the control plane never grants them.
const (
	CapabilitySeal    = "seal"
	CapabilityKeys    = "keys"
	CapabilityRenewal = "renewal"
	// CapabilityCleanup lets an agent count which keys its controller's
	// SealedSecrets are sealed with, and delete keys an admin deleted. It
	// needs CapabilityKeys.
	CapabilityCleanup = "cleanup"
	// CapabilityReseal lets an agent move sealed values from older keys to
	// the env key (reseal.v1) without decrypting them. It reads the key
	// Secrets, so it needs CapabilityKeys.
	CapabilityReseal = "reseal"
)

// Capabilities lists every known capability.
var Capabilities = []string{CapabilitySeal, CapabilityKeys, CapabilityRenewal, CapabilityCleanup, CapabilityReseal}

// IsCapability reports whether c is a known capability.
func IsCapability(c string) bool { return slices.Contains(Capabilities, c) }

// CapabilityNeeds is the capability each capability needs besides itself:
// counting references and resealing read the key Secrets that keys grants.
var CapabilityNeeds = map[string]string{CapabilityCleanup: CapabilityKeys, CapabilityReseal: CapabilityKeys}

// Limits on a check-in.
const (
	// MaxKeys is how many of a controller's keys the control plane keeps
	// track of: the newest it reports. A check-in reporting more is
	// accepted, and the oldest are left out of key sync. A 4096-bit key is
	// about 1.9 KB of a check-in and 127 bytes of the agent's stored state,
	// so 250 keys are about 465 KB of a 2 MiB check-in and 32 KB of a
	// 400 KB DynamoDB item; docs/design.md, section 9, has the numbers.
	MaxKeys = 250
	// MaxRestoreKeys bounds the fingerprints one keys.restore.v1 names.
	// Agents built when MaxKeys was 100 refuse a longer list; the control
	// plane restores more in later commands.
	MaxRestoreKeys = 100
	// MaxCertificateBytes bounds one PEM certificate.
	MaxCertificateBytes = 16 << 10
	// MaxUsageNamespaces bounds the namespaces a key usage report names: a
	// controller's own and its --additional-namespaces.
	MaxUsageNamespaces = 1000
	// MaxUsageError bounds the error of a key usage report.
	MaxUsageError = 1024
)

// Login methods for POST /agent/v1/session.
const (
	// MethodK8sOIDC logs in with a projected service-account token.
	MethodK8sOIDC = "k8s-oidc"
	// MethodAWSSTS logs in with a signed sts:GetCallerIdentity request,
	// proving the agent's IAM role without sending its credentials.
	MethodAWSSTS = "aws-sts"
	// MethodRenew renews a session that has not expired yet, sent as the
	// request's bearer token, without the agent's identity: an agent logs
	// in with its identity only when it starts or its session lapsed.
	// Control planes that predate it answer 400, and the agent then logs
	// in with its identity.
	MethodRenew = "renew"
)

// AWS login: the only request an agent may sign, and the signed header that
// names the control plane it is meant for, so a request signed for one
// control plane cannot be replayed against another.
const (
	AWSGetCallerIdentityBody = "Action=GetCallerIdentity&Version=2011-06-15"
	AWSAudienceHeader        = "X-K8s-Sealed-Secrets-Sealer-Audience"
)

// EnvHeader names the env an agent belongs to, on every request it makes. A
// control plane serving several envs sends the request to that env, whose
// registry must then know the agent; one serving a single env refuses
// agents of any other.
const EnvHeader = "X-K8s-Sealed-Secrets-Sealer-Env"

// CheckInIntervalHeader carries an agent's check-in interval, in whole
// seconds, on each check-in. The control plane counts the agent healthy
// for three intervals after a check-in. It is a header rather than a field
// of CheckIn because earlier control planes refuse a check-in with a field
// they do not know, but ignore a header; one that predates the header takes
// the agent to check in every 15 seconds.
const CheckInIntervalHeader = "X-K8s-Sealed-Secrets-Sealer-Check-In-Interval"

// Check-in timing, shared by agents and the control plane.
const (
	// DefaultCheckInInterval is an agent's check-in interval unless set
	// otherwise, and the one assumed for an agent that does not report its
	// own.
	DefaultCheckInInterval = 15 * time.Second
	// MinCheckInInterval and MaxCheckInInterval bound an agent's interval.
	MinCheckInInterval = 5 * time.Second
	MaxCheckInInterval = 5 * time.Minute
	// MinHealthWindow keeps an agent with a short interval healthy through
	// a brief outage, such as its controller restarting.
	MinHealthWindow = 3 * DefaultCheckInInterval
)

// HealthWindow is how long after an agent's last check-in the control plane
// counts it healthy: three of its check-in intervals, so three missed
// check-ins make it unhealthy, but at least MinHealthWindow and at most
// three of the longest interval. An interval of zero, from an agent that
// does not report it, is taken as the default.
func HealthWindow(interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = DefaultCheckInInterval
	}
	return min(max(3*interval, MinHealthWindow), 3*MaxCheckInInterval)
}

// SessionRequest asks for an agent session token. Token is set for
// MethodK8sOIDC and AWS for MethodAWSSTS; MethodRenew sets neither.
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
	// Protocol is the one protocol version agents without Protocols send.
	Protocol string `json:"protocol"`
	// Protocols lists every protocol version the agent speaks; the control
	// plane uses the newest it speaks too (Negotiate).
	Protocols    []string   `json:"protocols,omitempty"`
	AgentVersion string     `json:"agent_version"`
	Capabilities []string   `json:"capabilities"`
	Commands     []string   `json:"commands"`
	Controller   Controller `json:"controller"`
	Keys         []Key      `json:"keys"`
	// KeysComplete is false when the agent can see only the controller's
	// active certificate (it lacks the keys capability), so Keys may not be
	// the controller's whole key set.
	KeysComplete bool `json:"keys_complete"`
	// KeyUsage is the agent's latest finished count of key references, from
	// agents with the cleanup capability; nil before the first.
	KeyUsage *KeyUsage `json:"key_usage,omitempty"`
}

// KeyUsage is the agent's latest count of the values its controller's
// SealedSecrets hold, by the key that sealed them. It names no SealedSecret
// and holds no value.
type KeyUsage struct {
	// ScannedAt is when the scan finished, by the agent's clock.
	ScannedAt time.Time `json:"scanned_at"`
	// Namespaces are those the controller watches; nil for every namespace.
	Namespaces    []string `json:"namespaces"`
	SealedSecrets int      `json:"sealed_secrets"`
	Values        int      `json:"values"`
	// Unmatched counts the values no key in the cluster decrypts.
	Unmatched int `json:"unmatched"`
	// Keys holds, by fingerprint, the keys that seal at least one value; at
	// most MaxKeys.
	Keys map[string]KeyUse `json:"keys,omitempty"`
	// Error says why the scan failed; the counts are then absent.
	Error string `json:"error,omitempty"`
}

// KeyUse is how many values one key seals, and in how many SealedSecrets.
type KeyUse struct {
	Values        int `json:"values"`
	SealedSecrets int `json:"sealed_secrets"`
}

// Negotiate returns the newest of ours (newest first) that the agent speaks:
// one in its Protocols or, from an agent that sends only the one, its
// Protocol. It reports false when there is none.
func Negotiate(in CheckIn, ours []string) (string, bool) {
	for _, v := range ours {
		if v == in.Protocol || slices.Contains(in.Protocols, v) {
			return v, true
		}
	}
	return "", false
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
	CommandSeal          = "seal.v1"
	CommandKeysRestore   = "keys.restore.v1"
	CommandRenewalEnable = "renewal.enable.v1"
	CommandKeysDelete    = "keys.delete.v1"
	CommandReseal        = "reseal.v1"
)

// CommandCapability is the capability each command needs.
var CommandCapability = map[string]string{
	CommandSeal:          CapabilitySeal,
	CommandKeysRestore:   CapabilityKeys,
	CommandRenewalEnable: CapabilityRenewal,
	CommandKeysDelete:    CapabilityCleanup,
	CommandReseal:        CapabilityReseal,
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
	// UploadedBy names the escrowed copy the agent tried, by its uploader,
	// when it got one. BadCopy is set when the copy was at fault: it did not
	// open, or its private key is not the certificate's. The control plane
	// then hands the agent another copy. Agents before these fields leave
	// them out.
	UploadedBy string `json:"uploaded_by,omitempty"`
	BadCopy    bool   `json:"bad_copy,omitempty"`
}

// KeysDeletePayload asks an agent to remove keys an admin deleted from its
// controller, at most MaxRestoreKeys.
type KeysDeletePayload struct {
	Fingerprints []string `json:"fingerprints"`
}

// What keys.delete.v1 did with a key.
const (
	// KeyRemoved: the agent deleted the key's Secrets.
	KeyRemoved = "removed"
	// KeyAbsent: the cluster holds no Secret of the key.
	KeyAbsent = "absent"
	// KeyRefused: the agent left the key in place; Reason says why.
	KeyRefused = "refused"
)

// KeysDeleteResult reports a keys.delete.v1, one entry per fingerprint. The
// command succeeds when every key was removed or absent.
type KeysDeleteResult struct {
	Keys                []KeyDeletion `json:"keys"`
	ControllerRestarted bool          `json:"controller_restarted"`
}

// KeyDeletion is what keys.delete.v1 did with one key. Values and
// SealedSecrets are the references the agent counted, when it refused the
// key for them.
type KeyDeletion struct {
	Fingerprint   string `json:"fingerprint"`
	Outcome       string `json:"outcome"`
	Reason        string `json:"reason,omitempty"`
	Values        int    `json:"values,omitempty"`
	SealedSecrets int    `json:"sealed_secrets,omitempty"`
}

// RenewalEnablePayload asks an agent to turn on its controller's key
// renewal with the given period.
type RenewalEnablePayload struct {
	Period string `json:"period"`
}

// Sealing scopes a seal.v1 target may have. Cluster-wide is never one:
// such ciphertext decrypts into any namespace.
const (
	ScopeStrict        = "strict"
	ScopeNamespaceWide = "namespace-wide"
	// ScopeClusterWide names the scope of a reseal.v1 item only, so the
	// agent derives its label as the controller does; agents refuse to
	// reseal such values, as they refuse to seal them.
	ScopeClusterWide = "cluster-wide"
)

// Limits on a seal.
const (
	// MaxSealValueBytes bounds one value.
	MaxSealValueBytes = 64 << 10
	// MaxSealTargets bounds the documents one seal writes to.
	MaxSealTargets = 100
	// SealBudgetBytes bounds a seal's total size, (value + 1 KiB) per
	// target, so all of its ciphertexts fit in one DynamoDB item.
	SealBudgetBytes = 224 << 10
	// SealOverheadBytes is what sealing adds to a value, at most: the
	// RSA-wrapped session key (4096-bit keys), its length and the GCM tag.
	SealOverheadBytes = 1 << 10
)

// SealFits reports whether a value of n bytes may be sealed for targets
// documents.
func SealFits(n, targets int) bool {
	return n <= MaxSealValueBytes && targets <= MaxSealTargets && (n+SealOverheadBytes)*targets <= SealBudgetBytes
}

// SealPayload asks an agent to seal one value for each target, with the
// certificate of the env key its own controller holds.
type SealPayload struct {
	// Key is the name in spec.encryptedData the value is sealed for.
	Key         string       `json:"key"`
	Fingerprint string       `json:"fingerprint"`
	Targets     []SealTarget `json:"targets"`
	// Value is the value, encrypted under the transit key for this command
	// and agent (SealContext). The control plane stores it apart from the
	// rest of the payload and drops it once the command is leased.
	Value *Envelope `json:"value,omitempty"`
}

// SealTarget is one SealedSecret document's decryption label.
type SealTarget struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
}

// SealResult is a seal's ciphertexts, one per target in the same order, each
// base64 as it goes in spec.encryptedData.
type SealResult struct {
	Fingerprint string         `json:"fingerprint"`
	Targets     []SealedTarget `json:"targets"`
}

// SealedTarget is one target's ciphertext.
type SealedTarget struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Ciphertext string `json:"ciphertext"`
}

// Limits on a reseal.v1. A command and its result must each fit in one
// DynamoDB item (400 KB), beside the IDs and names they carry, so a command
// carries at most ResealBudgetBytes of items: each item costs its
// ciphertext and ResealItemOverheadBytes, which also covers the RSA part
// growing when the env key is larger than the key a value came from.
const (
	MaxResealItems          = 500
	ResealBudgetBytes       = 320 << 10
	ResealItemOverheadBytes = 512
	// MaxResealIDBytes bounds an item's ID.
	MaxResealIDBytes = 256
)

// ResealItemCost is what one item with a base64 ciphertext of n characters
// counts against ResealBudgetBytes.
func ResealItemCost(n int) int { return n + ResealItemOverheadBytes }

// ResealPayload asks an agent to move sealed values onto the env key. Each
// value keeps its label: the agent derives it from the item's namespace,
// name and scope, as the controller does.
type ResealPayload struct {
	// EnvKey is the fingerprint of the key values move to; the agent's
	// own controller must hold it.
	EnvKey string       `json:"env_key"`
	Items  []ResealItem `json:"items"`
}

// ResealItem is one value as it is in spec.encryptedData.
type ResealItem struct {
	// ID is opaque to the agent; the result names each item by it.
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Scope      string `json:"scope"`
	Ciphertext string `json:"ciphertext"`
}

// What reseal.v1 did with an item.
const (
	// ResealResealed: another key opened it; Ciphertext holds it on the
	// env key, and From names that key.
	ResealResealed = "resealed"
	// ResealCurrent: the env key opens it already; it is unchanged.
	ResealCurrent = "current"
	// ResealFailed: no key opens it with its label, or it is not a sealed
	// value; Error says why.
	ResealFailed = "failed"
)

// ResealResult reports a reseal.v1, one entry per item, in the payload's
// order. It never holds a value or a session key.
type ResealResult struct {
	Items []ResealedItem `json:"items"`
}

// ResealedItem is what reseal.v1 did with one item.
type ResealedItem struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Ciphertext string `json:"ciphertext,omitempty"`
	From       string `json:"from,omitempty"`
	Error      string `json:"error,omitempty"`
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

// Encryption context keys and purposes.
const (
	ContextEnv         = "env"
	ContextFingerprint = "fingerprint"
	ContextPurpose     = "purpose"
	ContextCommandID   = "command_id"
	ContextAgentID     = "agent_id"
	PurposeKeyEscrow   = "key-escrow"
	PurposeSeal        = "seal"
)

// SealContext is the transit encryption context of a seal.v1 value. It names
// the one agent that may decrypt it, which the transit key's policy
// enforces, and the command, so the value opens for nothing else.
func SealContext(env, commandID, agentID string) map[string]string {
	return map[string]string{
		ContextEnv:       env,
		ContextPurpose:   PurposeSeal,
		ContextCommandID: commandID,
		ContextAgentID:   agentID,
	}
}

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
