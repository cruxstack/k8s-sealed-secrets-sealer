// Package fleet computes the env's view of its agents from the registry and
// their latest check-ins: which agents are healthy, which key every cluster
// holds (the env key), and which clusters are missing keys. It is pure: no
// I/O, so the rules in docs/design.md section 7 are tested directly.
package fleet

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Timing shared by agents and the control plane.
const (
	CheckInInterval = protocol.DefaultCheckInInterval
	// HealthyWithin is how recent an agent's last check-in must be for it to
	// count as healthy at the default interval; protocol.HealthWindow gives
	// it for an agent's own.
	HealthyWithin = 3 * CheckInInterval
)

// Key lifecycle bounds.
const (
	// JoinWindow is how long a cluster that just joined the env, or was
	// rebuilt, is left out of the env key while it restores the env's
	// keys. Restore normally takes a check-in, a command and a controller
	// restart, about a minute. The window also covers a key command that
	// expires unleased (10 minutes) and two retries after failures (5
	// minutes apart, the second from another escrowed copy).
	JoinWindow = 30 * time.Minute
	// FutureSkew is how far ahead of now a key's NotBefore may be, for
	// clocks that disagree. A key dated later is not used or restored
	// until then.
	FutureSkew = time.Hour
	// UsageFresh is how recently, by the control plane's clock, a cluster's
	// count of key references must have come in to count.
	UsageFresh = time.Hour
)

// Why a key that is not revoked cannot be deleted. The delete API refuses
// with the same sentences as the fleet view's Key.DeleteBlocked.
const (
	BlockedActive  = "Revoke the key first."
	BlockedDeleted = "The key is already deleted."
)

// orderCertNotBefore is the controller's default key order and the only one
// under which a restored key keeps its place.
const orderCertNotBefore = "CertNotBefore"

// Keys is what the env records about its keys besides what agents report.
type Keys struct {
	// Revoked are the keys an admin revoked, by fingerprint.
	Revoked map[string]store.RevokedKey
	// Escrow lists, by fingerprint, the agents that escrowed a copy of
	// each key; a key with no escrowed copy is absent.
	Escrow map[string][]string
	// Usage holds each agent's latest count of key references, by agent
	// ID. It is nil where it was not read: check-ins plan without it, and
	// every key then counts as uncounted.
	Usage map[string]store.KeyUsage
}

// Usable reports whether a key may be the env key, count as held and be
// restored: it is not revoked, and its NotBefore is not after now plus
// FutureSkew.
func Usable(k store.KeyRef, revoked map[string]store.RevokedKey, now time.Time) bool {
	_, isRevoked := revoked[k.Fingerprint]
	return !isRevoked && !FutureDated(k, now)
}

// FutureDated reports whether a key's NotBefore is more than FutureSkew
// ahead of now.
func FutureDated(k store.KeyRef, now time.Time) bool {
	return k.NotBefore.After(now.Add(FutureSkew))
}

// Fleet is the env's view of its agents.
type Fleet struct {
	Env string `json:"env"`
	// EnvKey is the newest key every in-scope cluster holds, nil when there
	// is none.
	EnvKey *store.KeyRef `json:"env_key"`
	// KeysInSync is true when an env key exists.
	KeysInSync bool `json:"keys_in_sync"`
	// NoUsableKey is set when there is no env key although no cluster is
	// missing a key: every key the clusters share is revoked or dated in
	// the future, so sealing needs a new key.
	NoUsableKey bool `json:"no_usable_key"`
	// KeyLimit is how many keys of a cluster are kept track of
	// (protocol.MaxKeys).
	KeyLimit int `json:"key_limit"`
	// Keys are the keys clusters report and the revoked keys, newest
	// first.
	Keys   []Key   `json:"keys"`
	Agents []Agent `json:"agents"`
}

// Key is one of the env's sealing keys.
type Key struct {
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	// Holders are the agents whose clusters report the key.
	Holders []string `json:"holders"`
	// EscrowCopies is how many escrowed copies the key has.
	EscrowCopies int  `json:"escrow_copies"`
	EnvKey       bool `json:"env_key"`
	// Status is store.KeyActive, store.KeyRevoked or store.KeyDeleted,
	// with who revoked it and when, and for a deleted key who deleted it,
	// when, and when its escrowed copies are purged (Purged once that has
	// passed: it cannot be reinstated).
	Status    string     `json:"status"`
	RevokedBy string     `json:"revoked_by,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	DeletedBy string     `json:"deleted_by,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
	PurgeAt   *time.Time `json:"purge_at,omitempty"`
	Purged    bool       `json:"purged"`
	// FutureDated marks a key valid only from more than FutureSkew ahead;
	// it is not used or restored until then.
	FutureDated bool `json:"future_dated"`
	// References are the values sealed with the key, as clusters counted
	// them.
	References KeyReferences `json:"references"`
	// Deletable says whether an admin may delete the key now: only a
	// revoked key that no in-scope cluster has values sealed with, by
	// counts every one of them made since it was revoked. DeleteBlocked
	// says why not, in one sentence, on every key that is not deletable.
	Deletable     bool   `json:"deletable"`
	DeleteBlocked string `json:"delete_blocked,omitempty"`
}

// KeyReferences are the values sealed with one key, summed over the
// in-scope clusters that counted them.
type KeyReferences struct {
	Values        int `json:"values"`
	SealedSecrets int `json:"sealed_secrets"`
	// Clusters has one entry per in-scope cluster that counted, those
	// counting none included.
	Clusters []ClusterReferences `json:"clusters"`
	// Uncounted are the in-scope agents whose clusters did not count: no
	// cleanup capability, never counted, a failed count, or a count older
	// than UsageFresh.
	Uncounted []string `json:"uncounted"`
}

// ClusterReferences are one cluster's values sealed with a key.
type ClusterReferences struct {
	Agent         string    `json:"agent"`
	Cluster       string    `json:"cluster"`
	Values        int       `json:"values"`
	SealedSecrets int       `json:"sealed_secrets"`
	CountedAt     time.Time `json:"counted_at"`
}

// KeyUsage is an agent's latest count of its cluster's SealedSecrets.
type KeyUsage struct {
	// CountedAt is when the control plane received the count.
	CountedAt time.Time `json:"counted_at"`
	// Namespaces are those the controller watches; nil for every one.
	Namespaces    []string `json:"namespaces"`
	SealedSecrets int      `json:"sealed_secrets"`
	Values        int      `json:"values"`
	Unmatched     int      `json:"unmatched"`
	Error         string   `json:"error,omitempty"`
}

// Agent is one registered agent and what is known about it.
type Agent struct {
	ID                     string   `json:"id"`
	Cluster                string   `json:"cluster"`
	Region                 string   `json:"region"`
	RegisteredCapabilities []string `json:"registered_capabilities"`

	CheckedIn    bool                 `json:"checked_in"`
	Healthy      bool                 `json:"healthy"`
	InScope      bool                 `json:"in_scope"`
	LastCheckIn  *time.Time           `json:"last_checkin,omitempty"`
	AgentVersion string               `json:"agent_version,omitempty"`
	Capabilities []string             `json:"capabilities,omitempty"`
	Commands     []string             `json:"commands,omitempty"`
	Controller   *protocol.Controller `json:"controller,omitempty"`
	Keys         []store.KeyRef       `json:"keys,omitempty"`
	KeysComplete bool                 `json:"keys_complete"`
	// KeysReported is how many keys the agent reported; KeysDropped how
	// many of them, the oldest, were left out over the key limit.
	KeysReported int `json:"keys_reported"`
	KeysDropped  int `json:"keys_dropped"`
	// MissingKeys lists keys other in-scope clusters hold that this one does
	// not.
	MissingKeys []string `json:"missing_keys,omitempty"`
	// Joining is set while the cluster, new or rebuilt, is left out of the
	// env key because restore will give it the env's keys (JoinWindow).
	// JoinedAt is when it joined; nil for agents seen before it was
	// recorded.
	Joining  bool       `json:"joining"`
	JoinedAt *time.Time `json:"joined_at,omitempty"`
	// KeyUsage is the agent's latest count of key references; nil when it
	// has never reported one.
	KeyUsage *KeyUsage `json:"key_usage,omitempty"`
	Issues   []string  `json:"issues,omitempty"`

	// canRestore is set when the agent may be sent keys.restore.v1,
	// reports its whole key set and knows its controller orders keys by
	// NotBefore, as the agent requires to restore; orderUnknown when that
	// order alone keeps it from restoring. droppedUpTo is the newest
	// NotBefore of the usable keys left out of its report. canCount is set
	// when it is registered for and reports the cleanup capability, and
	// usage is its latest count.
	canRestore   bool
	orderUnknown bool
	droppedUpTo  *time.Time
	canCount     bool
	usage        *store.KeyUsage
}

// CanRestore reports whether the agent can restore keys into its cluster:
// it may be sent keys.restore.v1, reports its whole key set, and knows its
// controller orders keys by NotBefore.
func (a Agent) CanRestore() bool { return a.canRestore }

// Compute builds the env's fleet view at now.
//
// In-scope clusters are registered agents that have checked in at least
// once, whose controllers order keys by NotBefore. A cluster that is down
// stays in scope with its last key set, because it must still decrypt what
// is sealed now. A cluster that is joining is in scope but left out of the
// env key. Revoked and future-dated keys are never the env key, never
// count as held and are never missing.
func Compute(env string, reg *registry.Registry, states map[string]store.AgentState, keys Keys, now time.Time) Fleet {
	f := Fleet{Env: env, KeyLimit: protocol.MaxKeys}
	usable := func(k store.KeyRef) bool { return Usable(k, keys.Revoked, now) }

	for _, ra := range reg.Agents {
		a := Agent{
			ID:                     ra.ID,
			Cluster:                ra.Cluster,
			Region:                 ra.Region,
			RegisteredCapabilities: ra.Capabilities,
		}
		s, ok := states[ra.ID]
		if !ok {
			a.Issues = append(a.Issues, "has never checked in")
			f.Agents = append(f.Agents, a)
			continue
		}
		last := s.LastCheckIn
		ctrl := s.Controller
		a.CheckedIn = true
		a.LastCheckIn = &last
		a.Healthy = now.Sub(last) <= protocol.HealthWindow(s.CheckInInterval())
		a.AgentVersion = s.AgentVersion
		a.Capabilities = s.Capabilities
		a.Commands = s.Commands
		a.Controller = &ctrl
		a.Keys = s.Keys
		a.KeysComplete = s.KeysComplete
		a.KeysReported = max(s.KeysReported, len(s.Keys))
		a.KeysDropped = a.KeysReported - len(s.Keys)
		a.JoinedAt = s.JoinedAt
		a.droppedUpTo = s.DroppedUpTo
		keysOK := ra.HasCapability(protocol.CapabilityKeys) &&
			slices.Contains(s.Capabilities, protocol.CapabilityKeys) &&
			slices.Contains(s.Commands, protocol.CommandKeysRestore) &&
			s.KeysComplete
		// the agent refuses to restore unless it can tell the controller
		// orders keys by NotBefore; it reports "" when it cannot
		a.canRestore = keysOK && ctrl.KeyOrderPriority == orderCertNotBefore
		a.orderUnknown = keysOK && ctrl.KeyOrderPriority == ""
		a.canCount = ra.HasCapability(protocol.CapabilityCleanup) && slices.Contains(s.Capabilities, protocol.CapabilityCleanup)
		if u, ok := keys.Usage[ra.ID]; ok {
			a.usage = &u
			a.KeyUsage = usageView(u)
		}

		if !a.Healthy {
			a.Issues = append(a.Issues, "has not checked in recently")
		}
		if !s.KeysComplete {
			a.Issues = append(a.Issues, "reports only its controller's active key (no keys capability)")
		}
		if order := ctrl.KeyOrderPriority; order != "" && order != orderCertNotBefore {
			a.Issues = append(a.Issues, "controller orders keys by "+order+", not "+orderCertNotBefore+"; excluded from key comparison")
		} else {
			a.InScope = true
		}
		if a.orderUnknown {
			a.Issues = append(a.Issues, "key order unknown (set where the agent cannot read it, or its controller's Deployment could not be read); key restores into it are refused")
		}
		a.Issues = append(a.Issues, keyIssues(a, now)...)
		a.Issues = append(a.Issues, usageIssues(a)...)
		f.Agents = append(f.Agents, a)
	}

	markJoining(f.Agents, keys, usable, now)
	f.EnvKey = envKey(f.Agents, func(a *Agent) bool { return a.Joining }, usable)
	f.KeysInSync = f.EnvKey != nil
	markMissing(f.Agents, usable)
	f.NoUsableKey = f.EnvKey == nil && noUsableKey(f.Agents)
	explainHoldups(f.Agents, f.EnvKey, usable, now)
	f.Keys = keyList(f.Agents, f.EnvKey, keys, now)
	return f
}

// envKey returns the newest usable key every in-scope agent holds, leaving
// out those skip names; nil when there is none, or no agent to hold it.
// Keys made in the same second tie; the tie goes to the greater
// fingerprint, so the env key never depends on the order agents report in.
func envKey(agents []Agent, skip func(*Agent) bool, usable func(store.KeyRef) bool) *store.KeyRef {
	holders := map[string]int{}
	refs := map[string]store.KeyRef{}
	counted := 0
	for i := range agents {
		a := &agents[i]
		if !a.InScope || skip(a) {
			continue
		}
		counted++
		for _, k := range a.Keys {
			if !usable(k) {
				continue
			}
			holders[k.Fingerprint]++
			if prev, ok := refs[k.Fingerprint]; !ok || k.NotBefore.After(prev.NotBefore) {
				refs[k.Fingerprint] = k
			}
		}
	}
	if counted == 0 {
		return nil
	}
	var best *store.KeyRef
	for fp, n := range holders {
		if k := refs[fp]; n == counted && newer(&k, best) {
			best = &k
		}
	}
	return best
}

// newer reports whether key a comes before key b as the env key: a later
// NotBefore, or the same and a greater fingerprint. Any key is newer than
// none.
func newer(a, b *store.KeyRef) bool {
	return b == nil || a.NotBefore.After(b.NotBefore) ||
		(a.NotBefore.Equal(b.NotBefore) && a.Fingerprint > b.Fingerprint)
}

// noUsableKey reports whether in-scope clusters report keys and none is
// missing one: with no env key, every key they share is then revoked or
// dated in the future.
func noUsableKey(agents []Agent) bool {
	reported := false
	for _, a := range agents {
		if !a.InScope {
			continue
		}
		if len(a.MissingKeys) > 0 {
			return false
		}
		reported = reported || len(a.Keys) > 0
	}
	return reported
}

// joinCandidate reports whether an agent may be left out of the env key
// while it catches up: it joined within JoinWindow and can restore keys.
func joinCandidate(a *Agent, now time.Time) bool {
	return a.InScope && a.canRestore && a.JoinedAt != nil && now.Sub(*a.JoinedAt) < JoinWindow
}

// markJoining marks the clusters left out of the env key while they catch
// up: those that joined within JoinWindow, can restore keys, and lack the
// newest key every other cluster holds, when that key is escrowed (so
// restore will give it to them). The first clusters of an env have no one
// to catch up with, so they are never joining.
func markJoining(agents []Agent, keys Keys, usable func(store.KeyRef) bool, now time.Time) {
	others := envKey(agents, func(a *Agent) bool { return joinCandidate(a, now) }, usable)
	if others == nil || len(keys.Escrow[others.Fingerprint]) == 0 {
		return
	}
	for i := range agents {
		a := &agents[i]
		if joinCandidate(a, now) && !holds(*a, others.Fingerprint) {
			a.Joining = true
			a.Issues = append(a.Issues, fmt.Sprintf(
				"joined %s ago; left out of the env key for up to %d minutes while it restores the env's keys",
				ago(now.Sub(*a.JoinedAt)), int(JoinWindow/time.Minute)))
		}
	}
}

// markMissing lists, for each in-scope agent, the usable keys other
// in-scope clusters hold that it does not, leaving out keys that may be
// among those dropped from its report over the key limit.
func markMissing(agents []Agent, usable func(store.KeyRef) bool) {
	held := map[string]store.KeyRef{}
	for _, a := range agents {
		if !a.InScope {
			continue
		}
		for _, k := range a.Keys {
			if usable(k) {
				held[k.Fingerprint] = k
			}
		}
	}
	for i := range agents {
		a := &agents[i]
		if !a.InScope {
			continue
		}
		for fp, k := range held {
			if holds(*a, fp) || (a.droppedUpTo != nil && !k.NotBefore.After(*a.droppedUpTo)) {
				continue
			}
			a.MissingKeys = append(a.MissingKeys, fp)
		}
		sort.Strings(a.MissingKeys)
	}
}

// explainHoldups says why a cluster that joined, and is not left out of the
// env key, holds it back: it lacks the newest key every other cluster
// holds, made before it joined.
func explainHoldups(agents []Agent, current *store.KeyRef, usable func(store.KeyRef) bool, now time.Time) {
	for i := range agents {
		a := &agents[i]
		if !a.InScope || a.Joining || a.JoinedAt == nil || len(a.MissingKeys) == 0 {
			continue
		}
		// only a key made before the cluster joined is one it should have
		// caught up on; a key made since is likely its own, which the
		// others lack
		others := envKey(agents, func(b *Agent) bool { return b.Joining || b.ID == a.ID }, usable)
		if others == nil || holds(*a, others.Fingerprint) || !newer(others, current) || !others.NotBefore.Before(*a.JoinedAt) {
			continue
		}
		since := now.Sub(*a.JoinedAt)
		switch {
		case since >= JoinWindow:
			a.Issues = append(a.Issues, fmt.Sprintf(
				"joined %s ago and still lacks the key every other cluster holds, so it holds back the env key; check its key restores", ago(since)))
		case !a.canRestore:
			why := "it needs the keys capability"
			if a.orderUnknown {
				why = "its key order is unknown"
			}
			a.Issues = append(a.Issues, "joined "+ago(since)+" ago and cannot restore the env's keys ("+why+"), so it holds back the env key")
		default:
			a.Issues = append(a.Issues, "joined "+ago(since)+" ago; the key every other cluster holds has no escrowed copy yet, so it holds back the env key")
		}
	}
}

// keyIssues describes problems with an agent's key report: future-dated
// keys, and how close it is to the key limit.
func keyIssues(a Agent, now time.Time) []string {
	var out []string
	for _, k := range a.Keys {
		if FutureDated(k, now) {
			out = append(out, fmt.Sprintf("reports key %s valid only from %s; it is not used until then",
				k.Fingerprint, k.NotBefore.Format(time.RFC3339)))
		}
	}
	limit := protocol.MaxKeys
	switch n := a.KeysReported; {
	case a.KeysDropped > 0:
		out = append(out, fmt.Sprintf("reports %d keys, more than the %d kept; the %d oldest are left out of key sync", n, limit, a.KeysDropped))
	case n*5 >= limit*4:
		out = append(out, fmt.Sprintf("reports %d keys, %d%% of the %d kept per cluster", n, n*100/limit, limit))
	case n*2 >= limit:
		out = append(out, fmt.Sprintf("reports %d keys, over half of the %d kept per cluster", n, limit))
	}
	return out
}

// keyList lists every key a checked-in cluster reports and every revoked
// key, newest first, with what the clusters counted of each. A deleted key
// is left out once no cluster reports it and its escrowed copies are
// purged: it can neither come back nor need removing.
func keyList(agents []Agent, env *store.KeyRef, keys Keys, now time.Time) []Key {
	byFP := map[string]*Key{}
	entry := func(fp string, notBefore, notAfter time.Time) *Key {
		k, ok := byFP[fp]
		if !ok {
			k = &Key{Fingerprint: fp, NotBefore: notBefore, NotAfter: notAfter, Holders: []string{}, Status: store.KeyActive}
			byFP[fp] = k
		}
		return k
	}
	for _, a := range agents {
		for _, ref := range a.Keys {
			k := entry(ref.Fingerprint, ref.NotBefore, ref.NotAfter)
			k.Holders = append(k.Holders, a.ID)
		}
	}
	for fp, r := range keys.Revoked {
		if _, held := byFP[fp]; !held && r.Purged(now) {
			continue
		}
		k := entry(fp, r.NotBefore, r.NotAfter)
		at := r.At
		k.Status, k.RevokedBy, k.RevokedAt = store.KeyRevoked, r.By, &at
		if r.Deleted() {
			k.Status, k.DeletedBy, k.DeletedAt, k.PurgeAt, k.Purged = store.KeyDeleted, r.DeletedBy, r.DeletedAt, r.PurgeAt, r.Purged(now)
		}
	}
	out := make([]Key, 0, len(byFP))
	for _, k := range byFP {
		k.EscrowCopies = len(keys.Escrow[k.Fingerprint])
		k.EnvKey = env != nil && env.Fingerprint == k.Fingerprint
		k.FutureDated = FutureDated(store.KeyRef{NotBefore: k.NotBefore}, now)
		k.References = references(agents, k.Fingerprint, now)
		switch k.Status {
		case store.KeyActive:
			k.DeleteBlocked = BlockedActive
		case store.KeyDeleted:
			k.DeleteBlocked = BlockedDeleted
		default:
			k.DeleteBlocked = deleteBlocked(agents, k.References, keys.Revoked[k.Fingerprint], now)
			k.Deletable = k.DeleteBlocked == ""
		}
		out = append(out, *k)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NotBefore.Equal(out[j].NotBefore) {
			return out[i].NotBefore.After(out[j].NotBefore)
		}
		return out[i].Fingerprint > out[j].Fingerprint
	})
	return out
}

// counted reports whether an agent's latest count of key references
// counts at now: it may count (the cleanup capability), and its latest
// count succeeded and came in within UsageFresh.
func counted(a Agent, now time.Time) bool {
	return a.canCount && a.usage != nil && a.usage.Error == "" && now.Sub(a.usage.CountedAt) <= UsageFresh
}

// references sums what the in-scope clusters (every agent that has checked
// in, down or not) counted of a key, and names those that did not count.
func references(agents []Agent, fp string, now time.Time) KeyReferences {
	refs := KeyReferences{Clusters: []ClusterReferences{}, Uncounted: []string{}}
	for _, a := range agents {
		switch {
		case !a.CheckedIn:
		case !counted(a, now):
			refs.Uncounted = append(refs.Uncounted, a.ID)
		default:
			use := a.usage.Keys[fp]
			refs.Values += use.Values
			refs.SealedSecrets += use.SealedSecrets
			refs.Clusters = append(refs.Clusters, ClusterReferences{
				Agent: a.ID, Cluster: a.Cluster, Values: use.Values, SealedSecrets: use.SealedSecrets, CountedAt: a.usage.CountedAt,
			})
		}
	}
	return refs
}

// deleteBlocked says, in one sentence, why a revoked key may not be
// deleted at now, or returns "" when it may. A key any counted value is
// sealed with is never deleted. Every in-scope cluster must also have
// counted the values its SealedSecrets hold since the key was revoked (so
// no new value can be sealed with it), within UsageFresh, and found none
// sealed with the key.
func deleteBlocked(agents []Agent, refs KeyReferences, r store.RevokedKey, now time.Time) string {
	if refs.Values > 0 {
		var where []string
		for _, c := range refs.Clusters {
			if c.Values > 0 {
				where = append(where, c.Agent)
			}
		}
		return fmt.Sprintf("%s in %s %s it (%s).",
			count(refs.Values, "value"), count(refs.SealedSecrets, "SealedSecret"), plural(refs.Values, "uses", "use"), strings.Join(where, ", "))
	}
	var scoped, noCleanup, failed, waiting []string
	for _, a := range agents {
		if !a.CheckedIn {
			continue
		}
		scoped = append(scoped, a.ID)
		switch {
		case !a.canCount:
			noCleanup = append(noCleanup, a.ID)
		case a.usage != nil && a.usage.Error != "":
			failed = append(failed, a.ID)
		case a.usage == nil || now.Sub(a.usage.CountedAt) > UsageFresh || !a.usage.CountedAt.After(r.At):
			waiting = append(waiting, a.ID)
		}
	}
	switch {
	case len(scoped) == 0:
		return "No cluster has checked in, so none has counted the values sealed with it."
	case len(noCleanup) > 0:
		return fmt.Sprintf("%s cannot count the values sealed with it: %s the cleanup capability.",
			list(noCleanup), plural(len(noCleanup), "it needs", "they need"))
	case len(failed) > 0:
		return fmt.Sprintf("The last count of the values sealed with it failed in %s.", list(failed))
	case len(waiting) > 0:
		return fmt.Sprintf("Waiting for %s to count the values sealed with it since it was revoked; clusters count every few minutes.", list(waiting))
	}
	return ""
}

// usageView is what the fleet view shows of an agent's count.
func usageView(u store.KeyUsage) *KeyUsage {
	v := &KeyUsage{
		CountedAt: u.CountedAt, SealedSecrets: u.SealedSecrets, Values: u.Values, Unmatched: u.Unmatched, Error: u.Error,
	}
	if len(u.Namespaces) > 0 {
		v.Namespaces = u.Namespaces
	}
	return v
}

// usageIssues describes problems an agent's count of key references found:
// values none of its cluster's keys decrypts, or a count that failed.
func usageIssues(a Agent) []string {
	u := a.usage
	switch {
	case u == nil:
		return nil
	case u.Error != "" && a.canCount:
		return []string{"its last count of the values sealed with each key failed: " + u.Error}
	case u.Error == "" && u.Unmatched > 0:
		return []string{fmt.Sprintf("%s in this cluster's SealedSecrets %s none of its keys: the controller cannot decrypt them",
			count(u.Unmatched, "value"), plural(u.Unmatched, "matches", "match"))}
	}
	return nil
}

// count is n and a noun, plural unless n is 1.
func count(n int, noun string) string {
	return fmt.Sprintf("%d %s", n, plural(n, noun, noun+"s"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// list joins names for a sentence: "a", "a and b", "a, b and c".
func list(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// Key returns the key fp in the fleet view.
func (f Fleet) Key(fp string) (Key, bool) {
	for _, k := range f.Keys {
		if k.Fingerprint == fp {
			return k, true
		}
	}
	return Key{}, false
}

// holds reports whether an agent's cluster reports a key.
func holds(a Agent, fp string) bool {
	return slices.ContainsFunc(a.Keys, func(k store.KeyRef) bool { return k.Fingerprint == fp })
}

// ago is a duration for people, in whole minutes or hours.
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < 2*time.Minute:
		return "1 minute"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	default:
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	}
}
