package fleet

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// ErrNoSealer means no agent can seal right now.
var ErrNoSealer = errors.New("no agent is available to seal: none is healthy, able to seal and holding the env key")

// ErrNoUsableKey means the clusters share keys but each is revoked or dated
// in the future, so nothing can be sealed until a new key reaches every
// cluster.
var ErrNoUsableKey = errors.New("no usable sealing key: every key the clusters share is revoked or dated in the future; a new key is needed")

// KeysOutOfSyncError means no key is held by every in-scope cluster, so
// nothing can be sealed until key sync closes the gap.
type KeysOutOfSyncError struct {
	// Clusters are the clusters missing keys other clusters hold.
	Clusters []string
}

func (e *KeysOutOfSyncError) Error() string {
	if len(e.Clusters) == 0 {
		return "keys out of sync: no cluster has reported a sealing key yet"
	}
	return "keys out of sync: " + strings.Join(e.Clusters, ", ") + " not yet holding every key; key sync normally closes the gap within a few check-ins"
}

// ChooseSealer picks the agent for a seal (docs/design.md, section 7).
// Candidates are healthy agents registered and reporting the seal capability,
// handling seal.v1, and holding the env key. Agents in one of regions come
// first, then those with the fewest commands in flight, then the most
// recent check-in; ties go to the lowest ID, so the choice is stable.
func ChooseSealer(f Fleet, regions []string, inFlight map[string]int) (Agent, error) {
	if f.EnvKey == nil {
		if f.NoUsableKey {
			return Agent{}, ErrNoUsableKey
		}
		var missing []string
		for _, a := range f.Agents {
			if a.InScope && len(a.MissingKeys) > 0 {
				missing = append(missing, a.Cluster)
			}
		}
		sort.Strings(missing)
		return Agent{}, &KeysOutOfSyncError{Clusters: missing}
	}
	var candidates []Agent
	for _, a := range f.Agents {
		if canSeal(a, f.EnvKey.Fingerprint) {
			candidates = append(candidates, a)
		}
	}
	if len(candidates) == 0 {
		return Agent{}, ErrNoSealer
	}
	preferred := func(a Agent) bool { return slices.Contains(regions, a.Region) }
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if pa, pb := preferred(a), preferred(b); pa != pb {
			return pa
		}
		if inFlight[a.ID] != inFlight[b.ID] {
			return inFlight[a.ID] < inFlight[b.ID]
		}
		if !a.LastCheckIn.Equal(*b.LastCheckIn) {
			return a.LastCheckIn.After(*b.LastCheckIn)
		}
		return a.ID < b.ID
	})
	return candidates[0], nil
}

// canSeal reports whether an agent can seal with the env key now.
func canSeal(a Agent, envKey string) bool {
	if !a.Healthy || a.LastCheckIn == nil ||
		!slices.Contains(a.RegisteredCapabilities, protocol.CapabilitySeal) ||
		!slices.Contains(a.Capabilities, protocol.CapabilitySeal) ||
		!slices.Contains(a.Commands, protocol.CommandSeal) {
		return false
	}
	for _, k := range a.Keys {
		if k.Fingerprint == envKey {
			return true
		}
	}
	return false
}

// Name is how an agent is named to users: its cluster and region.
func (a Agent) Name() string {
	if a.Region == "" {
		return a.Cluster
	}
	return fmt.Sprintf("%s (%s)", a.Cluster, a.Region)
}
