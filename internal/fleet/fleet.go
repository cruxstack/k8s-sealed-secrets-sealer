// Package fleet computes the env's view of its agents from the registry and
// their latest check-ins: which agents are healthy, which key every cluster
// holds (the env key), and which clusters are missing keys. It is pure: no
// I/O, so the rules in docs/design.md section 7 are tested directly.
package fleet

import (
	"sort"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Timing shared by agents and the control plane.
const (
	CheckInInterval = 15 * time.Second
	// HealthyWithin is how recent an agent's last check-in must be for it to
	// count as healthy: three missed check-ins make it unhealthy.
	HealthyWithin = 3 * CheckInInterval
)

// orderCertNotBefore is the controller's default key order and the only one
// under which a restored key keeps its place.
const orderCertNotBefore = "CertNotBefore"

// Fleet is the env's view of its agents.
type Fleet struct {
	Env string `json:"env"`
	// EnvKey is the newest key every in-scope cluster holds, nil when there
	// is none.
	EnvKey *store.KeyRef `json:"env_key"`
	// KeysInSync is true when an env key exists.
	KeysInSync bool    `json:"keys_in_sync"`
	Agents     []Agent `json:"agents"`
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
	Controller   *protocol.Controller `json:"controller,omitempty"`
	Keys         []store.KeyRef       `json:"keys,omitempty"`
	KeysComplete bool                 `json:"keys_complete"`
	// MissingKeys lists keys other in-scope clusters hold that this one does
	// not.
	MissingKeys []string `json:"missing_keys,omitempty"`
	Issues      []string `json:"issues,omitempty"`
}

// Compute builds the env's fleet view at now.
//
// In-scope clusters are registered agents that have checked in at least
// once, whose controllers order keys by NotBefore. A cluster that is down
// stays in scope with its last key set, because it must still decrypt what
// is sealed now.
func Compute(env string, reg *registry.Registry, states map[string]store.AgentState, now time.Time) Fleet {
	f := Fleet{Env: env}
	holders := map[string]int{}
	refs := map[string]store.KeyRef{}
	inScope := 0

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
		a.Healthy = now.Sub(last) <= HealthyWithin
		a.AgentVersion = s.AgentVersion
		a.Capabilities = s.Capabilities
		a.Controller = &ctrl
		a.Keys = s.Keys
		a.KeysComplete = s.KeysComplete

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
			inScope++
			for _, k := range s.Keys {
				holders[k.Fingerprint]++
				if prev, ok := refs[k.Fingerprint]; !ok || k.NotBefore.After(prev.NotBefore) {
					refs[k.Fingerprint] = k
				}
			}
		}
		f.Agents = append(f.Agents, a)
	}

	if inScope > 0 {
		for fp, n := range holders {
			if n != inScope {
				continue
			}
			k := refs[fp]
			if f.EnvKey == nil || k.NotBefore.After(f.EnvKey.NotBefore) ||
				(k.NotBefore.Equal(f.EnvKey.NotBefore) && k.Fingerprint > f.EnvKey.Fingerprint) {
				f.EnvKey = &k
			}
		}
	}
	f.KeysInSync = f.EnvKey != nil

	for i := range f.Agents {
		a := &f.Agents[i]
		if !a.InScope {
			continue
		}
		held := map[string]bool{}
		for _, k := range a.Keys {
			held[k.Fingerprint] = true
		}
		for fp := range holders {
			if !held[fp] {
				a.MissingKeys = append(a.MissingKeys, fp)
			}
		}
		sort.Strings(a.MissingKeys)
	}
	return f
}
