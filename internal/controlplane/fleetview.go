package controlplane

import (
	"context"
	"slices"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// fleetSnapshot is what the fleet is computed from: the registry in force,
// every registered agent's latest state, and the revoked and reinstated
// keys.
type fleetSnapshot struct {
	reg        *registry.Registry
	states     map[string]store.AgentState
	revoked    map[string]store.RevokedKey
	reinstated map[string]store.ReinstatedKey
}

// readSnapshot reads every registered agent's state and the revoked and
// reinstated keys.
// Check-ins read them afresh: renewal and restore decisions rest on the
// other agents' latest states, and a check-in that planned from older ones
// could turn renewal on in a second cluster.
func (s *Server) readSnapshot(ctx context.Context) (fleetSnapshot, error) {
	reg := s.currentRegistry()
	ids := make([]string, 0, len(reg.Agents))
	for _, a := range reg.Agents {
		ids = append(ids, a.ID)
	}
	states, err := s.store.GetAgentStates(ctx, ids)
	if err != nil {
		return fleetSnapshot{}, err
	}
	lists, err := s.store.KeyLists(ctx)
	if err != nil {
		return fleetSnapshot{}, err
	}
	return fleetSnapshot{reg: reg, states: states, revoked: lists.Revoked, reinstated: lists.Reinstated}, nil
}

// loadFleet reads the fleet afresh and computes it at now. With usage it
// also reads every agent's latest count of key references, with one
// batch read, for the key references and the delete gate; check-ins and
// the sealing status do without.
func (s *Server) loadFleet(ctx context.Context, now time.Time, usage bool) (fleet.Fleet, error) {
	snap, err := s.readSnapshot(ctx)
	if err != nil {
		return fleet.Fleet{}, err
	}
	keys, err := s.fleetKeys(ctx, snap, nil)
	if err != nil {
		return fleet.Fleet{}, err
	}
	if usage {
		ids := make([]string, 0, len(snap.reg.Agents))
		for _, a := range snap.reg.Agents {
			ids = append(ids, a.ID)
		}
		if keys.Usage, err = s.store.KeyUsages(ctx, ids); err != nil {
			return fleet.Fleet{}, err
		}
	}
	return fleet.Compute(s.env, snap.reg, snap.states, keys, now), nil
}

// fleetKeys returns what the env records about the keys in a snapshot. For
// a check-in, self is the checking agent, whose keys are read again where
// it may still add an escrowed copy.
func (s *Server) fleetKeys(ctx context.Context, snap fleetSnapshot, self *store.AgentState) (fleet.Keys, error) {
	var fps []string
	for _, st := range snap.states {
		for _, k := range st.Keys {
			fps = append(fps, k.Fingerprint)
		}
	}
	// a reinstated key may be in no cluster, and is restored from escrow
	for fp := range snap.reinstated {
		fps = append(fps, fp)
	}
	escrow, err := s.escrowUploaders(ctx, fps, self)
	if err != nil {
		return fleet.Keys{}, err
	}
	return fleet.Keys{Revoked: snap.revoked, Escrow: escrow, Reinstated: snap.reinstated}, nil
}

// escrowUploaders returns who escrowed each key. Escrow records are removed
// only when a deleted key's copies are purged, and such a key is never
// escrowed, restored or reinstated again, so what is known is cached. A key
// is read again only while self holds it and may still add its copy.
func (s *Server) escrowUploaders(ctx context.Context, fps []string, self *store.AgentState) (map[string][]string, error) {
	out := map[string][]string{}
	var read []string
	queued := map[string]bool{}
	readAgain := func(fp string) {
		if !queued[fp] {
			queued[fp] = true
			read = append(read, fp)
		}
	}
	s.knownMu.Lock()
	for _, fp := range fps {
		if up, ok := s.knownEscrow[fp]; ok {
			out[fp] = up
		} else {
			readAgain(fp)
		}
	}
	if self != nil {
		for _, k := range self.Keys {
			up, ok := s.knownEscrow[k.Fingerprint]
			if ok && !slices.Contains(up, self.AgentID) && len(up) < maxEscrowCopies {
				readAgain(k.Fingerprint)
			}
		}
	}
	s.knownMu.Unlock()
	if len(read) == 0 {
		return out, nil
	}
	found, err := s.store.EscrowUploaders(ctx, read)
	if err != nil {
		return nil, err
	}
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if len(s.knownEscrow) > 10_000 {
		s.knownEscrow = map[string][]string{}
	}
	for fp, up := range found {
		out[fp] = up
		s.knownEscrow[fp] = up
	}
	return out, nil
}

// markEscrowed adds an uploader to a key's cached uploaders. A key not
// cached yet is left to be read, so the cache never holds a partial list
// for a key it has not read.
func (s *Server) markEscrowed(fp, agentID string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if up, ok := s.knownEscrow[fp]; ok && !slices.Contains(up, agentID) {
		s.knownEscrow[fp] = append(slices.Clone(up), agentID)
	}
}
