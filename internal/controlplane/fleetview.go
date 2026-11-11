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
	keys, err := s.fleetKeys(ctx, snap, nil, usage)
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
// it may still add an escrowed copy. With revoked, the escrowed copies of
// revoked keys no cluster holds are read too, for the fleet view: a
// deleted key's are what reinstating it restores from until its purge.
func (s *Server) fleetKeys(ctx context.Context, snap fleetSnapshot, self *store.AgentState, revoked bool) (fleet.Keys, error) {
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
	if revoked {
		now := s.now()
		for fp, r := range snap.revoked {
			if !r.Purged(now) {
				fps = append(fps, fp)
			}
		}
	}
	escrow, err := s.escrowUploaders(ctx, fps, self)
	if err != nil {
		return fleet.Keys{}, err
	}
	return fleet.Keys{Revoked: snap.revoked, Escrow: escrow, Reinstated: snap.reinstated}, nil
}

// escrowCacheTTL is how long who escrowed a key is cached. Copies are only
// added, except that a deleted key's are purged; a deletion a cluster then
// contradicts makes the key revoked again, and once reinstated it must be
// escrowed afresh, so no instance trusts its cache of it for long.
const escrowCacheTTL = 10 * time.Minute

// knownCopies is who escrowed a key, as read at a time.
type knownCopies struct {
	uploaders []string
	at        time.Time
}

// escrowUploaders returns who escrowed each key, cached for escrowCacheTTL.
// A key is read again sooner only while self holds it and may still add its
// copy.
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
	now := s.now()
	s.knownMu.Lock()
	for _, fp := range fps {
		if k, ok := s.knownEscrow[fp]; ok && now.Sub(k.at) < escrowCacheTTL {
			out[fp] = k.uploaders
		} else {
			readAgain(fp)
		}
	}
	if self != nil {
		for _, k := range self.Keys {
			known, ok := s.knownEscrow[k.Fingerprint]
			if ok && !slices.Contains(known.uploaders, self.AgentID) && len(known.uploaders) < maxEscrowCopies {
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
		s.knownEscrow = map[string]knownCopies{}
	}
	for _, fp := range read {
		// a key with no copy is read again each time, as before
		delete(s.knownEscrow, fp)
	}
	for fp, up := range found {
		out[fp] = up
		s.knownEscrow[fp] = knownCopies{uploaders: up, at: now}
	}
	return out, nil
}

// forgetEscrow drops what is cached of a key's copies.
func (s *Server) forgetEscrow(fp string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	delete(s.knownEscrow, fp)
}

// markEscrowed adds an uploader to a key's cached uploaders. A key not
// cached yet is left to be read, so the cache never holds a partial list
// for a key it has not read.
func (s *Server) markEscrowed(fp, agentID string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if k, ok := s.knownEscrow[fp]; ok && !slices.Contains(k.uploaders, agentID) {
		s.knownEscrow[fp] = knownCopies{uploaders: append(slices.Clone(k.uploaders), agentID), at: k.at}
	}
}
