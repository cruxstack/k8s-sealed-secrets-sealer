package controlplane

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// applyKeyReport fills in what a check-in's state takes from the agent's
// previous state and the env's keys: the keys kept under the key limit and
// when the agent joined. It returns the key records of the kept keys.
func applyKeyReport(state *store.AgentState, records []store.KeyRecord, prev store.AgentState, seen bool, revoked map[string]store.RevokedKey, now time.Time) []store.KeyRecord {
	reported := state.Keys
	state.KeysReported = len(reported)
	state.Keys, state.DroppedUpTo = limitKeys(reported, revoked, protocol.MaxKeys)
	state.JoinedAt = joinedAt(prev, seen, *state, now)
	if len(state.Keys) == len(reported) {
		return records
	}
	kept := map[string]bool{}
	for _, k := range state.Keys {
		kept[k.Fingerprint] = true
	}
	return slices.DeleteFunc(records, func(r store.KeyRecord) bool { return !kept[r.Fingerprint] })
}

// limitKeys keeps the newest max keys of a report, by NotBefore, revoked
// keys last, so a growing key set degrades instead of failing the check-in.
// It returns them oldest first, as agents report them, with the newest
// NotBefore among the active keys left out (nil when none were): a key no
// newer than that may be held although it is not listed.
func limitKeys(keys []store.KeyRef, revoked map[string]store.RevokedKey, limit int) ([]store.KeyRef, *time.Time) {
	if len(keys) <= limit {
		return keys, nil
	}
	isRevoked := func(k store.KeyRef) bool { _, ok := revoked[k.Fingerprint]; return ok }
	sorted := slices.Clone(keys)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if ra, rb := isRevoked(a), isRevoked(b); ra != rb {
			return rb
		}
		if !a.NotBefore.Equal(b.NotBefore) {
			return a.NotBefore.After(b.NotBefore)
		}
		return a.Fingerprint > b.Fingerprint
	})
	var upTo *time.Time
	for _, k := range sorted[limit:] {
		if !isRevoked(k) && (upTo == nil || k.NotBefore.After(*upTo)) {
			nb := k.NotBefore
			upTo = &nb
		}
	}
	kept := sorted[:limit:limit]
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].NotBefore.Before(kept[j].NotBefore) })
	return kept, upTo
}

// joinedAt returns when an agent joined the env: at its first check-in, or
// when its cluster was rebuilt, which shows as a whole key set sharing no
// key with the previous one. Agents seen before this was recorded have no
// join time, so they are never taken for joining.
func joinedAt(prev store.AgentState, seen bool, state store.AgentState, now time.Time) *time.Time {
	switch {
	case !seen:
		return &now
	case prev.KeysComplete && state.KeysComplete && len(prev.Keys) > 0 &&
		!slices.ContainsFunc(prev.Keys, func(k store.KeyRef) bool { return containsKey(state.Keys, k.Fingerprint) }):
		return &now
	default:
		return prev.JoinedAt
	}
}

func containsKey(keys []store.KeyRef, fp string) bool {
	return slices.ContainsFunc(keys, func(k store.KeyRef) bool { return k.Fingerprint == fp })
}

// keyLimitStep is how close a key count is to the key limit: 0, 50 or 80
// (percent), or 100 once keys are left out.
func keyLimitStep(n int) int {
	switch limit := protocol.MaxKeys; {
	case n > limit:
		return 100
	case n*5 >= limit*4:
		return 80
	case n*2 >= limit:
		return 50
	}
	return 0
}

// logKeyReport writes the alert events a check-in's keys call for, once,
// at the check-in where each condition first shows for the agent: the key
// count reaching half or 80% of the limit or going over it, a key dated
// in the future, and a controller that does not order keys by NotBefore.
func (s *Server) logKeyReport(ctx context.Context, agent *registry.Agent, prev store.AgentState, seen bool, state store.AgentState, now time.Time) {
	base := []any{"env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster}
	before := 0
	if seen {
		before = keyLimitStep(max(prev.KeysReported, len(prev.Keys)))
	}
	switch step := keyLimitStep(state.KeysReported); {
	case step <= before:
	case step == 100:
		s.logger.ErrorContext(ctx, "cluster reports more sealing keys than are kept; the oldest are left out of key sync",
			append([]any{"event", "keys.truncated", "keys", state.KeysReported, "limit", protocol.MaxKeys,
				"dropped", state.KeysReported - len(state.Keys)}, base...)...)
	default:
		s.logger.WarnContext(ctx, "cluster's sealing keys near the limit",
			append([]any{"event", "keys.near_limit", "keys", state.KeysReported, "limit", protocol.MaxKeys, "percent", step}, base...)...)
	}

	for _, k := range state.Keys {
		if fleet.FutureDated(k, now) && (!seen || !containsKey(prev.Keys, k.Fingerprint)) {
			s.logger.WarnContext(ctx, "cluster reports a sealing key dated in the future; it is not used until then",
				append([]any{"event", "key.future_dated", "fingerprint", k.Fingerprint, "not_before", k.NotBefore}, base...)...)
		}
	}

	order := state.Controller.KeyOrderPriority
	if order != "" && order != "CertNotBefore" && (!seen || prev.Controller.KeyOrderPriority != order) {
		s.logger.WarnContext(ctx, "controller does not order keys by NotBefore; its cluster is left out of key comparison",
			append([]any{"event", "key.order_mismatch", "key_order_priority", order}, base...)...)
	}
}
