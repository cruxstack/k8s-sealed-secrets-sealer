package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Key command timing.
const (
	// keyCommandTTL is how long a key command waits to be leased and run.
	keyCommandTTL = 10 * time.Minute
	// settleAfterSuccess holds off re-issuing work a command just did,
	// until the agent's next inventory shows it.
	settleAfterSuccess = 2 * time.Minute
	// retryAfterFailure holds off re-issuing work a command failed to do.
	retryAfterFailure = 5 * time.Minute
	// keyCommandLookback is how far back key sync reads an agent's
	// commands: a key command finishes within keyCommandTTL and holds off
	// its work for up to retryAfterFailure after, and a minute covers
	// clocks that differ between instances.
	keyCommandLookback = keyCommandTTL + max(settleAfterSuccess, retryAfterFailure) + time.Minute
	// maxCopiesPerCheckIn bounds the further copies of already escrowed
	// keys one check-in asks an agent for; keys with no copy are not held
	// back.
	maxCopiesPerCheckIn = 20
	// presentHold holds off restoring a key that a restore found already in
	// the cluster while the agent still does not report it: held under
	// another label (relabeled as compromised, say), or not loaded by its
	// controller, which the agent retries on its own. Restoring it again
	// would change nothing.
	presentHold = time.Hour
	// presentLookback is how far back key sync reads an agent's commands to
	// find such restores. It is read only when a restore is due.
	presentLookback = keyCommandTTL + presentHold + time.Minute
)

// keySyncPlan is what one agent's check-in leads to.
type keySyncPlan struct {
	// EscrowNeeded lists the agent's keys it should escrow a copy of.
	EscrowNeeded []string
	// Restore lists escrowed keys the agent's cluster is missing, newest
	// first; empty queues nothing.
	Restore []string
	// EnableRenewal queues renewal.enable.v1 for the agent.
	EnableRenewal bool
}

// planKeySync decides, for the agent that just checked in, which of its keys
// need escrow, which escrowed keys it should restore, and whether it should
// turn on key renewal. It is pure, so the rules are tested directly.
//
// An agent escrows a copy of each key it holds until the key has
// maxEscrowCopies copies, so a bad copy uploaded first is not the only one.
// Revoked and future-dated keys are neither escrowed nor restored.
//
// Every decision is about the checking-in agent only, and each agent checks
// in serially, so concurrent check-ins from different agents cannot queue
// the same command twice.
func planKeySync(f fleet.Fleet, self *registry.Agent, state store.AgentState, firstCheckIn bool, commands []store.CommandRecord, keys fleet.Keys, now time.Time) keySyncPlan {
	var plan keySyncPlan
	if !canRun(self, state, protocol.CommandKeysRestore) {
		// without the keys capability the agent can neither upload nor
		// restore; it may not even see its whole key set
		return planRenewal(plan, f, self, state, firstCheckIn, commands, now)
	}
	copies := 0
	for _, k := range state.Keys {
		up := keys.Escrow[k.Fingerprint]
		switch {
		case !fleet.Usable(k, keys.Revoked, now) || slices.Contains(up, self.ID) || len(up) >= maxEscrowCopies:
		case len(up) == 0:
			plan.EscrowNeeded = append(plan.EscrowNeeded, k.Fingerprint)
		case copies < maxCopiesPerCheckIn:
			// further copies of keys already escrowed can wait, so an agent
			// holding many is not kept busy uploading them all at once
			copies++
			plan.EscrowNeeded = append(plan.EscrowNeeded, k.Fingerprint)
		}
	}

	var me *fleet.Agent
	for i := range f.Agents {
		if f.Agents[i].ID == self.ID {
			me = &f.Agents[i]
		}
	}
	if me != nil && me.InScope && state.KeysComplete {
		busy := busyFingerprints(commands, now)
		for _, fp := range me.MissingKeys {
			if len(keys.Escrow[fp]) > 0 && !busy[fp] {
				plan.Restore = append(plan.Restore, fp)
			}
		}
		// the newest first, so a long list restores the env key early
		notBefore := map[string]time.Time{}
		for _, k := range f.Keys {
			notBefore[k.Fingerprint] = k.NotBefore
		}
		sort.SliceStable(plan.Restore, func(i, j int) bool {
			return notBefore[plan.Restore[i]].After(notBefore[plan.Restore[j]])
		})
		if len(plan.Restore) > protocol.MaxRestoreKeys {
			plan.Restore = plan.Restore[:protocol.MaxRestoreKeys]
		}
	}
	return planRenewal(plan, f, self, state, firstCheckIn, commands, now)
}

// planRenewal turns renewal on in one cluster when no in-scope cluster has it
// on. The cluster is chosen deterministically: the healthy, in-scope agent
// with the lowest ID that can run renewal.enable.v1 and whose renewal period
// it can read. Only that agent's own check-in queues the command, and never
// its first: agents that start together check in at once, each before the
// others' states are stored, so on a first check-in each could see itself as
// the lowest. By their next check-in they see each other.
func planRenewal(plan keySyncPlan, f fleet.Fleet, self *registry.Agent, state store.AgentState, firstCheckIn bool, commands []store.CommandRecord, now time.Time) keySyncPlan {
	if firstCheckIn {
		return plan
	}
	candidate := ""
	for _, a := range f.Agents {
		if !a.InScope {
			continue
		}
		if renewalOn(a.Controller) {
			return plan
		}
		if a.Healthy && a.Controller != nil && a.Controller.KeyRenewPeriod != "" &&
			slices.Contains(a.Capabilities, protocol.CapabilityRenewal) &&
			slices.Contains(a.Commands, protocol.CommandRenewalEnable) &&
			(candidate == "" || a.ID < candidate) {
			candidate = a.ID
		}
	}
	if candidate != self.ID || !canRun(self, state, protocol.CommandRenewalEnable) {
		return plan
	}
	for _, c := range commands {
		if c.Type == protocol.CommandRenewalEnable && recent(c, now) {
			return plan
		}
	}
	plan.EnableRenewal = true
	return plan
}

// renewalOn reports whether a controller is known to renew its key.
func renewalOn(c *protocol.Controller) bool {
	if c == nil || c.KeyRenewPeriod == "" {
		return false
	}
	d, err := time.ParseDuration(c.KeyRenewPeriod)
	return err == nil && d > 0
}

// canRun reports whether an agent may be sent a command type: its
// registration grants the capability, its check-in reports the capability,
// and it says it handles the type.
func canRun(self *registry.Agent, state store.AgentState, commandType string) bool {
	capability := protocol.CommandCapability[commandType]
	return capability != "" &&
		self.HasCapability(capability) &&
		slices.Contains(state.Capabilities, capability) &&
		slices.Contains(state.Commands, commandType)
}

// recent reports whether a command is still open or finished too recently
// for its work to be issued again.
func recent(c store.CommandRecord, now time.Time) bool {
	if c.Open(now) {
		return true
	}
	if c.FinishedAt == nil {
		// expired without a result
		return false
	}
	hold := retryAfterFailure
	if c.Status == store.CommandSucceeded {
		hold = settleAfterSuccess
	}
	return now.Sub(*c.FinishedAt) < hold
}

// busyFingerprints are keys a recent restore command covers, and keys a
// restore found already present within presentHold.
func busyFingerprints(commands []store.CommandRecord, now time.Time) map[string]bool {
	busy := map[string]bool{}
	for _, c := range commands {
		if c.Type != protocol.CommandKeysRestore {
			continue
		}
		for _, fp := range foundPresent(c, now) {
			busy[fp] = true
		}
		if !recent(c, now) {
			continue
		}
		var p protocol.KeysRestorePayload
		if err := json.Unmarshal([]byte(c.Payload), &p); err != nil {
			continue
		}
		for _, fp := range p.Fingerprints {
			busy[fp] = true
		}
	}
	return busy
}

// foundPresent returns the keys a restore command found already in its
// cluster, while its result is within presentHold.
func foundPresent(c store.CommandRecord, now time.Time) []string {
	if c.Type != protocol.CommandKeysRestore || c.FinishedAt == nil || c.Result == "" || now.Sub(*c.FinishedAt) >= presentHold {
		return nil
	}
	var res protocol.KeysRestoreResult
	if json.Unmarshal([]byte(c.Result), &res) != nil {
		return nil
	}
	return res.AlreadyPresent
}

// noteHeldKeys adds an issue to each agent in f missing keys that a recent
// restore found already in its cluster. Only those agents' commands are
// read.
func (s *Server) noteHeldKeys(ctx context.Context, f *fleet.Fleet, now time.Time) {
	for i := range f.Agents {
		a := &f.Agents[i]
		if len(a.MissingKeys) == 0 {
			continue
		}
		commands, err := s.store.CommandsSince(ctx, a.ID, time.Now().Add(-presentLookback))
		if err != nil {
			s.logger.WarnContext(ctx, "failed to read commands for the fleet", "agent_id", a.ID, "error", err)
			continue
		}
		var held []string
		for _, c := range commands {
			for _, fp := range foundPresent(c, now) {
				if slices.Contains(a.MissingKeys, fp) && !slices.Contains(held, fp) {
					held = append(held, fp)
				}
			}
		}
		if len(held) > 0 {
			sort.Strings(held)
			a.Issues = append(a.Issues, fmt.Sprintf(
				"a restore found missing keys already in its cluster (%s): held under a label other than active, or not loaded by its controller; they are not restored again for an hour",
				strings.Join(held, ", ")))
		}
	}
}

// syncKeys runs the key sync plan for an agent that just checked in, queues
// its commands, and returns the keys it should escrow. snap was read before
// the check-in was stored and holds its new state; seen says whether the
// agent had checked in before.
func (s *Server) syncKeys(ctx context.Context, self *registry.Agent, state store.AgentState, snap fleetSnapshot, seen bool) ([]string, error) {
	keys, err := s.fleetKeys(ctx, snap, &state)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	f := fleet.Compute(s.env, snap.reg, snap.states, keys, now)
	// only the commands recent enough to count; their IDs (ULIDs) are
	// stamped with the wall clock
	commands, err := s.store.CommandsSince(ctx, self.ID, time.Now().Add(-keyCommandLookback))
	if err != nil {
		return nil, err
	}

	plan := planKeySync(f, self, state, !seen, commands, keys, now)
	if len(plan.Restore) > 0 {
		// a restore that found keys already present holds them off longer
		// than every check-in reads back; read that far only now
		if commands, err = s.store.CommandsSince(ctx, self.ID, time.Now().Add(-presentLookback)); err != nil {
			return nil, err
		}
		plan = planKeySync(f, self, state, !seen, commands, keys, now)
	}
	if len(plan.Restore) > 0 {
		if err := s.queue(ctx, self, protocol.CommandKeysRestore, protocol.KeysRestorePayload{Fingerprints: plan.Restore}, now); err != nil {
			return nil, err
		}
		s.logger.WarnContext(ctx, "queued restore of escrowed keys",
			"event", "key.restore_queued", "env", s.env, "agent_id", self.ID, "cluster", self.Cluster,
			"fingerprints", plan.Restore)
	}
	if plan.EnableRenewal {
		period := s.keyRenewPeriod.String()
		if err := s.queue(ctx, self, protocol.CommandRenewalEnable, protocol.RenewalEnablePayload{Period: period}, now); err != nil {
			return nil, err
		}
		s.logger.WarnContext(ctx, "no cluster renews its sealing key; asking one to",
			"event", "renewal.enable_queued", "env", s.env, "agent_id", self.ID, "cluster", self.Cluster,
			"period", period)
	}
	return plan.EscrowNeeded, nil
}

// queue writes a command for an agent.
func (s *Server) queue(ctx context.Context, agent *registry.Agent, commandType string, payload any, now time.Time) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode %s payload: %w", commandType, err)
	}
	return s.store.PutCommand(ctx, store.CommandRecord{
		AgentID:   agent.ID,
		ID:        ulid.Make().String(),
		Type:      commandType,
		Status:    store.CommandQueued,
		CreatedAt: now,
		ExpiresAt: now.Add(keyCommandTTL),
		Payload:   string(body),
	})
}
