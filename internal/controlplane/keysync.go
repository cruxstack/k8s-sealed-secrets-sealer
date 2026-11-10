package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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
)

// keySyncPlan is what one agent's check-in leads to.
type keySyncPlan struct {
	// EscrowNeeded lists the agent's keys with no escrowed copy.
	EscrowNeeded []string
	// Restore lists escrowed keys the agent's cluster is missing; empty
	// queues nothing.
	Restore []string
	// EnableRenewal queues renewal.enable.v1 for the agent.
	EnableRenewal bool
}

// planKeySync decides, for the agent that just checked in, which of its keys
// need escrow, which escrowed keys it should restore, and whether it should
// turn on key renewal. It is pure, so the rules are tested directly.
//
// Every decision is about the checking-in agent only, and each agent checks
// in serially, so concurrent check-ins from different agents cannot queue
// the same command twice.
func planKeySync(f fleet.Fleet, self *registry.Agent, state store.AgentState, commands []store.CommandRecord, escrowed map[string]bool, now time.Time) keySyncPlan {
	var plan keySyncPlan
	if !canRun(self, state, protocol.CommandKeysRestore) {
		// without the keys capability the agent can neither upload nor
		// restore; it may not even see its whole key set
		return planRenewal(plan, f, self, state, commands, now)
	}
	for _, k := range state.Keys {
		if !escrowed[k.Fingerprint] {
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
			if escrowed[fp] && !busy[fp] {
				plan.Restore = append(plan.Restore, fp)
			}
		}
		if len(plan.Restore) > protocol.MaxKeys {
			plan.Restore = plan.Restore[:protocol.MaxKeys]
		}
	}
	return planRenewal(plan, f, self, state, commands, now)
}

// planRenewal turns renewal on in one cluster when no in-scope cluster has it
// on. The cluster is chosen deterministically: the healthy, in-scope agent
// with the lowest ID that can run renewal.enable.v1 and whose renewal period
// it can read. Only that agent's own check-in queues the command.
func planRenewal(plan keySyncPlan, f fleet.Fleet, self *registry.Agent, state store.AgentState, commands []store.CommandRecord, now time.Time) keySyncPlan {
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

// busyFingerprints are keys a recent restore command covers.
func busyFingerprints(commands []store.CommandRecord, now time.Time) map[string]bool {
	busy := map[string]bool{}
	for _, c := range commands {
		if c.Type != protocol.CommandKeysRestore || !recent(c, now) {
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

// syncKeys runs the key sync plan for an agent that just checked in, queues
// its commands, and returns the keys it should escrow.
func (s *Server) syncKeys(ctx context.Context, self *registry.Agent, state store.AgentState) ([]string, error) {
	ids := make([]string, 0, len(s.reg.Agents))
	for _, a := range s.reg.Agents {
		ids = append(ids, a.ID)
	}
	states, err := s.store.GetAgentStates(ctx, ids)
	if err != nil {
		return nil, err
	}
	// the store may lag this agent's own write; the check-in is newer
	states[self.ID] = state
	now := s.now().UTC()
	f := fleet.Compute(s.env, s.reg, states, now)

	fps := make([]string, 0, len(state.Keys))
	for _, a := range f.Agents {
		for _, k := range a.Keys {
			fps = append(fps, k.Fingerprint)
		}
	}
	escrowed, err := s.escrowed(ctx, fps)
	if err != nil {
		return nil, err
	}
	commands, err := s.store.Commands(ctx, self.ID)
	if err != nil {
		return nil, err
	}

	plan := planKeySync(f, self, state, commands, escrowed, now)
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

// escrowed reports which fingerprints have an escrowed copy. Escrow records
// are never deleted, so hits are cached.
func (s *Server) escrowed(ctx context.Context, fps []string) (map[string]bool, error) {
	out := map[string]bool{}
	var unknown []string
	s.knownMu.Lock()
	for _, fp := range fps {
		if s.knownEscrow[fp] {
			out[fp] = true
		} else if !slices.Contains(unknown, fp) {
			unknown = append(unknown, fp)
		}
	}
	s.knownMu.Unlock()
	if len(unknown) == 0 {
		return out, nil
	}
	found, err := s.store.Escrowed(ctx, unknown)
	if err != nil {
		return nil, err
	}
	for fp := range found {
		out[fp] = true
		s.markEscrowed(fp)
	}
	return out, nil
}

func (s *Server) markEscrowed(fp string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if len(s.knownEscrow) > 10_000 {
		s.knownEscrow = map[string]bool{}
	}
	s.knownEscrow[fp] = true
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
