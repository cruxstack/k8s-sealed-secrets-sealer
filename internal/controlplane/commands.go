package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Command delivery limits.
const (
	// maxPollWait is the longest a commands poll is held, under API
	// Gateway's integration timeout.
	maxPollWait = 20 * time.Second
	// maxResultBody bounds a command result.
	maxResultBody = 64 << 10
	// maxResultError bounds a failed command's error message.
	maxResultError = 1024
)

// agentCommands leases and returns the agent's queued commands, holding the
// request up to ?wait= seconds (at most 20) until one arrives.
func (s *Server) agentCommands(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	wait := time.Duration(0)
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "wait must be a whole number of seconds")
			return
		}
		wait = min(time.Duration(n)*time.Second, maxPollWait)
	}
	ctx := r.Context()
	deadline := time.Now().Add(wait)
	for {
		leased, err := s.leaseCommands(ctx, agent)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to lease commands", "agent_id", agent.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if len(leased) > 0 || !time.Now().Add(s.pollInterval).Before(deadline) {
			httpserver.WriteJSON(w, http.StatusOK, protocol.CommandsResponse{Commands: leased})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.pollInterval):
		}
	}
}

// leaseCommands leases every queued, unexpired command the agent may run.
// A command the agent is no longer registered for stays queued and expires.
func (s *Server) leaseCommands(ctx context.Context, agent *registry.Agent) ([]protocol.Command, error) {
	records, err := s.store.Commands(ctx, agent.ID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	leased := []protocol.Command{}
	for _, c := range records {
		if c.Status != store.CommandQueued || !c.Open(now) {
			continue
		}
		if capability := protocol.CommandCapability[c.Type]; capability == "" || !agent.HasCapability(capability) {
			continue
		}
		ok, err := s.store.LeaseCommand(ctx, agent.ID, c.ID, now)
		if err != nil {
			return nil, err
		}
		if !ok {
			// leased by a concurrent poll, or expired meanwhile
			continue
		}
		s.logger.InfoContext(ctx, "command leased",
			"event", "command.leased", "env", s.env, "agent_id", agent.ID, "command_id", c.ID, "type", c.Type)
		leased = append(leased, c.Protocol())
	}
	return leased, nil
}

// agentCommandResult accepts the outcome of a command the agent leased.
func (s *Server) agentCommandResult(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	id := r.PathValue("id")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in protocol.CommandResult
	if !decodeJSON(w, r, maxResultBody, &in) {
		return
	}
	switch {
	case in.Status != protocol.CommandSucceeded && in.Status != protocol.CommandFailed:
		writeError(w, http.StatusBadRequest, "status must be succeeded or failed")
		return
	case len(in.Error) > maxResultError:
		writeError(w, http.StatusBadRequest, "error is too long")
		return
	case len(in.Result) > 0 && !json.Valid(in.Result):
		writeError(w, http.StatusBadRequest, "result must be JSON")
		return
	}

	ctx := r.Context()
	cmd, found, err := s.findCommand(ctx, agent.ID, id)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read command", "agent_id", agent.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	ok, err := s.store.FinishCommand(ctx, agent.ID, id, in.Status, string(in.Result), in.Error, s.now().UTC())
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to record command result", "agent_id", agent.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "command is not leased or has expired")
		return
	}
	s.logCommandResult(ctx, agent, cmd, in)
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": in.Status})
}

func (s *Server) findCommand(ctx context.Context, agentID, id string) (store.CommandRecord, bool, error) {
	records, err := s.store.Commands(ctx, agentID)
	if err != nil {
		return store.CommandRecord{}, false, err
	}
	for _, c := range records {
		if c.ID == id {
			return c, true, nil
		}
	}
	return store.CommandRecord{}, false, nil
}

// logCommandResult writes the alert events for a finished key command.
func (s *Server) logCommandResult(ctx context.Context, agent *registry.Agent, cmd store.CommandRecord, in protocol.CommandResult) {
	base := []any{"env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "command_id", cmd.ID, "type", cmd.Type}
	s.logger.InfoContext(ctx, "command finished", append([]any{"event", "command.finished", "status", in.Status}, base...)...)

	switch cmd.Type {
	case protocol.CommandKeysRestore:
		var res protocol.KeysRestoreResult
		if len(in.Result) > 0 {
			_ = json.Unmarshal(in.Result, &res)
		}
		for _, fp := range res.Restored {
			s.logger.WarnContext(ctx, "sealing key restored from escrow",
				append([]any{"event", "key.restored", "fingerprint", fp, "controller_restarted", res.ControllerRestarted}, base...)...)
		}
		for _, f := range res.Failed {
			s.logger.ErrorContext(ctx, "failed to restore sealing key",
				append([]any{"event", "key.sync_failed", "fingerprint", f.Fingerprint, "error", f.Error}, base...)...)
		}
		if in.Status == protocol.CommandFailed && len(res.Failed) == 0 {
			s.logger.ErrorContext(ctx, "failed to restore sealing keys",
				append([]any{"event", "key.sync_failed", "error", in.Error}, base...)...)
		}
	case protocol.CommandRenewalEnable:
		if in.Status == protocol.CommandSucceeded {
			s.logger.WarnContext(ctx, "key renewal turned on", append([]any{"event", "renewal.enabled"}, base...)...)
		} else {
			s.logger.ErrorContext(ctx, "failed to turn on key renewal",
				append([]any{"event", "renewal.enable_failed", "error", in.Error}, base...)...)
		}
	}
}
