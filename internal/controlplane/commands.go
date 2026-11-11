package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
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
	// pollTimeout bounds a whole commands poll, its store calls included,
	// so the response is written within API Gateway's 30 seconds.
	pollTimeout = 25 * time.Second
	// leaseMargin is the least time a poll must have left to lease another
	// command: a command leased into a response that is never written is
	// lost.
	leaseMargin = 3 * time.Second
	// maxPollCommands and maxPollBytes bound the commands one poll leases.
	// Agents read at most 8 MiB of a response (1 MiB up to v0.6.2), and the
	// Lambda adapter sends at most 4 MiB (cmd/lambda); the largest command,
	// a seal of the largest value, is about 100 KiB.
	maxPollCommands = 16
	maxPollBytes    = 512 << 10
	// commandLookback is how far back a read of open commands looks: the
	// longest any command lives, and a minute for clocks that differ
	// between instances. A command type that lives longer belongs here.
	commandLookback = max(sealCommandTTL, keyCommandTTL) + time.Minute
	// maxResultBody bounds a command result: a seal's ciphertexts, at most
	// protocol.SealBudgetBytes in base64, with their names.
	maxResultBody = 512 << 10
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
	ctx, cancel := context.WithTimeout(r.Context(), pollTimeout)
	defer cancel()
	deadline := time.Now().Add(wait)
	for {
		leased, err := s.leaseCommands(ctx, agent)
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to lease commands", "agent_id", agent.ID, "leased", len(leased), "error", err)
			if len(leased) == 0 {
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			// what was leased goes out; held back, it would be lost
		}
		if len(leased) > 0 || !time.Now().Add(s.pollInterval).Before(deadline) {
			httpserver.WriteJSON(w, http.StatusOK, protocol.CommandsResponse{Commands: leased})
			return
		}
		select {
		case <-ctx.Done():
			if r.Context().Err() == nil {
				// the store was slow; the agent polls again
				httpserver.WriteJSON(w, http.StatusOK, protocol.CommandsResponse{Commands: []protocol.Command{}})
			}
			return
		case <-time.After(s.pollInterval):
		}
	}
}

// leaseCommands leases the agent's queued, unexpired commands it may run,
// oldest first, as many as one response carries. It stops early when ctx
// leaves too little time to send the response, and returns what it leased
// with any error, since those commands are leased whether or not they are
// sent. A command the agent is no longer registered for stays queued and
// expires.
func (s *Server) leaseCommands(ctx context.Context, agent *registry.Agent) ([]protocol.Command, error) {
	now := s.now().UTC()
	records, err := s.openCommands(ctx, agent.ID, now)
	if err != nil {
		return nil, err
	}
	leased := []protocol.Command{}
	size := 0
	for _, c := range records {
		if c.Status != store.CommandQueued {
			continue
		}
		if capability := protocol.CommandCapability[c.Type]; capability == "" || !agent.HasCapability(capability) {
			continue
		}
		if len(leased) == maxPollCommands {
			break
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < leaseMargin {
			break
		}
		cmd, n, err := sendable(c)
		if err != nil {
			// a broken record stays queued and expires; it must not hold
			// back the commands after it
			s.logger.ErrorContext(ctx, "failed to prepare command", "agent_id", agent.ID, "command_id", c.ID, "error", err)
			continue
		}
		if len(leased) > 0 && size+n > maxPollBytes {
			break
		}
		ok, err := s.store.LeaseCommand(ctx, agent.ID, c.ID, now)
		if err != nil {
			return leased, err
		}
		if !ok {
			// leased by a concurrent poll, or expired meanwhile
			continue
		}
		s.logger.InfoContext(ctx, "command leased",
			"event", "command.leased", "env", s.env, "agent_id", agent.ID, "command_id", c.ID, "type", c.Type)
		leased = append(leased, cmd)
		size += n
	}
	return leased, nil
}

// sendable returns a command as an agent receives it, with its size in a
// response.
func sendable(c store.CommandRecord) (protocol.Command, int, error) {
	cmd, err := c.Protocol()
	if err != nil {
		return protocol.Command{}, 0, err
	}
	b, err := json.Marshal(cmd)
	if err != nil {
		return protocol.Command{}, 0, fmt.Errorf("failed to encode command %s: %w", c.ID, err)
	}
	return cmd, len(b), nil
}

// openCommands returns an agent's open commands, oldest first. It reads only
// those queued within commandLookback, not every command kept for the audit
// trail. The lookback is measured on the wall clock, which stamps command
// IDs (ULIDs) as they are made.
func (s *Server) openCommands(ctx context.Context, agentID string, now time.Time) ([]store.CommandRecord, error) {
	records, err := s.store.CommandsSince(ctx, agentID, time.Now().Add(-commandLookback))
	if err != nil {
		return nil, err
	}
	open := records[:0]
	for _, c := range records {
		if c.Open(now) {
			open = append(open, c)
		}
	}
	return open, nil
}

// agentCommandResult accepts the outcome of a command the agent leased.
func (s *Server) agentCommandResult(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	id := r.PathValue("id")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var in protocol.CommandResult
	if !decodeAgentJSON(w, r, maxResultBody, &in) {
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
	cmd, found, err := s.store.Command(ctx, agent.ID, id)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read command", "agent_id", agent.ID, "command_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if cmd.Type == protocol.CommandSeal {
		s.finishSeal(w, r, agent, cmd, in)
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

// logRemovals writes the events of a finished keys.delete.v1: each key the
// agent removed from its cluster, and each it refused to. A key refused
// because values are sealed with it has its deletion undone.
func (s *Server) logRemovals(ctx context.Context, agent *registry.Agent, in protocol.CommandResult, base []any) {
	var res protocol.KeysDeleteResult
	if len(in.Result) > 0 {
		_ = json.Unmarshal(in.Result, &res)
	}
	refused := false
	for _, k := range res.Keys {
		switch k.Outcome {
		case protocol.KeyRemoved:
			s.logger.WarnContext(ctx, "deleted sealing key removed from a cluster",
				append([]any{"event", "key.removed", "fingerprint", k.Fingerprint, "controller_restarted", res.ControllerRestarted}, base...)...)
		case protocol.KeyRefused:
			refused = true
			s.logger.ErrorContext(ctx, "agent refused to remove a deleted sealing key",
				append([]any{"event", "key.remove_refused", "fingerprint", k.Fingerprint, "reason", k.Reason,
					"values", k.Values, "sealed_secrets", k.SealedSecrets}, base...)...)
		}
	}
	if in.Status == protocol.CommandFailed && !refused {
		s.logger.ErrorContext(ctx, "failed to remove deleted sealing keys",
			append([]any{"event", "key.remove_refused", "error", in.Error}, base...)...)
	}
	s.undoRefused(ctx, agent, res.Keys)
}

// undoRefused undoes the deletion of each key an agent refused to remove
// because values are sealed with it. The revoked keys are read only then.
func (s *Server) undoRefused(ctx context.Context, agent *registry.Agent, keys []protocol.KeyDeletion) {
	var revoked map[string]store.RevokedKey
	for _, k := range keys {
		if k.Outcome != protocol.KeyRefused || k.Values <= 0 {
			continue
		}
		if revoked == nil {
			var err error
			if revoked, err = s.store.RevokedKeys(ctx); err != nil {
				s.logger.ErrorContext(ctx, "failed to read revoked keys", "agent_id", agent.ID, "error", err)
				return
			}
		}
		if r, ok := revoked[k.Fingerprint]; ok && r.Deleted() {
			s.undoDeletion(ctx, agent, r, store.KeyUse{Values: k.Values, SealedSecrets: k.SealedSecrets}, s.now().UTC())
		}
	}
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
			fields := []any{"event", "key.sync_failed", "fingerprint", f.Fingerprint, "error", f.Error}
			if f.UploadedBy != "" {
				fields = append(fields, "uploaded_by", f.UploadedBy, "bad_copy", f.BadCopy)
			}
			s.logger.ErrorContext(ctx, "failed to restore sealing key", append(fields, base...)...)
		}
		if in.Status == protocol.CommandFailed && len(res.Failed) == 0 {
			s.logger.ErrorContext(ctx, "failed to restore sealing keys",
				append([]any{"event", "key.sync_failed", "error", in.Error}, base...)...)
		}
	case protocol.CommandKeysDelete:
		s.logRemovals(ctx, agent, in, base)
	case protocol.CommandRenewalEnable:
		if in.Status == protocol.CommandSucceeded {
			s.logger.WarnContext(ctx, "key renewal turned on", append([]any{"event", "renewal.enabled"}, base...)...)
		} else {
			s.logger.ErrorContext(ctx, "failed to turn on key renewal",
				append([]any{"event", "renewal.enable_failed", "error", in.Error}, base...)...)
		}
	}
}
