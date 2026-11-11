package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Escrow upload limits. A key Secret's certificate and private key are a few
// KB; the envelope adds base64 and a wrapped data key.
const (
	maxEscrowBody      = 64 << 10
	maxEscrowKeyID     = 2048
	maxEscrowWrapped   = 2048
	maxEscrowNonce     = 64
	maxEscrowFieldSize = 48 << 10
)

// maxEscrowCopies is how many escrowed copies of a key are kept, one per
// uploading agent. The control plane cannot check a copy's private key, so
// a copy that does not open (one an agent made from a key it does not hold,
// say) must not be the only one; restores try the others in turn.
const maxEscrowCopies = 3

// restoreFailureLookback is how far back a download counts the agent's
// failed restores of a key, to choose the copy it returns: long enough to
// step through every copy at the pace restores are retried.
const restoreFailureLookback = time.Hour

// restoreHistoryTTL is how long an agent's restore results, read for one
// escrow download, serve the downloads after it: a restore downloads all of
// its keys well within it, and the retry of a failed restore comes
// retryAfterFailure later, so it always reads them afresh.
const restoreHistoryTTL = time.Minute

// escrowContext is the encryption context every escrowed key is sealed with.
func escrowContext(env, fingerprint string) map[string]string {
	return map[string]string{
		protocol.ContextEnv:         env,
		protocol.ContextFingerprint: fingerprint,
		protocol.ContextPurpose:     protocol.PurposeKeyEscrow,
	}
}

// agentPutEscrow stores an agent's escrowed copy of a key it holds. The
// control plane cannot read the private key; it checks what it can see: the
// certificate is the key named in the path, the agent holds that key, and
// the envelope is bound to this env and key. Each agent stores one copy at
// most, and a key keeps maxEscrowCopies; a copy is never replaced.
func (s *Server) agentPutEscrow(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	ctx := r.Context()
	fp := protocol.ParseFingerprintPath(r.PathValue("fingerprint"))
	if !agent.HasCapability(protocol.CapabilityKeys) {
		writeError(w, http.StatusForbidden, "agent is not registered for the keys capability")
		return
	}
	var in protocol.EscrowUpload
	if !decodeAgentJSON(w, r, maxEscrowBody, &in) {
		return
	}
	if msg := validateEscrow(in, s.env, fp); msg != "" {
		s.logger.WarnContext(ctx, "escrow upload rejected",
			"event", "key.escrow_rejected", "env", s.env, "agent_id", agent.ID, "fingerprint", fp, "reason", msg)
		writeError(w, http.StatusBadRequest, "invalid escrow upload: "+msg)
		return
	}
	states, err := s.store.GetAgentStates(ctx, []string{agent.ID})
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read agent state", "agent_id", agent.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !slices.ContainsFunc(states[agent.ID].Keys, func(k store.KeyRef) bool { return k.Fingerprint == fp }) {
		writeError(w, http.StatusConflict, "agent has not reported this key")
		return
	}

	stored, first, err := s.store.PutEscrow(ctx, protocol.EscrowRecord{
		Fingerprint: fp,
		Certificate: in.Certificate,
		Envelope:    in.Envelope,
		UploadedBy:  agent.ID,
		UploadedAt:  s.now().UTC(),
	}, maxEscrowCopies)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to escrow sealing key",
			"event", "key.sync_failed", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "fingerprint", fp, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	switch {
	case first:
		s.markEscrowed(fp, agent.ID)
		s.logger.WarnContext(ctx, "sealing key escrowed",
			"event", "key.escrowed", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster,
			"fingerprint", fp, "kms_key_id", in.Envelope.KeyID)
	case stored:
		s.markEscrowed(fp, agent.ID)
		s.logger.InfoContext(ctx, "another copy of a sealing key escrowed",
			"event", "key.escrow_copied", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster,
			"fingerprint", fp, "kms_key_id", in.Envelope.KeyID)
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]bool{"stored": stored})
}

// validateEscrow returns why an upload is invalid, or "".
func validateEscrow(in protocol.EscrowUpload, env, fp string) string {
	if len(in.Certificate) > protocol.MaxCertificateBytes {
		return "certificate too large"
	}
	parsed, _, err := keys.ParseCert([]byte(in.Certificate))
	if err != nil {
		return "certificate does not parse"
	}
	if parsed.Fingerprint != fp {
		return "certificate is not the key in the path"
	}
	e := in.Envelope
	if !maps.Equal(e.Context, escrowContext(env, fp)) {
		return "envelope is not bound to this env and key"
	}
	if e.KeyID == "" || len(e.KeyID) > maxEscrowKeyID {
		return "envelope key_id is missing or too long"
	}
	for _, f := range []struct {
		value string
		limit int
	}{{e.WrappedKey, maxEscrowWrapped}, {e.Nonce, maxEscrowNonce}, {e.Ciphertext, maxEscrowFieldSize}} {
		if f.value == "" || len(f.value) > f.limit {
			return "envelope field is missing or too long"
		}
		if _, err := base64.StdEncoding.DecodeString(f.value); err != nil {
			return "envelope field is not base64"
		}
	}
	return ""
}

// agentGetEscrow returns an escrowed key to an agent with the keys
// capability. The record is ciphertext; only agent roles can decrypt it. A
// revoked key is not returned, so it is never restored.
//
// The agent checks a restored key before installing it: the envelope opens
// under its own escrow key and context, and the private key matches the
// certificate. A key with several copies returns one the agent's restores
// have not found bad (chooseCopy), so a copy that does not open is skipped
// on the next try. Only the agent's own results count: another agent could
// otherwise steer it away from the copies that open.
func (s *Server) agentGetEscrow(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	ctx := r.Context()
	fp := protocol.ParseFingerprintPath(r.PathValue("fingerprint"))
	if !agent.HasCapability(protocol.CapabilityKeys) {
		writeError(w, http.StatusForbidden, "agent is not registered for the keys capability")
		return
	}
	key, _, err := s.store.GetKey(ctx, fp)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read key", "agent_id", agent.ID, "fingerprint", fp, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if key.Status == store.KeyRevoked {
		s.logger.WarnContext(ctx, "refused to return a revoked key from escrow",
			"event", "key.escrow_refused", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "fingerprint", fp)
		writeError(w, http.StatusGone, "key is revoked")
		return
	}
	recs, err := s.store.Escrow(ctx, fp)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read escrow", "agent_id", agent.ID, "fingerprint", fp, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(recs) == 0 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	history, err := s.restoreHistory(ctx, agent.ID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read commands", "agent_id", agent.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	n := chooseCopy(recs, history[fp])
	rec := recs[n]
	s.logger.InfoContext(ctx, "escrowed key downloaded",
		"event", "key.escrow_read", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "fingerprint", fp,
		"uploaded_by", rec.UploadedBy, "copy", n+1, "copies", len(recs))
	httpserver.WriteJSON(w, http.StatusOK, rec)
}

// copyFailures is what an agent's recent restores of one key say about the
// key's escrowed copies.
type copyFailures struct {
	// bad lists the copies, by uploader, that did not open or held another
	// key.
	bad []string
	// unnamed counts failures that name no copy: from older agents, or
	// before the agent got one. Each moves the agent on to the next copy,
	// as before copies were named.
	unnamed int
	// failed counts every failure the copy was or may have been at fault
	// for.
	failed int
}

// chooseCopy returns which of a key's copies to hand an agent: the first
// its restores have not found bad, moved on by one for each failure that
// names no copy. When every copy failed, it goes round them all.
func chooseCopy(recs []protocol.EscrowRecord, f copyFailures) int {
	var good []int
	for i, r := range recs {
		if !slices.Contains(f.bad, r.UploadedBy) {
			good = append(good, i)
		}
	}
	if len(good) == 0 {
		return f.failed % len(recs)
	}
	return good[f.unnamed%len(good)]
}

// restoreHistory returns what an agent's restores of the last
// restoreFailureLookback say about each key's copies. It reads the agent's
// commands once for all the keys a restore downloads, not once per key.
func (s *Server) restoreHistory(ctx context.Context, agentID string) (map[string]copyFailures, error) {
	now := s.now()
	s.historyMu.Lock()
	h, ok := s.histories[agentID]
	s.historyMu.Unlock()
	if ok && !now.Before(h.at) && now.Sub(h.at) < restoreHistoryTTL {
		return h.byKey, nil
	}
	// failures older than the lookback no longer move the choice; command
	// IDs (ULIDs) are stamped with the wall clock
	commands, err := s.store.CommandsSince(ctx, agentID, time.Now().Add(-restoreFailureLookback))
	if err != nil {
		return nil, err
	}
	byKey := restoreFailures(commands)
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	if len(s.histories) > 10_000 {
		s.histories = map[string]restoreHistory{}
	}
	s.histories[agentID] = restoreHistory{at: now, byKey: byKey}
	return byKey, nil
}

// restoreHistory is an agent's restore failures by key, as read at a time.
type restoreHistory struct {
	at    time.Time
	byKey map[string]copyFailures
}

// restoreFailures sums up an agent's failed restores, by key, from its
// keys.restore.v1 results. A failure the copy was not at fault for, such
// as a Secret the agent could not create, says nothing about the copy.
func restoreFailures(commands []store.CommandRecord) map[string]copyFailures {
	out := map[string]copyFailures{}
	for _, c := range commands {
		if c.Type != protocol.CommandKeysRestore || c.Result == "" {
			continue
		}
		var res protocol.KeysRestoreResult
		if json.Unmarshal([]byte(c.Result), &res) != nil {
			continue
		}
		for _, f := range res.Failed {
			cf := out[f.Fingerprint]
			switch {
			case f.UploadedBy == "":
				cf.unnamed++
				cf.failed++
			case f.BadCopy:
				cf.failed++
				if !slices.Contains(cf.bad, f.UploadedBy) {
					cf.bad = append(cf.bad, f.UploadedBy)
				}
			}
			out[f.Fingerprint] = cf
		}
	}
	return out
}
