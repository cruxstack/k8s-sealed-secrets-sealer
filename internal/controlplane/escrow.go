package controlplane

import (
	"encoding/base64"
	"maps"
	"net/http"
	"slices"

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
// the envelope is bound to this env and key. The first upload wins.
func (s *Server) agentPutEscrow(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	ctx := r.Context()
	fp := protocol.ParseFingerprintPath(r.PathValue("fingerprint"))
	if !agent.HasCapability(protocol.CapabilityKeys) {
		writeError(w, http.StatusForbidden, "agent is not registered for the keys capability")
		return
	}
	var in protocol.EscrowUpload
	if !decodeJSON(w, r, maxEscrowBody, &in) {
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

	stored, err := s.store.PutEscrowIfAbsent(ctx, protocol.EscrowRecord{
		Fingerprint: fp,
		Certificate: in.Certificate,
		Envelope:    in.Envelope,
		UploadedBy:  agent.ID,
		UploadedAt:  s.now().UTC(),
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to escrow sealing key",
			"event", "key.sync_failed", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "fingerprint", fp, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.markEscrowed(fp)
	if stored {
		s.logger.WarnContext(ctx, "sealing key escrowed",
			"event", "key.escrowed", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster,
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
// capability. The record is ciphertext; only agent roles can decrypt it.
func (s *Server) agentGetEscrow(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	ctx := r.Context()
	fp := protocol.ParseFingerprintPath(r.PathValue("fingerprint"))
	if !agent.HasCapability(protocol.CapabilityKeys) {
		writeError(w, http.StatusForbidden, "agent is not registered for the keys capability")
		return
	}
	rec, ok, err := s.store.Escrow(ctx, fp)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to read escrow", "agent_id", agent.ID, "fingerprint", fp, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.logger.InfoContext(ctx, "escrowed key downloaded",
		"event", "key.escrow_read", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "fingerprint", fp)
	httpserver.WriteJSON(w, http.StatusOK, rec)
}
