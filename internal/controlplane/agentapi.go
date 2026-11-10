package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Request body limits for the agent API.
const (
	maxSessionBody = 32 << 10
	maxCheckInBody = 2 << 20
)

// Field limits on a check-in.
const (
	maxShortField = 64
	maxCommands   = 32
)

func (s *Server) agentSession(w http.ResponseWriter, r *http.Request) {
	var req protocol.SessionRequest
	if !decodeAgentJSON(w, r, maxSessionBody, &req) {
		return
	}
	verifier, ok := s.agents.Load().logins[req.Method]
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported login method")
		return
	}
	agent, err := verifier.VerifyLogin(r.Context(), req)
	if errors.Is(err, agentauth.ErrTooManyLogins) {
		s.logger.WarnContext(r.Context(), "agent login throttled",
			"event", "agent.login_throttled", "env", s.env, "method", req.Method, "error", err)
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too many logins; try again shortly")
		return
	}
	if err != nil {
		s.logger.WarnContext(r.Context(), "agent login rejected",
			"event", "agent.login_rejected", "env", s.env, "method", req.Method, "error", err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	token, exp, err := s.sessions.Issue(agent.ID)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to issue agent session", "agent_id", agent.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logger.InfoContext(r.Context(), "agent logged in",
		"event", "agent.login", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "method", req.Method)
	httpserver.WriteJSON(w, http.StatusOK, protocol.SessionResponse{
		Token: token, ExpiresAt: exp, AgentID: agent.ID, Env: s.env,
	})
}

// requireAgent authenticates an agent session token and passes the
// registered agent to next.
func (s *Server) requireAgent(next func(http.ResponseWriter, *http.Request, *registry.Agent)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.sessions.Verify(bearer(r))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// an agent removed from the registry loses access with its session,
		// or when the registry is next read (Options.ReloadRegistry)
		agent, ok := s.currentRegistry().Agent(id)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, agent)
	}
}

func (s *Server) agentCheckIn(w http.ResponseWriter, r *http.Request, agent *registry.Agent) {
	var in protocol.CheckIn
	if !decodeAgentJSON(w, r, maxCheckInBody, &in) {
		return
	}
	now := s.now().UTC()
	state, records, ignored, err := validateCheckIn(in, agent, now)
	if err != nil {
		s.logger.WarnContext(r.Context(), "agent check-in rejected",
			"event", "agent.checkin_rejected", "env", s.env, "agent_id", agent.ID, "error", err)
		writeError(w, http.StatusBadRequest, "invalid check-in: "+err.Error())
		return
	}
	if len(ignored) > 0 {
		s.logger.WarnContext(r.Context(), "agent reports capabilities it is not registered for; ignoring them",
			"event", "agent.capability_ignored", "env", s.env, "agent_id", agent.ID, "capabilities", ignored)
	}
	state.CheckInIntervalSeconds = checkInIntervalSeconds(r.Header.Get(protocol.CheckInIntervalHeader))
	// the fleet as it was before this check-in: the agent's previous state
	// says whether it checked in before, and with the revoked keys shapes
	// what is stored (the keys kept under the limit, when it joined)
	snap, snapErr := s.readSnapshot(r.Context())
	prev, seen := snap.states[agent.ID]
	records = applyKeyReport(&state, records, prev, seen, snap.revoked, now)
	if snapErr != nil {
		// the check-in is stored all the same, so the agent stays healthy,
		// and key sync waits for the next; without the previous state the
		// join time is unknown, as for agents seen before it was recorded
		state.JoinedAt = nil
	}
	if err := s.store.PutAgentState(r.Context(), state); err != nil {
		s.logger.ErrorContext(r.Context(), "failed to store agent check-in", "agent_id", agent.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if snapErr == nil {
		s.logKeyReport(r.Context(), agent, prev, seen, state, now)
	}
	for _, rec := range records {
		if s.isKnownKey(rec.Fingerprint) {
			continue
		}
		created, err := s.store.PutKeyIfAbsent(r.Context(), rec)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "failed to record key", "agent_id", agent.ID, "fingerprint", rec.Fingerprint, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		s.markKnownKey(rec.Fingerprint)
		if created {
			s.logger.WarnContext(r.Context(), "new sealing key discovered",
				"event", "key.discovered", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster,
				"fingerprint", rec.Fingerprint, "not_before", rec.NotBefore)
		}
	}
	var escrowNeeded []string
	err = snapErr
	if err == nil {
		snap.states[agent.ID] = state
		escrowNeeded, err = s.syncKeys(r.Context(), agent, state, snap, seen)
	}
	if err != nil {
		// key sync catches up on a later check-in; the check-in itself is
		// stored
		s.logger.ErrorContext(r.Context(), "failed to plan key sync",
			"event", "key.sync_failed", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "error", err)
	}
	s.logger.DebugContext(r.Context(), "agent checked in",
		"event", "agent.checkin", "agent_id", agent.ID, "keys", len(state.Keys), "active", state.Controller.ActiveFingerprint)
	next := fleet.CheckInInterval
	if state.CheckInIntervalSeconds > 0 {
		next = state.CheckInInterval()
	}
	httpserver.WriteJSON(w, http.StatusOK, protocol.CheckInResponse{
		NextCheckInSeconds: int(next / time.Second),
		EscrowNeeded:       escrowNeeded,
	})
}

// checkInIntervalSeconds reads an agent's check-in interval header, held
// within the bounds an agent accepts. It is 0 when the header is missing or
// not a whole number of seconds, as from agents that predate it.
func checkInIntervalSeconds(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return min(max(n, int(protocol.MinCheckInInterval/time.Second)), int(protocol.MaxCheckInInterval/time.Second))
}

func (s *Server) isKnownKey(fp string) bool {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	return s.knownKeys[fp]
}

func (s *Server) markKnownKey(fp string) {
	s.knownMu.Lock()
	defer s.knownMu.Unlock()
	if len(s.knownKeys) > 10_000 {
		s.knownKeys = map[string]bool{}
	}
	s.knownKeys[fp] = true
}

// validateCheckIn checks a check-in and turns it into the agent's state and
// the key records it reports. Fingerprints and validity come from parsing
// each certificate, never from the agent's claims. Capabilities are limited
// to those the registry grants; the rest are returned as ignored.
func validateCheckIn(in protocol.CheckIn, agent *registry.Agent, now time.Time) (store.AgentState, []store.KeyRecord, []string, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	version, ok := protocol.Negotiate(in, protocol.Versions)
	switch {
	case len(in.Protocols) > protocol.MaxProtocols:
		fail("too many protocols")
	case !ok:
		fail("unsupported protocol; this control plane speaks %s", strings.Join(protocol.Versions, ", "))
	}
	if len(in.AgentVersion) > maxShortField {
		fail("agent_version is too long")
	}

	var capabilities, ignored []string
	for _, c := range in.Capabilities {
		switch {
		case !protocol.IsCapability(c):
			fail("unknown capability %q", c)
		case slices.Contains(capabilities, c) || slices.Contains(ignored, c):
			fail("duplicate capability %q", c)
		case agent.HasCapability(c):
			capabilities = append(capabilities, c)
		default:
			ignored = append(ignored, c)
		}
	}
	if len(in.Commands) > maxCommands {
		fail("too many commands")
	}
	var commands []string
	for _, c := range in.Commands {
		switch {
		case c == "" || len(c) > maxShortField:
			fail("invalid command type")
		case slices.Contains(commands, c):
			fail("duplicate command type %q", c)
		default:
			// types this control plane does not know are kept for the
			// fleet view but never sent
			commands = append(commands, c)
		}
	}

	ctrl := in.Controller
	if len(validation.IsDNS1123Label(ctrl.Namespace)) > 0 {
		fail("controller namespace must be a DNS-1123 label")
	}
	if len(validation.IsDNS1123Label(ctrl.Name)) > 0 {
		fail("controller name must be a DNS-1123 label")
	}
	if p := ctrl.KeyRenewPeriod; p != "" && p != "0" {
		if _, err := time.ParseDuration(p); err != nil {
			fail("controller key_renew_period is not a duration")
		}
	}
	switch ctrl.KeyOrderPriority {
	case "", "CertNotBefore", "SecretCreationTimestamp":
	default:
		fail("controller key_order_priority is not recognized")
	}

	// more than protocol.MaxKeys keys is not refused: the newest are kept
	if len(in.Keys) == 0 {
		fail("keys must not be empty")
	}
	var refs []store.KeyRef
	var records []store.KeyRecord
	seen := map[string]bool{}
	for i, k := range in.Keys {
		if len(k.Certificate) > protocol.MaxCertificateBytes {
			fail("keys[%d]: certificate too large", i)
			continue
		}
		parsed, _, err := keys.ParseCert([]byte(k.Certificate))
		if err != nil {
			fail("keys[%d]: %v", i, err)
			continue
		}
		if parsed.Fingerprint != k.Fingerprint {
			fail("keys[%d]: fingerprint does not match its certificate", i)
			continue
		}
		if seen[parsed.Fingerprint] {
			fail("keys[%d]: duplicate key", i)
			continue
		}
		seen[parsed.Fingerprint] = true
		ref := store.KeyRef{Fingerprint: parsed.Fingerprint, NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter}
		refs = append(refs, ref)
		records = append(records, store.KeyRecord{
			Fingerprint:    parsed.Fingerprint,
			Certificate:    k.Certificate,
			NotBefore:      parsed.NotBefore,
			NotAfter:       parsed.NotAfter,
			FirstSeenAgent: agent.ID,
			FirstSeenAt:    now,
		})
	}
	if ctrl.ActiveFingerprint == "" || !seen[ctrl.ActiveFingerprint] {
		fail("controller active_fingerprint must be one of the reported keys")
	}

	if len(errs) > 0 {
		return store.AgentState{}, nil, nil, errors.Join(errs...)
	}
	return store.AgentState{
		AgentID:      agent.ID,
		LastCheckIn:  now,
		AgentVersion: in.AgentVersion,
		Protocol:     version,
		Capabilities: capabilities,
		Commands:     commands,
		Controller:   ctrl,
		Keys:         refs,
		KeysComplete: in.KeysComplete,
	}, records, ignored, nil
}
