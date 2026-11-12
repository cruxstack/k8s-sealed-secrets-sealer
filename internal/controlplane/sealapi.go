package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Seal limits.
const (
	// sealCommandTTL is how long a seal waits to be leased and run.
	sealCommandTTL = 2 * time.Minute
	// sealChangeHold is how long a seal holds a place among its session's
	// pending changes: until its command expires, and a minute for a
	// result recorded as it does.
	sealChangeHold = sealCommandTTL + time.Minute
	// maxSealBody bounds a seal request: a value of MaxSealValueBytes,
	// even with JSON escaping, and its path and key.
	maxSealBody = 512 << 10
	// maxPathBytes bounds a file path.
	maxPathBytes = 1024
	// maxCiphertextChars bounds one base64 ciphertext in a seal result.
	maxCiphertextChars = (protocol.MaxSealValueBytes+protocol.SealOverheadBytes)*4/3 + 4
	// maxRegions bounds the regions a seal names.
	maxRegions = 64
)

// Seal statuses, as users see them.
const (
	sealQueued  = "queued"
	sealSealing = "sealing"
	sealSealed  = "sealed"
	sealFailed  = "failed"
	sealExpired = "expired"
	// sealSuperseded is a value sealed and then replaced in the session by
	// a newer seal of the same key for the same documents.
	sealSuperseded = "superseded"
)

// sealView is a seal's progress.
type sealView struct {
	ID          string       `json:"id"`
	Status      string       `json:"status"`
	Path        string       `json:"path"`
	Key         string       `json:"key"`
	Regions     []string     `json:"regions,omitempty"`
	Targets     []targetView `json:"targets"`
	Agent       agentView    `json:"agent"`
	Fingerprint string       `json:"fingerprint"`
	CreatedAt   time.Time    `json:"created_at"`
	// ChangeID names the pending change a sealed value went into.
	ChangeID string `json:"change_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

// changeID is the ID of the pending change for a key in a file, sealed for
// some regions or, with none, every document: sealing the same key into the
// same file for the same regions again replaces it.
func changeID(path, key string, regions []string) string {
	id := path + "\x00" + key
	if len(regions) > 0 {
		id += "\x00" + strings.Join(regions, "\x00")
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

// sealRegions checks the regions a seal names against a file's documents
// and returns them sorted, or nil when they reach every document: naming
// every region is sealing for all. Each must be a region of a document. A
// file with a document that lists several regions can be sealed only for
// all of them: the regions it lists share that document.
func sealRegions(named []string, docs []manifest.Document) ([]string, error) {
	if len(named) == 0 {
		return nil, nil
	}
	if len(named) > maxRegions {
		return nil, fmt.Errorf("at most %d regions can be named", maxRegions)
	}
	have := map[string]bool{}
	unlabelled, shared := false, false
	for _, d := range docs {
		if len(d.Regions) == 0 {
			unlabelled = true
		}
		if len(d.Regions) > 1 {
			shared = true
		}
		for _, r := range d.Regions {
			have[r] = true
		}
	}
	regions := slices.Clone(named)
	slices.Sort(regions)
	regions = slices.Compact(regions)
	for _, r := range regions {
		if !manifest.IsRegion(r) {
			return nil, errors.New("regions must be region names: lowercase DNS labels of at most 63 characters")
		}
		if !have[r] {
			return nil, fmt.Errorf("no document of this file for the env is in region %q", r)
		}
	}
	if !unlabelled && len(regions) == len(have) {
		return nil, nil
	}
	if shared {
		return nil, errors.New("a document of this file lists several regions, which share it, so a value can't be sealed for some regions only: seal it for every document")
	}
	return regions, nil
}

func validChangeID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

// requestSeal seals a value into the SealedSecret documents for this env in
// a file, as one seal.v1 command: every document, or with regions named,
// those in the regions. The value is encrypted under the transit key as
// soon as it arrives and is never stored, logged or returned.
func (s *Server) requestSeal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path  string `json:"path"`
		Key   string `json:"key"`
		Value string `json:"value"`
		// Regions limits the seal to the file's documents in them.
		Regions []string `json:"regions"`
	}
	if !decodeJSON(w, r, maxSealBody, &in) {
		return
	}
	switch {
	case in.Path == "" || len(in.Path) > maxPathBytes:
		writeError(w, http.StatusBadRequest, "path is required")
		return
	case len(validation.IsConfigMapKey(in.Key)) > 0:
		writeError(w, http.StatusBadRequest, "key must be a valid Secret key: letters, digits, '-', '_' or '.', at most 253 characters")
		return
	case in.Value == "":
		writeError(w, http.StatusBadRequest, "value is required")
		return
	case len(in.Value) > protocol.MaxSealValueBytes:
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("value is larger than %d KiB", protocol.MaxSealValueBytes>>10))
		return
	}
	sess, ok := s.currentSession(w, r)
	if !ok {
		return
	}
	if sess.Locked(s.now()) {
		writeError(w, http.StatusConflict, store.ErrSessionBusy.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sessionRequestTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)

	// write access is checked again on every seal
	file, err := s.repos.File(ctx, user, sess.Owner, sess.Repo, sess.Commit, in.Path, true)
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	if file.Error != "" {
		writeError(w, http.StatusUnprocessableEntity, "this file cannot be sealed into: "+file.Error)
		return
	}
	if len(file.Documents) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "this file has no SealedSecret for the "+s.env+" env")
		return
	}
	for _, d := range file.Documents {
		if !d.Sealable() {
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("this file cannot be sealed into: %s/%s: %s", d.Namespace, d.Name, d.Problem))
			return
		}
	}
	sealFor, err := sealRegions(in.Regions, file.Documents)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	var targets []store.Target
	var targeted []manifest.Document
	for _, d := range file.Documents {
		if len(sealFor) > 0 && !d.InRegions(sealFor) {
			continue
		}
		targeted = append(targeted, d)
		targets = append(targets, store.Target{Index: &d.Index, Namespace: d.Namespace, Name: d.Name, Scope: d.Scope, Regions: d.Regions})
	}
	// an agent in one of the documents' regions is preferred
	regions := manifest.RegionsOf(targeted)
	if !protocol.SealFits(len(in.Value), len(targets)) {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("value is too large to seal for %d documents", len(targets)))
		return
	}
	changes, err := s.store.Changes(ctx, sess.ID, false)
	if err != nil {
		s.internalError(w, r, "failed to read pending changes", err)
		return
	}
	existing := make([]string, len(changes))
	for i, c := range changes {
		existing[i] = c.ID
	}
	// seals still running count toward the cap too: each holds its
	// change's place until it is done
	commandID := ulid.Make().String()
	reservedAt := s.now().UTC()
	err = s.store.ReserveChange(ctx, sess.ID, changeID(file.Path, in.Key, sealFor), commandID, existing,
		maxChangesPerSession, reservedAt.Add(sealChangeHold), reservedAt)
	switch {
	case errors.Is(err, store.ErrTooManyChanges):
		writeError(w, http.StatusConflict, sessionFull(changes))
		return
	case err != nil:
		s.internalError(w, r, "failed to reserve a pending change", err)
		return
	}

	now := s.now().UTC()
	agent, envKey, err := s.chooseSealer(ctx, regions, now)
	var outOfSync *fleet.KeysOutOfSyncError
	switch {
	case errors.As(err, &outOfSync):
		s.logger.WarnContext(ctx, "seal refused: no key is held by every cluster",
			"event", "keys.out_of_sync", "env", s.env, "clusters", outOfSync.Clusters, "user", user.Login)
		writeError(w, http.StatusConflict, outOfSync.Error())
		return
	case errors.Is(err, fleet.ErrNoUsableKey):
		s.logger.WarnContext(ctx, "seal refused: every key the clusters share is revoked or dated in the future; a new key is needed",
			"event", "keys.out_of_sync", "env", s.env, "reason", "no_usable_key", "user", user.Login)
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, fleet.ErrNoSealer):
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	case err != nil:
		s.internalError(w, r, "failed to choose an agent", err)
		return
	}

	value := []byte(in.Value)
	sealed, err := envelope.Seal(ctx, s.transit, s.transitKey, value, protocol.SealContext(s.env, commandID, agent.ID))
	clear(value)
	if err != nil {
		s.internalError(w, r, "failed to encrypt value for transit", err)
		return
	}
	secret, err := json.Marshal(sealed)
	if err != nil {
		s.internalError(w, r, "failed to encode transit envelope", err)
		return
	}

	// The command is queued before the session is marked used: a pull
	// request locks the session and then waits for queued seals, so a seal
	// is either in the pull request or refused here.
	seal := store.Seal{
		SessionID:   sess.ID,
		CommandID:   commandID,
		AgentID:     agent.ID,
		Path:        file.Path,
		Key:         in.Key,
		Fingerprint: envKey,
		Regions:     sealFor,
		Targets:     targets,
		UserID:      user.ID,
		UserLogin:   user.Login,
		CreatedAt:   now,
		ExpiresAt:   sess.EndsAt,
	}
	if err := s.store.PutSeal(ctx, seal); err != nil {
		s.internalError(w, r, "failed to record seal", err)
		return
	}
	payload := protocol.SealPayload{Key: in.Key, Fingerprint: envKey}
	for _, t := range targets {
		payload.Targets = append(payload.Targets, protocol.SealTarget{Namespace: t.Namespace, Name: t.Name, Scope: t.Scope})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.internalError(w, r, "failed to encode seal payload", err)
		return
	}
	err = s.store.PutCommand(ctx, store.CommandRecord{
		AgentID:   agent.ID,
		ID:        commandID,
		Type:      protocol.CommandSeal,
		Status:    store.CommandQueued,
		CreatedAt: now,
		ExpiresAt: now.Add(sealCommandTTL),
		Payload:   string(body),
		Secret:    string(secret),
		SessionID: sess.ID,
	})
	if err != nil {
		s.internalError(w, r, "failed to queue seal", err)
		return
	}
	switch ok, err := s.touch(ctx, sess, now); {
	case errors.Is(err, store.ErrSessionBusy):
		writeError(w, http.StatusConflict, err.Error()+"; seal the value again once it is open")
		return
	case err != nil:
		s.internalError(w, r, "failed to mark session used", err)
		return
	case !ok:
		writeError(w, http.StatusNotFound, "session not found; it may have expired or been discarded")
		return
	}
	s.logger.InfoContext(ctx, "seal requested",
		"event", "seal.requested", "env", s.env, "session_id", sess.ID, "command_id", commandID,
		"user", user.Login, "user_id", user.ID, "repository", sess.Owner+"/"+sess.Repo, "path", file.Path,
		"key", in.Key, "regions", sealFor, "targets", len(targets), "agent_id", agent.ID, "fingerprint", envKey)
	httpserver.WriteJSON(w, http.StatusAccepted, s.viewSeal(seal, sealQueued, ""))
}

// sessionFull says why a session has no room for another change. Changes
// newer seals of the same key cover between them are not shown, yet count:
// removing one of those brings them back. So do seals still running.
func sessionFull(changes []store.Change) string {
	shown := map[string]bool{}
	for _, c := range store.Effective(changes) {
		shown[c.ID] = true
	}
	var hidden []string
	for _, c := range changes {
		if !shown[c.ID] {
			name := plain(c.Path) + ": " + c.Key
			if len(c.Regions) > 0 {
				name += " in " + plain(strings.Join(c.Regions, ", "))
			}
			hidden = append(hidden, name)
		}
	}
	msg := fmt.Sprintf("this session holds %d pending changes, the most it can", maxChangesPerSession)
	if len(hidden) > 0 {
		const named = 5
		list := strings.Join(hidden[:min(len(hidden), named)], "; ")
		if len(hidden) > named {
			list += fmt.Sprintf("; and %d more", len(hidden)-named)
		}
		msg += fmt.Sprintf(", including %s not shown, under newer seals of the same key (%s)", plural(len(hidden), "change"), list)
	}
	if running := maxChangesPerSession - len(changes); running > 0 {
		msg += fmt.Sprintf(", and %s still running", plural(running, "seal"))
	}
	return msg + "; open a pull request with them first"
}

// chooseSealer picks the agent for a seal and returns it with the env key.
func (s *Server) chooseSealer(ctx context.Context, regions []string, now time.Time) (fleet.Agent, string, error) {
	return s.chooseAgent(ctx, regions, now, fleet.ChooseSealer)
}

// chooseAgent picks an agent with choose, counting the commands in flight
// of each that might be chosen, and returns it with the env key.
func (s *Server) chooseAgent(ctx context.Context, regions []string, now time.Time, choose func(fleet.Fleet, []string, map[string]int) (fleet.Agent, error)) (fleet.Agent, string, error) {
	f, err := s.loadFleet(ctx, now, false)
	if err != nil {
		return fleet.Agent{}, "", err
	}
	// commands in flight, counted only for agents that might be chosen
	inFlight := map[string]int{}
	for _, a := range f.Agents {
		if !a.Healthy {
			continue
		}
		cmds, err := s.openCommands(ctx, a.ID, now)
		if err != nil {
			return fleet.Agent{}, "", err
		}
		inFlight[a.ID] = len(cmds)
	}
	agent, err := choose(f, regions, inFlight)
	if err != nil {
		return fleet.Agent{}, "", err
	}
	return agent, f.EnvKey.Fingerprint, nil
}

func (s *Server) viewSeal(seal store.Seal, status, errMsg string) sealView {
	return sealView{
		ID:          seal.CommandID,
		Status:      status,
		Path:        seal.Path,
		Key:         seal.Key,
		Regions:     seal.Regions,
		Targets:     viewTargets(seal.Targets),
		Agent:       s.agentView(seal.AgentID),
		Fingerprint: seal.Fingerprint,
		CreatedAt:   seal.CreatedAt,
		Error:       errMsg,
	}
}

// getSeal serves a seal's progress, for the UI to poll.
func (s *Server) getSeal(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id := r.PathValue("seal")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, "seal not found")
		return
	}
	seal, found, err := s.store.Seal(ctx, sess.ID, id)
	if err != nil {
		s.internalError(w, r, "failed to read seal", err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "seal not found")
		return
	}
	cmd, found, err := s.store.Command(ctx, seal.AgentID, seal.CommandID)
	if err != nil {
		s.internalError(w, r, "failed to read seal command", err)
		return
	}
	now := s.now().UTC()
	var v sealView
	switch {
	case !found || cmd.Expired(now):
		// commands are removed an hour after they expire
		v = s.viewSeal(seal, sealExpired, "no agent finished sealing in time; seal the value again")
	case cmd.Status == store.CommandQueued:
		v = s.viewSeal(seal, sealQueued, "")
	case cmd.Status == store.CommandLeased:
		v = s.viewSeal(seal, sealSealing, "")
	case cmd.Status == store.CommandSucceeded:
		pending, err := s.sealPending(ctx, seal)
		if err != nil {
			s.internalError(w, r, "failed to read pending changes", err)
			return
		}
		if !pending {
			v = s.viewSeal(seal, sealSuperseded, "a newer seal of this key replaced the value")
			break
		}
		v = s.viewSeal(seal, sealSealed, "")
		v.ChangeID = changeID(seal.Path, seal.Key, seal.Regions)
	default:
		v = s.viewSeal(seal, sealFailed, cmd.Error)
		if v.Error == "" {
			v.Error = "the agent could not seal the value"
		}
	}
	httpserver.WriteJSON(w, http.StatusOK, v)
}

// finishSeal records a seal.v1 result: the ciphertexts become a pending
// change in the seal's session before the command is marked done, so a
// succeeded seal always has its change. It writes the response.
func (s *Server) finishSeal(w http.ResponseWriter, r *http.Request, agent *registry.Agent, cmd store.CommandRecord, in protocol.CommandResult) {
	ctx := r.Context()
	now := s.now().UTC()
	log := s.logger.With("env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "command_id", cmd.ID, "session_id", cmd.SessionID)
	if cmd.Status != store.CommandLeased || !now.Before(cmd.ExpiresAt) {
		writeError(w, http.StatusConflict, "command is not leased or has expired")
		return
	}
	seal, found, err := s.store.Seal(ctx, cmd.SessionID, cmd.ID)
	if err != nil {
		s.internalError(w, r, "failed to read seal", err)
		return
	}

	status, errMsg := in.Status, in.Error
	var res protocol.SealResult
	if status == protocol.CommandSucceeded {
		switch {
		case !found:
			status, errMsg = protocol.CommandFailed, "the seal's session record is missing"
		default:
			if err := checkSealResult(cmd, in.Result, &res); err != nil {
				status, errMsg = protocol.CommandFailed, "the agent returned an invalid result: "+err.Error()
				log.ErrorContext(ctx, "invalid seal result", "event", "seal.invalid_result", "error", err)
			}
		}
	}
	// a key revoked while the seal waited or ran seals nothing more: its
	// value never becomes a pending change
	revoked := false
	if status == protocol.CommandSucceeded {
		key, _, err := s.store.GetKey(ctx, res.Fingerprint)
		if err != nil {
			// the command stays leased and expires; the user seals again
			s.internalError(w, r, "failed to read key", err)
			return
		}
		if key.Revoked() {
			revoked = true
			status, errMsg = protocol.CommandFailed, "the key was revoked; seal the value again"
		}
	}

	summary := ""
	if status == protocol.CommandSucceeded {
		ciphertexts := make([]string, len(res.Targets))
		for i, t := range res.Targets {
			ciphertexts[i] = t.Ciphertext
		}
		stored, err := s.store.PutChange(ctx, store.Change{
			SessionID:   seal.SessionID,
			ID:          changeID(seal.Path, seal.Key, seal.Regions),
			Path:        seal.Path,
			Key:         seal.Key,
			CommandID:   cmd.ID,
			AgentID:     agent.ID,
			Fingerprint: res.Fingerprint,
			Regions:     seal.Regions,
			Targets:     seal.Targets,
			Ciphertexts: ciphertexts,
			UserID:      seal.UserID,
			UserLogin:   seal.UserLogin,
			SealedAt:    now,
			ExpiresAt:   seal.ExpiresAt,
		})
		if err != nil {
			// the command stays leased and expires; the user seals again
			s.internalError(w, r, "failed to store pending change", err)
			return
		}
		if !stored {
			log.InfoContext(ctx, "a newer seal of the same key already landed", "event", "seal.superseded")
		} else {
			s.pruneChanges(ctx, seal.SessionID, log)
		}
		b, _ := json.Marshal(map[string]any{"fingerprint": res.Fingerprint, "targets": len(res.Targets)})
		summary = string(b)
	}

	// the seal's change holds its own place now, or the seal failed:
	// either way it gives up the place it held, so removing the change
	// frees one
	if found {
		if err := s.store.ReleaseChange(ctx, seal.SessionID, changeID(seal.Path, seal.Key, seal.Regions), cmd.ID, now); err != nil {
			log.WarnContext(ctx, "failed to release the seal's place among pending changes", "error", err)
		}
	}
	ok, err := s.store.FinishCommand(ctx, agent.ID, cmd.ID, status, summary, errMsg, now)
	if err != nil {
		s.internalError(w, r, "failed to record command result", err)
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "command is not leased or has expired")
		return
	}
	fields := []any{"user", seal.UserLogin, "path", seal.Path, "key", seal.Key, "fingerprint", seal.Fingerprint}
	if status == protocol.CommandSucceeded {
		log.InfoContext(ctx, "value sealed", append([]any{"event", "seal.succeeded", "targets", len(res.Targets)}, fields...)...)
	} else {
		log.WarnContext(ctx, "seal failed", append([]any{"event", "seal.failed", "error", errMsg}, fields...)...)
	}
	// the agent did its part when only the key's revocation failed it
	if in.Status == protocol.CommandSucceeded && status != protocol.CommandSucceeded && !revoked {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}

// sealPending reports whether a finished seal's value is still a pending
// change of its session, as the session shows it: not when a newer seal of
// the same key replaced it, or newer seals cover all its documents.
func (s *Server) sealPending(ctx context.Context, seal store.Seal) (bool, error) {
	changes, err := s.store.Changes(ctx, seal.SessionID, false)
	if err != nil {
		return false, err
	}
	id := changeID(seal.Path, seal.Key, seal.Regions)
	return slices.ContainsFunc(store.Effective(changes), func(c store.Change) bool {
		return c.ID == id && c.CommandID == seal.CommandID
	}), nil
}

// pruneChanges removes the session's changes that one newer change covers
// for every document, such as a seal for one region followed by one for
// all. Changes that newer ones only cover between them stay, so removing
// one of those brings the older value back. Overlapping changes are
// resolved when read anyway (store.Effective), so a failure here only
// leaves the list longer than it needs to be.
func (s *Server) pruneChanges(ctx context.Context, sessionID string, log *slog.Logger) {
	changes, err := s.store.Changes(ctx, sessionID, false)
	if err != nil {
		log.WarnContext(ctx, "failed to read changes to prune", "error", err)
		return
	}
	for _, c := range store.Superseded(changes) {
		// only if no newer seal replaced it since it was read
		if _, err := s.store.PruneChange(ctx, sessionID, c.ID, c.CommandID); err != nil {
			log.WarnContext(ctx, "failed to prune a covered change", "change_id", c.ID, "error", err)
		}
	}
}

// checkSealResult checks that a result has one well-formed ciphertext for
// each target the command asked for, in order, made with its key.
func checkSealResult(cmd store.CommandRecord, raw json.RawMessage, res *protocol.SealResult) error {
	var p protocol.SealPayload
	if err := json.Unmarshal([]byte(cmd.Payload), &p); err != nil {
		return fmt.Errorf("failed to decode the command's payload: %w", err)
	}
	// fields a newer agent adds are ignored, as in every agent message
	if len(raw) == 0 || json.Unmarshal(raw, res) != nil {
		return errors.New("not a seal result")
	}
	if res.Fingerprint != p.Fingerprint {
		return errors.New("sealed with another key")
	}
	if len(res.Targets) != len(p.Targets) {
		return fmt.Errorf("%d ciphertexts for %d targets", len(res.Targets), len(p.Targets))
	}
	for i, t := range res.Targets {
		want := p.Targets[i]
		if t.Namespace != want.Namespace || t.Name != want.Name {
			return fmt.Errorf("target %d is %s/%s, want %s/%s", i, t.Namespace, t.Name, want.Namespace, want.Name)
		}
		if t.Ciphertext == "" || len(t.Ciphertext) > maxCiphertextChars {
			return fmt.Errorf("target %d has no usable ciphertext", i)
		}
		if _, err := base64.StdEncoding.DecodeString(t.Ciphertext); err != nil {
			return fmt.Errorf("target %d's ciphertext is not base64", i)
		}
	}
	return nil
}
