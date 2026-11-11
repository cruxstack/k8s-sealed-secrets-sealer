package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// File reseal statuses, as users see them.
const (
	resealQueued    = "queued"
	resealResealing = "resealing"
	resealDone      = "done"
	resealFailed    = "failed"
	resealExpired   = "expired"
)

// errNoAgentAnswered is why the values of a command that expired failed.
const errNoAgentAnswered = "no agent answered in time"

// fileResealView is a file reseal's progress.
type fileResealView struct {
	ID       string                `json:"id"`
	Path     string                `json:"path"`
	Status   string                `json:"status"`
	Values   resealValuesView      `json:"values"`
	Failures []store.ResealFailure `json:"failures,omitempty"`
	// ChangeIDs name the pending changes it made.
	ChangeIDs []string   `json:"change_ids,omitempty"`
	Agent     *agentView `json:"agent,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	Error     string     `json:"error,omitempty"`
}

type resealValuesView struct {
	Total    int `json:"total"`
	Resealed int `json:"resealed"`
	Current  int `json:"current"`
	Failed   int `json:"failed"`
	Pending  int `json:"pending"`
}

// requestReseal reseals every value of this env's documents in a file, at
// the session's commit, for an env admin who can write to the repository:
// values on older keys move to the env key, and become pending changes, one
// per key. Values a pending change of the session already sets are left
// out, so a reseal never replaces a value sealed here. Nothing is
// decrypted: the agent only rewraps each value's one-time key.
func (s *Server) requestReseal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
	}
	if !decodeJSON(w, r, maxResealBody, &in) {
		return
	}
	if in.Path == "" || len(in.Path) > maxPathBytes {
		writeError(w, http.StatusBadRequest, "path is required")
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

	// a seal still running has no change yet to leave out; a seal that
	// lands later wins over the reseal anyway (store.Outranks)
	sealing, err := s.sessionCommandRunning(ctx, sess.ID, s.now().UTC(), func(c store.CommandRecord) bool { return c.Type == protocol.CommandSeal })
	if err != nil {
		s.internalError(w, r, "failed to read seal commands", err)
		return
	}
	if sealing {
		writeError(w, http.StatusConflict, "A seal is still running in this session; reseal once it finishes.")
		return
	}

	// write access is checked again, as for a seal
	file, values, err := s.repos.FileValues(ctx, user, sess.Owner, sess.Repo, sess.Commit, in.Path)
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	if file.Error != "" {
		writeError(w, http.StatusUnprocessableEntity, "this file cannot be resealed: "+file.Error)
		return
	}
	if len(file.Documents) == 0 {
		writeError(w, http.StatusConflict, "this file has no SealedSecret for the "+s.env+" env")
		return
	}
	changes, err := s.store.Changes(ctx, sess.ID, false)
	if err != nil {
		s.internalError(w, r, "failed to read pending changes", err)
		return
	}
	plan := planReseal(0, file.Path, file.Documents, values, pendingIn(store.Effective(changes), file.Path))

	now := s.now().UTC()
	agent, envKey, err := s.chooseResealer(ctx, regionsOf(file.Documents), now)
	if msg, refused := resealRefusal(err); refused {
		writeError(w, http.StatusConflict, msg)
		return
	}
	if err != nil {
		s.internalError(w, r, "failed to choose an agent", err)
		return
	}

	packs, tooLarge := packReseal(plan.groups)
	for _, g := range tooLarge {
		for _, v := range g.values {
			plan.failures = append(plan.failures, store.ResealFailure{Key: v.key, Document: v.doc.Index, Region: v.doc.Region, Error: errTooLargeToReseal})
		}
	}
	reseal := store.FileReseal{
		SessionID: sess.ID,
		ID:        ulid.Make().String(),
		Path:      file.Path,
		AgentID:   agent.ID,
		EnvKey:    envKey,
		UserID:    user.ID,
		UserLogin: user.Login,
		CreatedAt: now,
		ExpiresAt: sess.EndsAt,
		Total:     plan.total,
		Pending:   plan.pending,
		Failures:  withoutPath(plan.failures),
	}
	for _, d := range plan.docs {
		reseal.Documents = append(reseal.Documents, store.Target{Index: &d.Index, Namespace: d.Namespace, Name: d.Name, Scope: d.Scope, Region: d.Region})
	}
	var cmds []store.CommandRecord
	places := map[string]string{}
	for _, pack := range packs {
		cmd, err := resealCommand(agent.ID, ulid.Make().String(), resealPayload(envKey, pack), now)
		if err != nil {
			s.internalError(w, r, "failed to prepare a reseal", err)
			return
		}
		cmd.SessionID, cmd.ResealID = sess.ID, reseal.ID
		entry := store.FileResealCommand{ID: cmd.ID}
		for _, g := range pack {
			entry.Keys = append(entry.Keys, g.key)
			places[resealChangeID(file.Path, g.key, reseal.ID)] = cmd.ID
			for _, v := range g.values {
				entry.Items = append(entry.Items, resealItemID(v.file, v.doc.Index, v.key))
			}
		}
		reseal.Commands = append(reseal.Commands, entry)
		cmds = append(cmds, cmd)
	}

	// each key's change takes a place among the session's pending changes;
	// those still running hold theirs until they are done
	if len(places) > 0 {
		existing := make([]string, len(changes))
		for i, c := range changes {
			existing[i] = c.ID
		}
		err = s.store.ReserveChanges(ctx, sess.ID, places, existing, maxChangesPerSession, now.Add(resealChangeHold), now)
		switch {
		case errors.Is(err, store.ErrTooManyChanges):
			writeError(w, http.StatusConflict, fmt.Sprintf(
				"resealing this file can make %s, one for each key with values to reseal, and this session holds %d of the %d it can; open a pull request with them first",
				plural(len(places), "change"), len(changes), maxChangesPerSession))
			return
		case err != nil:
			s.internalError(w, r, "failed to reserve pending changes", err)
			return
		}
	}
	// recorded before its commands are queued, so every result finds it
	if err := s.store.PutFileReseal(ctx, reseal); err != nil {
		s.internalError(w, r, "failed to record reseal", err)
		return
	}
	for _, cmd := range cmds {
		if err := s.store.PutCommand(ctx, cmd); err != nil {
			s.internalError(w, r, "failed to queue reseal", err)
			return
		}
	}
	switch ok, err := s.touch(ctx, sess, now); {
	case errors.Is(err, store.ErrSessionBusy):
		writeError(w, http.StatusConflict, err.Error()+"; reseal the file again once it is open")
		return
	case err != nil:
		s.internalError(w, r, "failed to mark session used", err)
		return
	case !ok:
		writeError(w, http.StatusNotFound, "session not found; it may have expired or been discarded")
		return
	}
	sent := 0
	for _, c := range reseal.Commands {
		sent += len(c.Items)
	}
	s.logger.InfoContext(ctx, "reseal requested",
		"event", "reseal.requested", "env", s.env, "session_id", sess.ID, "reseal_id", reseal.ID,
		"user", user.Login, "user_id", user.ID, "repository", sess.Owner+"/"+sess.Repo, "path", file.Path,
		"values", plan.total, "sent", sent, "pending", plan.pending, "failed", len(plan.failures),
		"commands", len(cmds), "agent_id", agent.ID, "env_key", envKey)
	v, err := s.viewFileReseal(ctx, reseal, now)
	if err != nil {
		s.internalError(w, r, "failed to read reseal", err)
		return
	}
	httpserver.WriteJSON(w, http.StatusAccepted, v)
}

// pendingIn returns whether a pending change of the session sets a
// document's key in a file: those values are left out of a reseal.
func pendingIn(effective []store.Change, path string) func(manifest.Document, string) bool {
	type at struct {
		key   string
		index int
	}
	type named struct{ key, region, namespace, name string }
	byIndex, byName := map[at]bool{}, map[named]bool{}
	for _, c := range effective {
		if c.Path != path {
			continue
		}
		for _, t := range c.Targets {
			if t.Index != nil {
				byIndex[at{c.Key, *t.Index}] = true
			} else {
				// changes stored before targets recorded positions
				byName[named{c.Key, t.Region, t.Namespace, t.Name}] = true
			}
		}
	}
	return func(d manifest.Document, key string) bool {
		return byIndex[at{key, d.Index}] || byName[named{key, d.Region, d.Namespace, d.Name}]
	}
}

// withoutPath drops the path from failures of one file.
func withoutPath(fs []store.ResealFailure) []store.ResealFailure {
	out := make([]store.ResealFailure, len(fs))
	for i, f := range fs {
		f.Path = ""
		out[i] = f
	}
	return out
}

// getReseal serves a file reseal's progress, for the UI to poll.
func (s *Server) getReseal(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id := r.PathValue("reseal")
	if _, err := ulid.ParseStrict(id); err != nil {
		writeError(w, http.StatusNotFound, "reseal not found")
		return
	}
	reseal, found, err := s.store.FileReseal(ctx, sess.ID, id)
	if err != nil {
		s.internalError(w, r, "failed to read reseal", err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "reseal not found")
		return
	}
	v, err := s.viewFileReseal(ctx, reseal, s.now().UTC())
	if err != nil {
		s.internalError(w, r, "failed to read reseal commands", err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, v)
}

// viewFileReseal views a file reseal from what its commands did: a command
// without an outcome is read for whether it still runs or expired, and the
// values of one that expired failed.
func (s *Server) viewFileReseal(ctx context.Context, fr store.FileReseal, now time.Time) (fileResealView, error) {
	agent := s.agentView(fr.AgentID)
	v := fileResealView{
		ID:        fr.ID,
		Path:      fr.Path,
		Agent:     &agent,
		CreatedAt: fr.CreatedAt,
		Values:    resealValuesView{Total: fr.Total, Pending: fr.Pending, Failed: len(fr.Failures)},
		Failures:  slices.Clone(fr.Failures),
	}
	docs := map[int]store.Target{}
	for _, d := range fr.Documents {
		if d.Index != nil {
			docs[*d.Index] = d
		}
	}
	running, leased, succeeded, failed, expired := 0, false, 0, 0, 0
	var firstError string
	for _, c := range fr.Commands {
		if o, ok := fr.Outcomes[c.ID]; ok {
			v.Values.Resealed += o.Counts.Resealed
			v.Values.Current += o.Counts.Current
			v.Values.Failed += o.Counts.Failed
			v.Failures = append(v.Failures, o.Failures...)
			v.ChangeIDs = append(v.ChangeIDs, o.ChangeIDs...)
			if o.Status == store.CommandSucceeded {
				succeeded++
			} else {
				failed++
				if firstError == "" {
					firstError = o.Error
				}
			}
			continue
		}
		cmd, found, err := s.store.Command(ctx, fr.AgentID, c.ID)
		if err != nil {
			return fileResealView{}, err
		}
		if found && cmd.Open(now) {
			running++
			leased = leased || cmd.Status == store.CommandLeased
			continue
		}
		// expired, or removed an hour after it expired; a result recorded
		// as it finished has its outcome
		expired++
		v.Values.Failed += len(c.Items)
		for _, id := range c.Items {
			_, doc, key, _ := parseResealItemID(id)
			v.Failures = append(v.Failures, store.ResealFailure{Key: key, Document: doc, Region: docs[doc].Region, Error: errNoAgentAnswered})
		}
	}
	sort.SliceStable(v.Failures, func(i, j int) bool {
		a, b := v.Failures[i], v.Failures[j]
		if a.Document != b.Document {
			return a.Document < b.Document
		}
		return a.Key < b.Key
	})
	if len(v.Failures) > maxResealFailures {
		v.Failures = v.Failures[:maxResealFailures]
	}
	switch {
	case running > 0 && (leased || succeeded+failed+expired > 0):
		v.Status = resealResealing
	case running > 0:
		v.Status = resealQueued
	case len(fr.Commands) == 0 || succeeded > 0:
		v.Status = resealDone
	case failed > 0:
		v.Status, v.Error = resealFailed, firstError
		if v.Error == "" {
			v.Error = "the agent could not reseal the values"
		}
	default:
		v.Status, v.Error = resealExpired, "no agent finished resealing in time; reseal the file again"
	}
	return v, nil
}

// finishReseal records a reseal.v1 result: in its session as pending
// changes, or in its run, before the command is marked done, so a command
// that succeeded always has its results kept. It writes the response.
func (s *Server) finishReseal(w http.ResponseWriter, r *http.Request, agent *registry.Agent, cmd store.CommandRecord, in protocol.CommandResult) {
	ctx := r.Context()
	now := s.now().UTC()
	log := s.logger.With("env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster, "command_id", cmd.ID)
	if cmd.Status != store.CommandLeased || !now.Before(cmd.ExpiresAt) {
		writeError(w, http.StatusConflict, "command is not leased or has expired")
		return
	}
	raw, found, err := s.store.CommandPayload(ctx, cmd.ID)
	if err != nil {
		// the command stays leased and expires
		s.internalError(w, r, "failed to read the reseal's payload", err)
		return
	}
	var p protocol.ResealPayload
	if !found || json.Unmarshal([]byte(raw), &p) != nil {
		s.internalError(w, r, "failed to read the reseal's payload", errors.New("missing or invalid"))
		return
	}

	status, errMsg := in.Status, in.Error
	var res protocol.ResealResult
	if status == protocol.CommandSucceeded {
		if err := checkResealResult(p, in.Result, &res); err != nil {
			status, errMsg = protocol.CommandFailed, "the agent returned an invalid result: "+err.Error()
			log.ErrorContext(ctx, "invalid reseal result", "event", "reseal.invalid_result", "error", err)
		}
	}
	// values move only onto a key that is still the env's to seal with
	revoked := false
	if status == protocol.CommandSucceeded && resealCounts(res).Resealed > 0 {
		key, _, err := s.store.GetKey(ctx, p.EnvKey)
		if err != nil {
			s.internalError(w, r, "failed to read key", err)
			return
		}
		if key.Revoked() {
			revoked = true
			status, errMsg = protocol.CommandFailed, "the key the values were resealed with was revoked; reseal them again"
		}
	}
	if status != protocol.CommandSucceeded {
		res = protocol.ResealResult{}
	}

	switch {
	case cmd.RunID != "":
		err = s.recordRunResult(ctx, cmd, p, res, status, errMsg, now)
	case cmd.ResealID != "":
		err = s.recordFileReseal(ctx, cmd, agent, p, res, status, errMsg, now)
	}
	if err != nil {
		// the command stays leased and expires; its values count as failed
		s.internalError(w, r, "failed to record reseal results", err)
		return
	}
	counts := resealCounts(res)
	if status != protocol.CommandSucceeded {
		counts = store.ResealCounts{Failed: len(p.Items)}
	}
	summary, _ := json.Marshal(counts)
	ok, err := s.store.FinishCommand(ctx, agent.ID, cmd.ID, status, string(summary), errMsg, now)
	if err != nil {
		s.internalError(w, r, "failed to record command result", err)
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "command is not leased or has expired")
		return
	}
	fields := []any{"resealed", counts.Resealed, "current", counts.Current, "failed", counts.Failed,
		"session_id", cmd.SessionID, "reseal_id", cmd.ResealID, "run_id", cmd.RunID, "repository", cmd.RunRepo}
	if status == protocol.CommandSucceeded {
		log.InfoContext(ctx, "values resealed", append([]any{"event", "command.finished", "type", cmd.Type, "status", status}, fields...)...)
	} else {
		log.WarnContext(ctx, "reseal failed", append([]any{"event", "reseal.failed", "error", errMsg}, fields...)...)
	}
	// the agent did its part when only the key's revocation failed it
	if in.Status == protocol.CommandSucceeded && status != protocol.CommandSucceeded && !revoked {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}

// recordFileReseal turns a reseal.v1 result of a session into pending
// changes, one per key with resealed values, each setting only the
// documents whose value was resealed, and records what the command did.
func (s *Server) recordFileReseal(ctx context.Context, cmd store.CommandRecord, agent *registry.Agent, p protocol.ResealPayload, res protocol.ResealResult, status, errMsg string, now time.Time) error {
	fr, found, err := s.store.FileReseal(ctx, cmd.SessionID, cmd.ResealID)
	if err != nil {
		return err
	}
	if !found {
		// the session ended; nothing is left to record in
		return nil
	}
	docs := map[int]store.Target{}
	for _, d := range fr.Documents {
		if d.Index != nil {
			docs[*d.Index] = d
		}
	}
	outcome := store.ResealOutcome{Status: status, Error: errMsg, FinishedAt: now}
	type keyChange struct {
		targets     []store.Target
		ciphertexts []string
		from        []string
	}
	byKey := map[string]*keyChange{}
	var keys []string
	if status == protocol.CommandSucceeded {
		outcome.Counts = resealCounts(res)
		for _, it := range res.Items {
			_, doc, key, ok := parseResealItemID(it.ID)
			target, known := docs[doc]
			if !ok || !known {
				return fmt.Errorf("reseal %s has no document for item %q", fr.ID, it.ID)
			}
			switch it.Status {
			case protocol.ResealResealed:
				c := byKey[key]
				if c == nil {
					c = &keyChange{}
					byKey[key] = c
					keys = append(keys, key)
				}
				c.targets = append(c.targets, target)
				c.ciphertexts = append(c.ciphertexts, it.Ciphertext)
				if !slices.Contains(c.from, it.From) {
					c.from = append(c.from, it.From)
				}
			case protocol.ResealFailed:
				outcome.Failures = append(outcome.Failures, store.ResealFailure{Key: key, Document: doc, Region: target.Region, Error: it.Error})
			}
		}
	} else {
		outcome.Counts.Failed = len(p.Items)
		for _, it := range p.Items {
			_, doc, key, _ := parseResealItemID(it.ID)
			outcome.Failures = append(outcome.Failures, store.ResealFailure{Key: key, Document: doc, Region: docs[doc].Region, Error: errMsg})
		}
	}
	if len(outcome.Failures) > maxResealFailures {
		outcome.Failures = outcome.Failures[:maxResealFailures]
	}
	slices.Sort(keys)
	for _, key := range keys {
		c := byKey[key]
		slices.Sort(c.from)
		change := store.Change{
			SessionID:    fr.SessionID,
			ID:           resealChangeID(fr.Path, key, fr.ID),
			Path:         fr.Path,
			Key:          key,
			CommandID:    cmd.ID,
			AgentID:      agent.ID,
			Fingerprint:  p.EnvKey,
			Targets:      c.targets,
			Ciphertexts:  c.ciphertexts,
			UserID:       fr.UserID,
			UserLogin:    fr.UserLogin,
			SealedAt:     now,
			ExpiresAt:    fr.ExpiresAt,
			Kind:         store.ChangeReseal,
			ResealedFrom: c.from,
		}
		stored, err := s.store.PutChange(ctx, change)
		if err != nil {
			return fmt.Errorf("failed to store the change of %s: %w", key, err)
		}
		if stored {
			outcome.ChangeIDs = append(outcome.ChangeIDs, change.ID)
		}
	}
	if len(keys) > 0 {
		s.pruneChanges(ctx, fr.SessionID, s.logger.With("env", s.env, "session_id", fr.SessionID))
	}
	// its changes hold their own places now, or the command failed: either
	// way it gives up the places it held
	places := map[string]string{}
	for _, c := range fr.Commands {
		if c.ID == cmd.ID {
			for _, key := range c.Keys {
				places[resealChangeID(fr.Path, key, fr.ID)] = cmd.ID
			}
		}
	}
	if len(places) > 0 {
		if err := s.store.ReleaseChanges(ctx, fr.SessionID, places, now); err != nil {
			s.logger.WarnContext(ctx, "failed to release the reseal's places among pending changes", "reseal_id", fr.ID, "error", err)
		}
	}
	if _, err := s.store.RecordResealOutcome(ctx, fr.SessionID, fr.ID, cmd.ID, outcome); err != nil {
		return err
	}
	return nil
}
