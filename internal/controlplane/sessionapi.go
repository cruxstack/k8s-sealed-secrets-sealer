package controlplane

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Session limits (docs/design.md, section 11).
const (
	// sessionIdleTimeout ends a session nobody has used for this long.
	sessionIdleTimeout = time.Hour
	// sessionMaxAge ends a session this long after it opened, used or not.
	sessionMaxAge = 8 * time.Hour
	// maxSessionsPerUser bounds a user's open sessions, one per repository.
	maxSessionsPerUser = 10
	// sessionRequestTimeout bounds session requests, which wait on GitHub.
	sessionRequestTimeout = 25 * time.Second
	// maxOpenSessionBody bounds a request to open a session.
	maxOpenSessionBody = 1 << 10
)

// sessionView is a session as its owner sees it.
type sessionView struct {
	ID         string    `json:"id"`
	Repository string    `json:"repository"`
	Owner      string    `json:"owner"`
	Repo       string    `json:"repo"`
	Branch     string    `json:"branch"`
	Commit     string    `json:"commit"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	EndsAt     time.Time `json:"ends_at"`
	// PendingChanges counts Changes; listings carry only the count.
	PendingChanges int          `json:"pending_changes"`
	Changes        []changeView `json:"changes,omitempty"`
}

// changeView is a pending change without its ciphertexts, which are never
// returned to clients. Its targets are the documents it still sets: a newer
// change of the same key for some of them takes those over.
type changeView struct {
	ID   string `json:"id"`
	Path string `json:"path"`
	Key  string `json:"key"`
	// Regions is what the seal was limited to; absent for every document.
	Regions     []string     `json:"regions,omitempty"`
	Targets     []targetView `json:"targets"`
	SealedAt    time.Time    `json:"sealed_at"`
	SealedBy    agentView    `json:"sealed_by"`
	Fingerprint string       `json:"fingerprint"`
}

type targetView struct {
	// Index is the document's position in the file, when recorded.
	Index     *int   `json:"index,omitempty"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Region    string `json:"region,omitempty"`
}

// agentView names an agent for users.
type agentView struct {
	ID      string `json:"id"`
	Cluster string `json:"cluster,omitempty"`
	Region  string `json:"region,omitempty"`
}

// viewSession views a session with its changes as they apply: changes a
// newer one covers are left out, and those it partly covers lose the
// documents it took over.
func viewSession(s store.Session, changes []store.Change, agent func(string) agentView) sessionView {
	if changes != nil {
		changes = store.Effective(changes)
	}
	v := sessionView{
		ID:         s.ID,
		Repository: s.Owner + "/" + s.Repo,
		Owner:      s.Owner,
		Repo:       s.Repo,
		Branch:     s.Branch,
		Commit:     s.Commit,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
		EndsAt:     s.EndsAt,

		PendingChanges: len(changes),
	}
	if changes != nil {
		v.Changes = []changeView{}
	}
	// by file, then key, then regions (every document first), as people
	// read them
	changes = slices.Clone(changes)
	slices.SortFunc(changes, compareChanges)
	for _, c := range changes {
		v.Changes = append(v.Changes, changeView{
			ID:          c.ID,
			Path:        c.Path,
			Key:         c.Key,
			Regions:     c.Regions,
			Targets:     viewTargets(c.Targets),
			SealedAt:    c.SealedAt,
			SealedBy:    agent(c.AgentID),
			Fingerprint: c.Fingerprint,
		})
	}
	return v
}

// compareChanges orders changes by file, key and regions, with a change for
// every document before those for some regions.
func compareChanges(a, b store.Change) int {
	return cmp.Or(
		strings.Compare(a.Path, b.Path),
		strings.Compare(a.Key, b.Key),
		slices.Compare(a.Regions, b.Regions),
	)
}

func viewTargets(ts []store.Target) []targetView {
	out := make([]targetView, len(ts))
	for i, t := range ts {
		out[i] = targetView(t)
	}
	return out
}

// agentView names an agent from the registry; an agent since removed is
// named by its ID alone.
func (s *Server) agentView(id string) agentView {
	if a, ok := s.currentRegistry().Agent(id); ok {
		return agentView{ID: a.ID, Cluster: a.Cluster, Region: a.Region}
	}
	return agentView{ID: id}
}

// listSessions serves the signed-in user's open sessions, with how many
// pending changes each has.
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	sessions, err := s.store.Sessions(ctx, user.ID, s.now().UTC())
	if err != nil {
		s.internalError(w, r, "failed to read sessions", err)
		return
	}
	out := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		changes, err := s.store.Changes(ctx, sess.ID, false)
		if err != nil {
			s.internalError(w, r, "failed to read pending changes", err)
			return
		}
		v := viewSession(sess, nil, s.agentView)
		v.PendingChanges = len(store.Effective(changes))
		out = append(out, v)
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// getSession serves the user's open session for a repository, with its
// pending changes, or null when there is none.
func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), sessionRequestTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	owner, name := r.PathValue("owner"), r.PathValue("repo")
	if _, err := s.repos.Require(ctx, user, owner, name, false); err != nil {
		s.repoError(w, r, err)
		return
	}
	sess, ok, err := s.store.Session(ctx, user.ID, store.RepoKey(owner, name), s.now().UTC())
	if err != nil {
		s.internalError(w, r, "failed to read session", err)
		return
	}
	if !ok {
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"session": nil})
		return
	}
	s.writeSession(w, r, http.StatusOK, sess)
}

func (s *Server) writeSession(w http.ResponseWriter, r *http.Request, status int, sess store.Session) {
	changes, err := s.store.Changes(r.Context(), sess.ID, false)
	if err != nil {
		s.internalError(w, r, "failed to read pending changes", err)
		return
	}
	httpserver.WriteJSON(w, status, map[string]any{"session": viewSession(sess, changes, s.agentView)})
}

// createSession opens a session for a repository at the head of its default
// branch, or returns the user's open one. The user must be able to write to
// the repository. When commit is given, it must still be the head: the user
// is about to seal into what they saw.
func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Commit string `json:"commit"`
	}
	if !decodeJSON(w, r, maxOpenSessionBody, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sessionRequestTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	repo, head, err := s.repos.Head(ctx, user, r.PathValue("owner"), r.PathValue("repo"), true)
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	now := s.now().UTC()
	existing, ok, err := s.store.Session(ctx, user.ID, store.RepoKey(repo.Owner, repo.Name), now)
	if err != nil {
		s.internalError(w, r, "failed to read session", err)
		return
	}
	if ok {
		s.writeSession(w, r, http.StatusOK, existing)
		return
	}
	if in.Commit != "" && in.Commit != head {
		writeError(w, http.StatusConflict, "the default branch has moved since this page loaded; reload to see its latest commit")
		return
	}

	sess, created, err := s.store.CreateSession(ctx, store.Session{
		ID:        ulid.Make().String(),
		UserID:    user.ID,
		UserLogin: user.Login,
		Owner:     repo.Owner,
		Repo:      repo.Name,
		Branch:    repo.DefaultBranch,
		Commit:    head,
		CreatedAt: now,
		UsedAt:    now,
		ExpiresAt: now.Add(sessionIdleTimeout),
		EndsAt:    now.Add(sessionMaxAge),
	}, maxSessionsPerUser, now)
	if errors.Is(err, store.ErrTooManySessions) {
		writeError(w, http.StatusTooManyRequests, "you have too many open sessions; discard one before opening another")
		return
	}
	if err != nil {
		s.internalError(w, r, "failed to create session", err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		s.logger.InfoContext(ctx, "session opened",
			"event", "session.opened", "env", s.env, "session_id", sess.ID, "user", user.Login, "user_id", user.ID,
			"repository", repo.FullName, "commit", head)
	}
	s.writeSession(w, r, status, sess)
}

// currentSession returns the user's open session for the repository in the
// path, which must be the session the path names. It writes the error
// response and returns false otherwise.
func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	ctx := r.Context()
	user := userauth.UserFrom(ctx)
	owner, name, id := r.PathValue("owner"), r.PathValue("repo"), r.PathValue("id")
	if !githubapp.ValidName(owner) || !githubapp.ValidName(name) {
		writeError(w, http.StatusNotFound, "session not found")
		return store.Session{}, false
	}
	sess, ok, err := s.store.Session(ctx, user.ID, store.RepoKey(owner, name), s.now().UTC())
	if err != nil {
		s.internalError(w, r, "failed to read session", err)
		return store.Session{}, false
	}
	if !ok || sess.ID != id {
		writeError(w, http.StatusNotFound, "session not found; it may have expired or been discarded")
		return store.Session{}, false
	}
	return sess, true
}

// touch marks a session used, keeping it open for another idle timeout
// within its maximum age.
func (s *Server) touch(ctx context.Context, sess store.Session, now time.Time) (bool, error) {
	expires := now.Add(sessionIdleTimeout)
	if expires.After(sess.EndsAt) {
		expires = sess.EndsAt
	}
	return s.store.TouchSession(ctx, sess.UserID, store.RepoKey(sess.Owner, sess.Repo), sess.ID, expires, now)
}

// deleteSession discards a session and its pending changes.
func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	discarded, err := s.store.DiscardSession(ctx, sess.UserID, store.RepoKey(sess.Owner, sess.Repo), sess.ID, s.now().UTC())
	switch {
	case errors.Is(err, store.ErrSessionBusy):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internalError(w, r, "failed to delete session", err)
		return
	case !discarded:
		writeError(w, http.StatusNotFound, "session not found; it may have expired or been discarded")
		return
	}
	s.logger.InfoContext(ctx, "session discarded",
		"event", "session.discarded", "env", s.env, "session_id", sess.ID, "user", sess.UserLogin, "user_id", sess.UserID,
		"repository", sess.Owner+"/"+sess.Repo)
	w.WriteHeader(http.StatusNoContent)
}

// deleteChange removes one pending change from a session.
func (s *Server) deleteChange(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id := r.PathValue("change")
	if !validChangeID(id) {
		writeError(w, http.StatusNotFound, "change not found")
		return
	}
	// removed only while no pull request is being opened, so one that
	// locks the session afterwards never reads it
	found, err := s.store.RemoveChange(ctx, sess.UserID, store.RepoKey(sess.Owner, sess.Repo), sess.ID, id, s.now().UTC())
	switch {
	case errors.Is(err, store.ErrSessionBusy):
		writeError(w, http.StatusConflict, "a pull request is being opened from this session; remove the change once it is open or has failed")
		return
	case err != nil:
		s.internalError(w, r, "failed to delete change", err)
		return
	case !found:
		writeError(w, http.StatusNotFound, "change not found")
		return
	}
	if _, err := s.touch(ctx, sess, s.now().UTC()); err != nil && !errors.Is(err, store.ErrSessionBusy) {
		s.logger.WarnContext(ctx, "failed to mark session used", "session_id", sess.ID, "error", err)
	}
	s.logger.InfoContext(ctx, "pending change removed",
		"event", "change.removed", "env", s.env, "session_id", sess.ID, "user", sess.UserLogin, "change_id", id)
	w.WriteHeader(http.StatusNoContent)
}

// internalError logs err and answers 500 without detail.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	s.logger.ErrorContext(r.Context(), msg, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}
