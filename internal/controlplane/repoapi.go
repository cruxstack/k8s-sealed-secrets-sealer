package controlplane

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Time limits on repository requests, which wait on GitHub.
const (
	listReposTimeout = 20 * time.Second
	listFilesTimeout = 25 * time.Second
)

// listRepos serves the repositories the signed-in user can read
// (repos.Service.List). When time runs short, or GitHub fails part way,
// those known to be readable are served, marked incomplete. The permission
// lookups a list makes on GitHub count against limitRepoChecks; once the
// user's are spent, lists wait for the window to end.
func (s *Server) listRepos(w http.ResponseWriter, r *http.Request) {
	key, _ := limitKey(r, limitRepoChecks)
	if !s.admit(w, r, limitRepoChecks, key, 0) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), listReposTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	list, err := s.repos.List(ctx, user)
	s.charge(ctx, limitRepoChecks, key, list.Lookups)
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, list)
}

// listFiles serves a repository's SealedSecret files for this env, at the
// head of its default branch or, with ?commit=, at the base commit of the
// user's session for it. No other commit is listed: each costs a tree and
// up to hundreds of files read from GitHub.
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), listFilesTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	owner, name, commit := r.PathValue("owner"), r.PathValue("repo"), r.URL.Query().Get("commit")
	if commit != "" {
		sess, ok, err := s.store.Session(ctx, user.ID, store.RepoKey(owner, name), s.now().UTC())
		if err != nil {
			s.internalError(w, r, "failed to read session", err)
			return
		}
		if !ok || sess.Commit != commit {
			// then only the head, which a page may name too
			listing, err := s.repos.Files(ctx, user, owner, name, "")
			if err == nil && listing.Commit != commit {
				err = repos.ErrCommitNotFound
			}
			if err != nil {
				s.repoError(w, r, err)
				return
			}
			httpserver.WriteJSON(w, http.StatusOK, listing)
			return
		}
	}
	listing, err := s.repos.Files(ctx, user, owner, name, commit)
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, listing)
}

// repoError answers a failed repository request: the user's own access
// problems as themselves, GitHub's rate limit as unavailable for a while,
// and other GitHub failures as a bad gateway without detail.
func (s *Server) repoError(w http.ResponseWriter, r *http.Request, err error) {
	var limited *githubapp.RateLimitError
	switch {
	case errors.As(err, &limited):
		wait := limited.RetryAfter(s.now())
		s.logger.WarnContext(r.Context(), "github rate limit reached", "event", "github.rate_limited",
			"path", r.URL.Path, "retry_at", limited.RetryAt.UTC(), "secondary", limited.Secondary)
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeError(w, http.StatusServiceUnavailable,
			"GitHub is limiting the sealer's requests for now; try again in "+aboutDuration(wait))
	case errors.Is(err, repos.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, repos.ErrCommitNotFound), errors.Is(err, repos.ErrFileNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, repos.ErrForbidden), errors.Is(err, repos.ErrArchived):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "GitHub did not answer in time")
	default:
		s.logger.ErrorContext(r.Context(), "github request failed", "event", "github.request_failed", "path", r.URL.Path, "error", err)
		writeError(w, http.StatusBadGateway, "GitHub request failed")
	}
}

// aboutDuration says roughly how long d is, for people: "40 seconds",
// "1 minute", "12 minutes".
func aboutDuration(d time.Duration) string {
	if d < time.Minute {
		return plural(int(math.Ceil(d.Seconds())), "second")
	}
	return plural(int(math.Ceil(d.Minutes())), "minute")
}
