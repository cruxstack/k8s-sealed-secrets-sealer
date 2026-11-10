package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Time limits on repository requests, which wait on GitHub.
const (
	listReposTimeout = 20 * time.Second
	listFilesTimeout = 25 * time.Second
)

// listRepos serves the repositories the signed-in user can read.
func (s *Server) listRepos(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), listReposTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	list, err := s.repos.List(ctx, user)
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, map[string]any{"repositories": list})
}

// listFiles serves a repository's SealedSecret files for this env.
func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), listFilesTimeout)
	defer cancel()
	user := userauth.UserFrom(ctx)
	// ?commit= lists an earlier commit, such as a session's base
	listing, err := s.repos.Files(ctx, user, r.PathValue("owner"), r.PathValue("repo"), r.URL.Query().Get("commit"))
	if err != nil {
		s.repoError(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, listing)
}

// repoError answers a failed repository request: the user's own access
// problems as themselves, GitHub failures as a bad gateway without detail.
func (s *Server) repoError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
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
