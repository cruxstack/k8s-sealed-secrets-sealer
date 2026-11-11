package repos

import (
	"context"
	"errors"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
)

// Scheduled work, such as a reseal run, acts for no signed-in user: these
// read and write through the GitHub App alone, with the same caches as
// users' requests. What they find is shown only to people who can read the
// repository.

// AppRepository returns a repository's details. ErrNotFound means the App
// cannot reach it.
func (s *Service) AppRepository(ctx context.Context, owner, name string) (githubapp.Repository, error) {
	if !githubapp.ValidName(owner) || !githubapp.ValidName(name) {
		return githubapp.Repository{}, ErrNotFound
	}
	r, err := s.details(ctx, owner, name)
	if errors.Is(err, githubapp.ErrNotFound) {
		return githubapp.Repository{}, ErrNotFound
	}
	return r, err
}

// AppInstalled returns the repositories the App is installed on. A list
// GitHub cut short is returned with the error.
func (s *Service) AppInstalled(ctx context.Context) ([]githubapp.Repository, error) {
	return s.installed(ctx)
}

// AppHead returns the head of a repository's default branch.
func (s *Service) AppHead(ctx context.Context, r githubapp.Repository) (string, error) {
	return s.gh.BranchHead(ctx, r.Owner, r.Name, r.DefaultBranch)
}

// AppCandidates returns the files the discovery globs match at a commit,
// by path, and whether GitHub listed only part of its tree or more matched
// than are read.
func (s *Service) AppCandidates(ctx context.Context, r githubapp.Repository, commit string) ([]githubapp.TreeEntry, bool, error) {
	snap, err := s.snapshot(ctx, r, commit)
	return snap.candidates, snap.truncated, err
}

// AppFileValues reads a candidate and returns its documents for the env with
// their values; its Error says why its content cannot be parsed.
func (s *Service) AppFileValues(ctx context.Context, r githubapp.Repository, e githubapp.TreeEntry) (File, []map[string]string, error) {
	return s.fileValues(ctx, r, e)
}

// AppOpenPullRequest writes values into their files at pr.Commit, on a new
// branch, and opens a pull request into the default branch, as
// OpenPullRequest does for a user.
func (s *Service) AppOpenPullRequest(ctx context.Context, r githubapp.Repository, pr NewPullRequest) (githubapp.PullRequest, error) {
	return s.openPullRequest(ctx, r, pr)
}

// PullRequestState reads a pull request's state.
func (s *Service) PullRequestState(ctx context.Context, owner, name string, number int) (githubapp.PullState, error) {
	return s.gh.PullRequestState(ctx, owner, name, number)
}
