package repos

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Target names a document a value was sealed for.
type Target struct {
	Namespace string
	Name      string
	Scope     string
}

// Value is a sealed value to write into a file: one ciphertext for each of
// the file's documents for the env, in file order.
type Value struct {
	Path string
	Key  string
	// Targets are the documents the value was sealed for. They must still
	// be exactly the file's documents for the env.
	Targets     []Target
	Ciphertexts []string
}

// NewPullRequest is a pull request of sealed values.
type NewPullRequest struct {
	// Commit is the commit of the default branch the values were sealed
	// at; the branch starts there.
	Commit  string
	Branch  string
	Title   string
	Body    string
	Message string
	Values  []Value
}

// FileError says why a file could not be written. Its message is shown to
// users and never echoes file content.
type FileError struct {
	Path   string
	Reason string
}

func (e *FileError) Error() string { return e.Path + ": " + e.Reason }

// OpenPullRequest writes sealed values into their files as they are at the
// commit, on a new branch, and opens a pull request into the default branch.
// The user's write access is checked first. Only spec.encryptedData of each
// file's documents for the env changes (manifest.SetEncryptedData); a file
// whose documents no longer match what a value was sealed for is refused
// with a FileError.
func (s *Service) OpenPullRequest(ctx context.Context, user *userauth.User, owner, name string, pr NewPullRequest) (githubapp.PullRequest, error) {
	r, _, err := s.repository(ctx, user, owner, name, true)
	if err != nil {
		return githubapp.PullRequest{}, err
	}
	snap, err := s.snapshot(ctx, r, pr.Commit)
	if err != nil {
		return githubapp.PullRequest{}, err
	}

	byPath := map[string][]Value{}
	for _, v := range pr.Values {
		byPath[v.Path] = append(byPath[v.Path], v)
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) == 0 || len(paths) > githubapp.MaxPullRequestFiles {
		return githubapp.PullRequest{}, fmt.Errorf("failed to open a pull request: %d files", len(paths))
	}

	files := make([]githubapp.FileChange, len(paths))
	errs := make([]error, len(paths))
	forEach(ctx, len(paths), func(i int) {
		files[i], errs[i] = s.render(ctx, r, snap, paths[i], byPath[paths[i]])
	})
	if err := ctx.Err(); err != nil {
		return githubapp.PullRequest{}, err
	}
	// a failure to reach GitHub comes first; files that cannot be written
	// are reported together
	var fileErrs []error
	for _, err := range errs {
		var fe *FileError
		switch {
		case errors.As(err, &fe):
			fileErrs = append(fileErrs, err)
		case err != nil:
			return githubapp.PullRequest{}, err
		}
	}
	if len(fileErrs) > 0 {
		return githubapp.PullRequest{}, errors.Join(fileErrs...)
	}
	return s.gh.CreatePullRequest(ctx, r.Owner, r.Name, githubapp.NewPullRequest{
		Base:    r.DefaultBranch,
		Parent:  pr.Commit,
		Branch:  pr.Branch,
		Message: pr.Message,
		Files:   files,
		Title:   pr.Title,
		Body:    pr.Body,
	})
}

// render returns a file's content at the snapshot's commit with values
// written in.
func (s *Service) render(ctx context.Context, r githubapp.Repository, snap snapshot, filePath string, values []Value) (githubapp.FileChange, error) {
	i := sort.Search(len(snap.candidates), func(i int) bool { return snap.candidates[i].Path >= filePath })
	if i == len(snap.candidates) || snap.candidates[i].Path != filePath {
		return githubapp.FileChange{}, &FileError{Path: filePath, Reason: "the file is no longer discovered"}
	}
	entry := snap.candidates[i]
	content, err := s.gh.Blob(ctx, r.Owner, r.Name, entry.SHA)
	if err != nil {
		return githubapp.FileChange{}, err
	}
	docs, err := manifest.Find(content, s.ann, s.env)
	if err != nil {
		return githubapp.FileChange{}, &FileError{Path: filePath, Reason: userError(err)}
	}
	var edits []manifest.Edit
	for _, v := range values {
		if !sameTargets(docs, v.Targets) || len(v.Ciphertexts) != len(docs) {
			return githubapp.FileChange{}, &FileError{Path: filePath,
				Reason: "its documents for the " + s.env + " env no longer match what " + v.Key + " was sealed for; seal it again"}
		}
		for j, d := range docs {
			edits = append(edits, manifest.Edit{Document: d.Index, Key: v.Key, Value: v.Ciphertexts[j]})
		}
	}
	out, err := manifest.SetEncryptedData(content, edits)
	if errors.Is(err, manifest.ErrLayout) {
		s.logger.WarnContext(ctx, "cannot edit file in place", "repository", r.FullName, "path", filePath, "error", err)
		return githubapp.FileChange{}, &FileError{Path: filePath, Reason: err.Error()}
	}
	if err != nil {
		return githubapp.FileChange{}, fmt.Errorf("failed to edit %s: %w", filePath, err)
	}
	if len(out) > manifest.MaxFileBytes {
		return githubapp.FileChange{}, &FileError{Path: filePath, Reason: "the file would be larger than 1 MiB"}
	}
	return githubapp.FileChange{Path: filePath, Mode: entry.Mode, Content: out}, nil
}

// sameTargets reports whether a file's documents for the env are exactly
// the targets, in order, and can all be sealed into.
func sameTargets(docs []manifest.Document, targets []Target) bool {
	if len(docs) == 0 || len(docs) != len(targets) {
		return false
	}
	for i, d := range docs {
		t := targets[i]
		if !d.Sealable() || d.Namespace != t.Namespace || d.Name != t.Name || d.Scope != t.Scope {
			return false
		}
	}
	return true
}
