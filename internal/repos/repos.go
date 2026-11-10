// Package repos gives signed-in users access to repositories through the
// GitHub App, limited to what each user may do on GitHub themselves.
//
// The App's installation token can read every repository it is installed
// on, so every call here first asks GitHub for the user's own permission on
// the repository: read to list and discover, write to seal and open pull
// requests. A user who cannot read a repository is told it does not exist,
// so private repository names are not disclosed.
package repos

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// Errors for users. ErrNotFound covers repositories a user cannot read.
var (
	ErrNotFound       = errors.New("repository not found")
	ErrForbidden      = errors.New("you do not have write access to this repository")
	ErrArchived       = errors.New("this repository is archived")
	ErrCommitNotFound = errors.New("commit not found")
	ErrFileNotFound   = errors.New("no SealedSecret file at that path")
)

// Defaults and limits.
const (
	// DefaultPermissionTTL is how long a permission lookup is reused: short
	// enough that revoked access stops working quickly.
	DefaultPermissionTTL = 2 * time.Minute
	// maxCandidates bounds the files read for one discovery.
	maxCandidates = 500
	// concurrency bounds parallel GitHub calls for one request.
	concurrency = 8
	// cache sizes; a full cache is emptied rather than evicted piecemeal
	maxPermissionEntries = 10_000
	maxParsedBlobs       = 5_000
	maxSnapshots         = 1_000
)

// DefaultFileGlobs select the files discovery reads: YAML files with
// "sealed" in their name.
var DefaultFileGlobs = []string{"*sealed*.yaml", "*sealed*.yml"}

// GitHub is what the service needs from the GitHub App.
type GitHub interface {
	Repositories(ctx context.Context) ([]githubapp.Repository, error)
	Repository(ctx context.Context, owner, repo string) (githubapp.Repository, error)
	Permission(ctx context.Context, owner, repo, login string) (githubapp.Permission, error)
	BranchHead(ctx context.Context, owner, repo, branch string) (string, error)
	Tree(ctx context.Context, owner, repo, commit string) (githubapp.Tree, error)
	Blob(ctx context.Context, owner, repo, sha string) ([]byte, error)
	CreatePullRequest(ctx context.Context, owner, repo string, pr githubapp.NewPullRequest) (githubapp.PullRequest, error)
}

// Options configures a Service.
type Options struct {
	GitHub      GitHub
	Env         string
	Annotations manifest.Annotations
	// FileGlobs match file names (or, with a slash, paths) to read during
	// discovery. Empty means DefaultFileGlobs.
	FileGlobs     []string
	PermissionTTL time.Duration
	Logger        *slog.Logger
	Now           func() time.Time
}

// Service is repository access for signed-in users.
type Service struct {
	gh            GitHub
	env           string
	ann           manifest.Annotations
	globs         []string
	permissionTTL time.Duration
	logger        *slog.Logger
	now           func() time.Time

	mu          sync.Mutex
	permissions map[string]permissionEntry
	parsed      map[string]parsedBlob
	snapshots   map[string]snapshot
}

// snapshot is a commit's discovery candidates: the files whose name matches
// the globs, sorted by path. Commits never change, so it is cached.
type snapshot struct {
	candidates []githubapp.TreeEntry
	truncated  bool
}

type permissionEntry struct {
	access  Access
	expires time.Time
}

type parsedBlob struct {
	docs []manifest.Document
	err  error
}

// New returns a Service. It makes no network calls.
func New(opts Options) (*Service, error) {
	globs := opts.FileGlobs
	if len(globs) == 0 {
		globs = DefaultFileGlobs
	}
	for _, g := range globs {
		if _, err := path.Match(g, ""); err != nil {
			return nil, fmt.Errorf("failed to use file glob %q: %w", g, err)
		}
	}
	ttl := opts.PermissionTTL
	if ttl <= 0 {
		ttl = DefaultPermissionTTL
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		gh:            opts.GitHub,
		env:           opts.Env,
		ann:           opts.Annotations,
		globs:         globs,
		permissionTTL: ttl,
		logger:        logger,
		now:           now,
		permissions:   map[string]permissionEntry{},
		parsed:        map[string]parsedBlob{},
		snapshots:     map[string]snapshot{},
	}, nil
}

// Access is what a user may do on a repository.
type Access struct {
	Read  bool
	Write bool
}

// Level names an access for clients: "write", "read" or "none".
func (a Access) Level() string {
	switch {
	case a.Write:
		return "write"
	case a.Read:
		return "read"
	}
	return "none"
}

// Repo is a repository as a user sees it.
type Repo struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	// Access is "write" or "read".
	Access string `json:"access"`
}

// List returns the repositories the App is installed on that the user can
// read. Archived repositories are left out: nothing can be sealed into them.
func (s *Service) List(ctx context.Context, user *userauth.User) ([]Repo, error) {
	all, err := s.gh.Repositories(ctx)
	if err != nil {
		return nil, err
	}
	var candidates []githubapp.Repository
	for _, r := range all {
		if !r.Archived {
			candidates = append(candidates, r)
		}
	}

	access := make([]Access, len(candidates))
	errs := make([]error, len(candidates))
	forEach(ctx, len(candidates), func(i int) {
		access[i], errs[i] = s.access(ctx, user, candidates[i].Owner, candidates[i].Name)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out := []Repo{}
	failed := 0
	for i, r := range candidates {
		if errs[i] != nil {
			failed++
			s.logger.WarnContext(ctx, "failed to check repository permission",
				"repository", r.FullName, "user", user.Login, "error", errs[i])
			continue
		}
		if access[i].Read {
			out = append(out, repo(r, access[i]))
		}
	}
	// nothing could be checked: say so instead of showing no repositories
	if failed > 0 && failed == len(candidates) {
		return nil, fmt.Errorf("failed to check repository permissions: %w", errs[0])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out, nil
}

func repo(r githubapp.Repository, a Access) Repo {
	return Repo{
		Owner:         r.Owner,
		Name:          r.Name,
		FullName:      r.FullName,
		Private:       r.Private,
		DefaultBranch: r.DefaultBranch,
		Access:        a.Level(),
	}
}

// Require checks that the user can read the repository and, with write,
// write to it. It returns ErrNotFound when the user cannot read it (or it
// does not exist) and ErrForbidden when they can read but not write.
func (s *Service) Require(ctx context.Context, user *userauth.User, owner, name string, write bool) (Access, error) {
	if !githubapp.ValidName(owner) || !githubapp.ValidName(name) {
		return Access{}, ErrNotFound
	}
	a, err := s.access(ctx, user, owner, name)
	if err != nil {
		return Access{}, err
	}
	switch {
	case !a.Read:
		return a, ErrNotFound
	case write && !a.Write:
		return a, ErrForbidden
	}
	return a, nil
}

// access returns the user's access, from the cache when it is fresh. The
// answer must be for the same GitHub user ID: logins can change hands.
func (s *Service) access(ctx context.Context, user *userauth.User, owner, name string) (Access, error) {
	if user == nil || user.ID == 0 || user.Login == "" {
		return Access{}, errors.New("failed to check repository permission: no signed-in user")
	}
	key := strconv.FormatInt(user.ID, 10) + "|" + strings.ToLower(owner+"/"+name)
	now := s.now()
	s.mu.Lock()
	if e, ok := s.permissions[key]; ok && now.Before(e.expires) {
		s.mu.Unlock()
		return e.access, nil
	}
	s.mu.Unlock()

	p, err := s.gh.Permission(ctx, owner, name, user.Login)
	if errors.Is(err, githubapp.ErrNotFound) {
		// the App cannot see the repository
		return Access{}, nil
	}
	if err != nil {
		return Access{}, err
	}
	a := Access{Read: p.Read, Write: p.Write}
	if p.UserID != user.ID && (p.Read || p.Write) {
		s.logger.WarnContext(ctx, "github answered a permission lookup for another user; denying",
			"event", "repo.permission_mismatch", "repository", owner+"/"+name, "user", user.Login,
			"user_id", user.ID, "answered_for", p.UserID)
		a = Access{}
	}
	s.mu.Lock()
	if len(s.permissions) >= maxPermissionEntries {
		s.permissions = map[string]permissionEntry{}
	}
	s.permissions[key] = permissionEntry{access: a, expires: now.Add(s.permissionTTL)}
	s.mu.Unlock()
	return a, nil
}

// File is a file with SealedSecret documents for the env.
type File struct {
	Path string `json:"path"`
	// Blob is the file's Git object ID at the listed commit.
	Blob      string              `json:"blob"`
	Documents []manifest.Document `json:"documents"`
	// Error says why the file could not be read; it has no documents then.
	Error string `json:"error,omitempty"`
}

// Listing is a repository's SealedSecret files for the env at a commit of
// its default branch.
type Listing struct {
	Repo   Repo   `json:"repository"`
	Branch string `json:"branch"`
	Commit string `json:"commit"`
	Files  []File `json:"files"`
	// Truncated is set when not every matching file could be read: the
	// tree was too large, or too many files matched.
	Truncated bool `json:"truncated"`
	// FileGlobs are the globs that select the files read.
	FileGlobs []string `json:"file_globs"`
}

// Files lists the files that hold SealedSecret documents for the env, at a
// commit or, when commit is empty, the head of the default branch. Files
// with no such documents are left out; files that match but cannot be
// parsed are listed with an error.
func (s *Service) Files(ctx context.Context, user *userauth.User, owner, name, commit string) (Listing, error) {
	r, a, err := s.repository(ctx, user, owner, name, false)
	if err != nil {
		return Listing{}, err
	}
	if commit == "" {
		if commit, err = s.gh.BranchHead(ctx, r.Owner, r.Name, r.DefaultBranch); err != nil {
			return Listing{}, err
		}
	}
	snap, err := s.snapshot(ctx, r, commit)
	if err != nil {
		return Listing{}, err
	}
	listing := Listing{
		Repo:      repo(r, a),
		Branch:    r.DefaultBranch,
		Commit:    commit,
		Files:     []File{},
		Truncated: snap.truncated,
		FileGlobs: s.globs,
	}

	files := make([]File, len(snap.candidates))
	forEach(ctx, len(snap.candidates), func(i int) {
		files[i] = s.file(ctx, r, snap.candidates[i])
	})
	if err := ctx.Err(); err != nil {
		return Listing{}, err
	}
	for _, f := range files {
		if len(f.Documents) > 0 || f.Error != "" {
			listing.Files = append(listing.Files, f)
		}
	}
	return listing, nil
}

// Head checks the user's access, read or write, and returns the repository
// with the head of its default branch. Writing to an archived repository is
// refused.
func (s *Service) Head(ctx context.Context, user *userauth.User, owner, name string, write bool) (Repo, string, error) {
	r, a, err := s.repository(ctx, user, owner, name, write)
	if err != nil {
		return Repo{}, "", err
	}
	head, err := s.gh.BranchHead(ctx, r.Owner, r.Name, r.DefaultBranch)
	if err != nil {
		return Repo{}, "", err
	}
	return repo(r, a), head, nil
}

// File checks the user's access, read or write, and returns a discovered
// file's documents for the env at a commit; its Error says why it could not
// be read. ErrFileNotFound means no file at that path matches the discovery
// globs.
func (s *Service) File(ctx context.Context, user *userauth.User, owner, name, commit, filePath string, write bool) (File, error) {
	r, _, err := s.repository(ctx, user, owner, name, write)
	if err != nil {
		return File{}, err
	}
	snap, err := s.snapshot(ctx, r, commit)
	if err != nil {
		return File{}, err
	}
	i := sort.Search(len(snap.candidates), func(i int) bool { return snap.candidates[i].Path >= filePath })
	if i == len(snap.candidates) || snap.candidates[i].Path != filePath {
		return File{}, ErrFileNotFound
	}
	return s.file(ctx, r, snap.candidates[i]), nil
}

// repository checks the user's access and returns the repository and that
// access. Nothing can be pushed to an archived repository, so it is never
// writable.
func (s *Service) repository(ctx context.Context, user *userauth.User, owner, name string, write bool) (githubapp.Repository, Access, error) {
	a, err := s.Require(ctx, user, owner, name, write)
	if err != nil {
		return githubapp.Repository{}, Access{}, err
	}
	r, err := s.gh.Repository(ctx, owner, name)
	if errors.Is(err, githubapp.ErrNotFound) {
		return githubapp.Repository{}, Access{}, ErrNotFound
	}
	if err != nil {
		return githubapp.Repository{}, Access{}, err
	}
	if r.Archived {
		if write {
			return githubapp.Repository{}, Access{}, ErrArchived
		}
		a.Write = false
	}
	return r, a, nil
}

// snapshot returns a commit's discovery candidates, from the cache when it
// has them.
func (s *Service) snapshot(ctx context.Context, r githubapp.Repository, commit string) (snapshot, error) {
	if !githubapp.ValidSHA(commit) {
		return snapshot{}, ErrCommitNotFound
	}
	key := strings.ToLower(r.FullName) + "@" + commit
	s.mu.Lock()
	if snap, ok := s.snapshots[key]; ok {
		s.mu.Unlock()
		return snap, nil
	}
	s.mu.Unlock()

	tree, err := s.gh.Tree(ctx, r.Owner, r.Name, commit)
	if errors.Is(err, githubapp.ErrNotFound) {
		return snapshot{}, ErrCommitNotFound
	}
	if err != nil {
		return snapshot{}, err
	}
	snap := snapshot{truncated: tree.Truncated}
	for _, e := range tree.Entries {
		if e.Type == "blob" && e.Size <= manifest.MaxFileBytes && s.matches(e.Path) {
			snap.candidates = append(snap.candidates, e)
		}
	}
	sort.Slice(snap.candidates, func(i, j int) bool { return snap.candidates[i].Path < snap.candidates[j].Path })
	if len(snap.candidates) > maxCandidates {
		snap.candidates = snap.candidates[:maxCandidates]
		snap.truncated = true
	}
	s.mu.Lock()
	if len(s.snapshots) >= maxSnapshots {
		s.snapshots = map[string]snapshot{}
	}
	s.snapshots[key] = snap
	s.mu.Unlock()
	return snap, nil
}

// file reads and parses one candidate.
func (s *Service) file(ctx context.Context, r githubapp.Repository, e githubapp.TreeEntry) File {
	docs, err := s.parse(ctx, r.Owner, r.Name, e.SHA)
	f := File{Path: e.Path, Blob: e.SHA, Documents: docs}
	if err != nil {
		f.Error = userError(err)
		s.logger.DebugContext(ctx, "skipping unreadable file", "repository", r.FullName, "path", e.Path, "error", err)
	}
	return f
}

// matches reports whether a path is a discovery candidate.
func (s *Service) matches(p string) bool {
	base := path.Base(p)
	for _, g := range s.globs {
		target := base
		if strings.Contains(g, "/") {
			target = p
		}
		if ok, _ := path.Match(g, target); ok {
			return true
		}
	}
	return false
}

// parse returns a blob's documents for the env. Blobs are immutable, so the
// result is cached by object ID.
func (s *Service) parse(ctx context.Context, owner, name, blob string) ([]manifest.Document, error) {
	s.mu.Lock()
	if p, ok := s.parsed[blob]; ok {
		s.mu.Unlock()
		return p.docs, p.err
	}
	s.mu.Unlock()

	content, err := s.gh.Blob(ctx, owner, name, blob)
	if err != nil {
		// not cached: a fetch can succeed next time
		return nil, err
	}
	docs, err := manifest.Find(content, s.ann, s.env)
	s.mu.Lock()
	if len(s.parsed) >= maxParsedBlobs {
		s.parsed = map[string]parsedBlob{}
	}
	s.parsed[blob] = parsedBlob{docs: docs, err: err}
	s.mu.Unlock()
	return docs, err
}

// userError is the message shown for a file that could not be read.
func userError(err error) string {
	for _, known := range []error{manifest.ErrInvalidYAML, manifest.ErrDuplicateKey, manifest.ErrTooLarge, manifest.ErrTooMany} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "file could not be read from GitHub"
}

// forEach runs fn for 0..n-1 with bounded concurrency, stopping early when
// ctx ends.
func forEach(ctx context.Context, n int, fn func(int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i := range n {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}()
	}
	wg.Wait()
}
