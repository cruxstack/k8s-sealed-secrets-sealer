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
	"sync/atomic"
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
	// listPermissionTTL is how long the repository list reuses one. A list
	// checks every repository the App is installed on, and only shows what
	// the user could read lately; opening a repository checks again.
	listPermissionTTL = 10 * time.Minute
	// maxCandidates bounds the files read for one discovery.
	maxCandidates = 500
	// concurrency bounds parallel GitHub calls for one request.
	concurrency = 8
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
	// Cache holds GitHub's answers. The envs one process serves share one;
	// nil means the Service gets its own.
	Cache  *Cache
	Logger *slog.Logger
	Now    func() time.Time
}

// Service is repository access for signed-in users.
type Service struct {
	gh            GitHub
	env           string
	ann           manifest.Annotations
	globs         []string
	permissionTTL time.Duration
	cache         *Cache
	logger        *slog.Logger
	now           func() time.Time
}

// snapshot is a commit's discovery candidates: the files whose name matches
// the globs, sorted by path. Commits never change, so it is cached.
type snapshot struct {
	candidates []githubapp.TreeEntry
	truncated  bool
}

// permission is a user's access to a repository and when GitHub said so.
type permission struct {
	access  Access
	checked time.Time
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
	cache := opts.Cache
	if cache == nil {
		cache = NewCache()
	}
	return &Service{
		gh:            opts.GitHub,
		env:           opts.Env,
		ann:           opts.Annotations,
		globs:         globs,
		permissionTTL: ttl,
		cache:         cache,
		logger:        logger,
		now:           now,
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

// RepoList is the repositories a user is shown.
type RepoList struct {
	Repositories []Repo `json:"repositories"`
	// Incomplete is set when some repositories are left out because their
	// permission could not be checked in time, or GitHub failed.
	Incomplete bool `json:"incomplete,omitempty"`
	// Lookups counts the permission lookups the list made on GitHub, for
	// rate limits: those the cache answered cost nothing.
	Lookups int `json:"-"`
}

// List returns the repositories the App is installed on that the user can
// read. Archived repositories are left out: nothing can be sealed into them.
//
// The installation's list is reused for installedTTL by every user and env,
// and each permission for listPermissionTTL, so a list costs GitHub calls
// only for what was not checked lately. Checks start only while a quarter
// of the time ctx allows is left, so the list goes out in time; a
// repository not checked by then, or whose check failed, is left out and
// the list marked incomplete, and a later list checks it. Lookups is set
// even when the list fails.
func (s *Service) List(ctx context.Context, user *userauth.User) (RepoList, error) {
	if user == nil || user.ID == 0 || user.Login == "" {
		return RepoList{}, errors.New("failed to list repositories: no signed-in user")
	}
	all, err := s.installed(ctx)
	if err != nil && len(all) == 0 {
		return RepoList{}, err
	}
	out := RepoList{Repositories: []Repo{}, Incomplete: err != nil}
	if err != nil {
		s.logger.WarnContext(ctx, "listing only some repositories", "listed", len(all), "error", err)
	}
	var candidates []githubapp.Repository
	for _, r := range all {
		if !r.Archived {
			candidates = append(candidates, r)
		}
	}

	// checks running when the time is up finish with ctx
	starting := ctx
	if deadline, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		starting, cancel = context.WithDeadline(ctx, deadline.Add(-time.Until(deadline)/4))
		defer cancel()
	}
	access := make([]Access, len(candidates))
	errs := make([]error, len(candidates))
	checked := make([]bool, len(candidates))
	var lookups atomic.Int32
	forEach(starting, len(candidates), func(i int) {
		access[i], errs[i] = s.access(ctx, user, candidates[i].Owner, candidates[i].Name, s.listPermissionTTL(), &lookups)
		checked[i] = true
	})
	out.Lookups = int(lookups.Load())

	var failure error
	unchecked := 0
	for i, r := range candidates {
		switch {
		case !checked[i], errs[i] != nil && ctx.Err() != nil:
			// time ran out before this one was known
			unchecked++
		case errs[i] != nil:
			if failure == nil {
				failure = errs[i]
			}
			s.logger.WarnContext(ctx, "failed to check repository permission",
				"repository", r.FullName, "user", user.Login, "error", errs[i])
		case access[i].Read:
			out.Repositories = append(out.Repositories, repo(r, access[i]))
		}
	}
	if failure != nil || unchecked > 0 {
		out.Incomplete = true
		s.logger.WarnContext(ctx, "listing only the repositories checked in time",
			"user", user.Login, "listed", len(out.Repositories), "unchecked", unchecked, "error", failure)
	}
	// nothing to show, and GitHub failing is why: say so instead
	if len(out.Repositories) == 0 && failure != nil {
		return RepoList{Lookups: out.Lookups}, fmt.Errorf("failed to check repository permissions: %w", failure)
	}
	sort.Slice(out.Repositories, func(i, j int) bool { return out.Repositories[i].FullName < out.Repositories[j].FullName })
	return out, nil
}

// listPermissionTTL is how long the list reuses a permission: never less
// than other checks do.
func (s *Service) listPermissionTTL() time.Duration {
	return max(listPermissionTTL, s.permissionTTL)
}

// installed returns the repositories the App is installed on. A list GitHub
// cut short is returned with the error, and not kept.
func (s *Service) installed(ctx context.Context) ([]githubapp.Repository, error) {
	if all, ok := s.cache.installed.get("", s.now()); ok {
		return all, nil
	}
	type listing struct {
		repos []githubapp.Repository
		err   error
	}
	l, err := once(ctx, s.cache, "installed", func(ctx context.Context) (listing, error) {
		all, err := s.gh.Repositories(ctx)
		if err == nil {
			s.cache.installed.put("", all, s.now().Add(installedTTL))
		}
		return listing{all, err}, nil
	})
	if err != nil {
		// the caller's time ran out before the list came
		return nil, err
	}
	return l.repos, l.err
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
	a, err := s.access(ctx, user, owner, name, s.permissionTTL, nil)
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

// access returns the user's access, from the cache when GitHub said it
// within maxAge. The answer must be for the same GitHub user ID: logins can
// change hands. A lookup on GitHub is counted in lookups, when given,
// unless another caller's was shared.
func (s *Service) access(ctx context.Context, user *userauth.User, owner, name string, maxAge time.Duration, lookups *atomic.Int32) (Access, error) {
	if user == nil || user.ID == 0 || user.Login == "" {
		return Access{}, errors.New("failed to check repository permission: no signed-in user")
	}
	key := permissionKey(user, owner, name)
	now := s.now()
	if p, ok := s.cache.permissions.get(key, now); ok && now.Sub(p.checked) < maxAge {
		return p.access, nil
	}
	return once(ctx, s.cache, "permission|"+key, func(ctx context.Context) (Access, error) {
		if lookups != nil {
			lookups.Add(1)
		}
		p, err := s.gh.Permission(ctx, owner, name, user.Login)
		if errors.Is(err, githubapp.ErrNotFound) {
			// the App cannot see the repository
			err, p = nil, githubapp.Permission{}
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
		checked := s.now()
		s.cache.permissions.put(key, permission{access: a, checked: checked}, checked.Add(s.listPermissionTTL()))
		return a, nil
	})
}

// permissionKey names a user's permission on a repository, by GitHub user
// ID: logins can change hands.
func permissionKey(user *userauth.User, owner, name string) string {
	return strconv.FormatInt(user.ID, 10) + "|" + strings.ToLower(owner+"/"+name)
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
	errs := make([]error, len(snap.candidates))
	forEach(ctx, len(snap.candidates), func(i int) {
		files[i], errs[i] = s.file(ctx, r, snap.candidates[i])
	})
	if err := ctx.Err(); err != nil {
		return Listing{}, err
	}
	for i, f := range files {
		// a file GitHub failed to send is listed as unreadable, unless the
		// rate limit is why: then every file would be
		if err := errs[i]; err != nil {
			var limited *githubapp.RateLimitError
			if errors.As(err, &limited) {
				return Listing{}, err
			}
			s.logger.WarnContext(ctx, "failed to read file", "repository", r.FullName, "path", f.Path, "error", err)
			f.Error = "file could not be read from GitHub"
		}
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
// file's documents for the env at a commit; its Error says why they cannot
// be parsed. ErrFileNotFound means no file at that path matches the
// discovery globs. Failing to read the file from GitHub is an error.
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
	return s.file(ctx, r, snap.candidates[i])
}

// FileValues checks the user's write access and returns a discovered
// file's documents for the env at a commit, with the values in each
// document's spec.encryptedData, in the same order: what resealing it
// sends. Its content is read from GitHub again, not from the cache, which
// holds no values.
func (s *Service) FileValues(ctx context.Context, user *userauth.User, owner, name, commit, filePath string) (File, []map[string]string, error) {
	r, _, err := s.repository(ctx, user, owner, name, true)
	if err != nil {
		return File{}, nil, err
	}
	snap, err := s.snapshot(ctx, r, commit)
	if err != nil {
		return File{}, nil, err
	}
	i := sort.Search(len(snap.candidates), func(i int) bool { return snap.candidates[i].Path >= filePath })
	if i == len(snap.candidates) || snap.candidates[i].Path != filePath {
		return File{}, nil, ErrFileNotFound
	}
	e := snap.candidates[i]
	content, err := s.gh.Blob(ctx, r.Owner, r.Name, e.SHA)
	if err != nil {
		return File{}, nil, err
	}
	f := File{Path: e.Path, Blob: e.SHA}
	docs, values, err := manifest.EncryptedData(content, s.ann, s.env)
	if reason, ok := contentError(err); ok {
		f.Error = reason
		return f, nil, nil
	}
	if err != nil {
		return File{}, nil, err
	}
	f.Documents = docs
	return f, values, nil
}

// repository checks the user's access and returns the repository and that
// access. Nothing can be pushed to an archived repository, so it is never
// writable.
func (s *Service) repository(ctx context.Context, user *userauth.User, owner, name string, write bool) (githubapp.Repository, Access, error) {
	a, err := s.Require(ctx, user, owner, name, write)
	if err != nil {
		return githubapp.Repository{}, Access{}, err
	}
	r, err := s.details(ctx, owner, name)
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

// details returns a repository's details, reused for repositoryTTL: every
// seal and pull request needs them, and they rarely change.
func (s *Service) details(ctx context.Context, owner, name string) (githubapp.Repository, error) {
	key := strings.ToLower(owner + "/" + name)
	if r, ok := s.cache.repos.get(key, s.now()); ok {
		return r, nil
	}
	return once(ctx, s.cache, "repository|"+key, func(ctx context.Context) (githubapp.Repository, error) {
		r, err := s.gh.Repository(ctx, owner, name)
		if err == nil {
			s.cache.repos.put(key, r, s.now().Add(repositoryTTL))
		}
		return r, err
	})
}

// snapshot returns a commit's discovery candidates, from the cache when it
// has them.
func (s *Service) snapshot(ctx context.Context, r githubapp.Repository, commit string) (snapshot, error) {
	if !githubapp.ValidSHA(commit) {
		return snapshot{}, ErrCommitNotFound
	}
	// the candidates depend on the globs, which each env sets
	key := strings.Join(s.globs, "\x00") + "\x00" + strings.ToLower(r.FullName) + "@" + commit
	if snap, ok := s.cache.snapshots.get(key, s.now()); ok {
		return snap, nil
	}
	return once(ctx, s.cache, "snapshot|"+key, func(ctx context.Context) (snapshot, error) {
		// a call that ended just before this one started may have cached it
		if snap, ok := s.cache.snapshots.get(key, s.now()); ok {
			return snap, nil
		}
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
		// commits never change
		s.cache.snapshots.put(key, snap, time.Time{})
		return snap, nil
	})
}

// file reads and parses one candidate. A file whose content cannot be
// parsed comes back with its Error set; failing to read it from GitHub is
// an error.
func (s *Service) file(ctx context.Context, r githubapp.Repository, e githubapp.TreeEntry) (File, error) {
	docs, err := s.parse(ctx, r.Owner, r.Name, e.SHA)
	f := File{Path: e.Path, Blob: e.SHA, Documents: docs}
	if reason, ok := contentError(err); ok {
		f.Error = reason
		s.logger.DebugContext(ctx, "skipping unparsable file", "repository", r.FullName, "path", e.Path, "error", err)
		return f, nil
	}
	return f, err
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
// result is cached by object ID, with the env and annotations it was parsed
// for. Errors from manifest.Find are the content's; others are GitHub's.
func (s *Service) parse(ctx context.Context, owner, name, blob string) ([]manifest.Document, error) {
	key := s.env + "\x00" + s.ann.Env + "\x00" + s.ann.Region + "\x00" + blob
	if p, ok := s.cache.parsed.get(key, s.now()); ok {
		return p.docs, p.err
	}
	p, err := once(ctx, s.cache, "blob|"+key, func(ctx context.Context) (parsedBlob, error) {
		// a call that ended just before this one started may have cached it
		if p, ok := s.cache.parsed.get(key, s.now()); ok {
			return p, nil
		}
		content, err := s.gh.Blob(ctx, owner, name, blob)
		if err != nil {
			// not cached: a fetch can succeed next time
			return parsedBlob{}, err
		}
		docs, err := manifest.Find(content, s.ann, s.env)
		p := parsedBlob{docs: docs, err: err}
		s.cache.parsed.put(key, p, time.Time{})
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	return p.docs, p.err
}

// contentError returns the message shown for a file whose content cannot be
// parsed, and false for any other error.
func contentError(err error) (string, bool) {
	for _, known := range []error{manifest.ErrInvalidYAML, manifest.ErrDuplicateKey, manifest.ErrTooLarge, manifest.ErrTooMany} {
		if errors.Is(err, known) {
			return known.Error(), true
		}
	}
	return "", false
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
