package repos

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

var (
	alice = &userauth.User{ID: 1001, Login: "alice"}
	bob   = &userauth.User{ID: 1002, Login: "bob"}
	carol = &userauth.User{ID: 1003, Login: "carol"}
)

// counting wraps the GitHub App client and counts calls.
type counting struct {
	GitHub
	permissions  atomic.Int32
	blobs        atomic.Int32
	trees        atomic.Int32
	repositories atomic.Int32
	repository   atomic.Int32
	// answerFor, when set, makes permission answers claim another user
	answerFor int64
	// blobErr, when set, fails every blob read
	blobErr error
	// stall names a repository whose permission lookup waits until its
	// context ends; permErr fails the others' when set
	stall   string
	permErr error
	mock    *mockgithub.Server
}

func (c *counting) Repositories(ctx context.Context) ([]githubapp.Repository, error) {
	c.repositories.Add(1)
	return c.GitHub.Repositories(ctx)
}

func (c *counting) Repository(ctx context.Context, owner, repo string) (githubapp.Repository, error) {
	c.repository.Add(1)
	return c.GitHub.Repository(ctx, owner, repo)
}

func (c *counting) Permission(ctx context.Context, owner, repo, login string) (githubapp.Permission, error) {
	c.permissions.Add(1)
	if owner+"/"+repo == c.stall {
		<-ctx.Done()
		return githubapp.Permission{}, ctx.Err()
	}
	if c.permErr != nil {
		return githubapp.Permission{}, c.permErr
	}
	p, err := c.GitHub.Permission(ctx, owner, repo, login)
	if c.answerFor != 0 {
		p.UserID = c.answerFor
	}
	return p, err
}

func (c *counting) Blob(ctx context.Context, owner, repo, sha string) ([]byte, error) {
	c.blobs.Add(1)
	if c.blobErr != nil {
		return nil, c.blobErr
	}
	return c.GitHub.Blob(ctx, owner, repo, sha)
}

func (c *counting) Tree(ctx context.Context, owner, repo, commit string) (githubapp.Tree, error) {
	c.trees.Add(1)
	return c.GitHub.Tree(ctx, owner, repo, commit)
}

func newService(t *testing.T, repos []mockgithub.Repo) (*Service, *counting, *time.Time) {
	t.Helper()
	if repos == nil {
		var err error
		if repos, err = mockgithub.Fixtures(); err != nil {
			t.Fatal(err)
		}
	}
	key := testcerts.RSA(t, 2048)
	mock := mockgithub.New(mockgithub.Options{
		Org:   "example-org",
		Users: mockgithub.DefaultUsers(),
		App:   mockgithub.App{ID: "1", PublicKey: &key.PublicKey, InstallationID: 1},
		Repos: repos,
	})
	srv := httptest.NewServer(mock.Handler())
	t.Cleanup(srv.Close)
	gh, err := githubapp.New(githubapp.Options{
		APIURL:     srv.URL,
		AppID:      "1",
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		Org:        "example-org",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &counting{GitHub: gh, mock: mock}
	now := time.Now()
	s, err := New(Options{
		GitHub:      c,
		Env:         "dev",
		Annotations: manifest.Annotations{Env: manifest.DefaultEnvAnnotation, Region: manifest.DefaultRegionAnnotation},
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, c, &now
}

func names(rs []Repo) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.FullName+":"+r.Access)
	}
	return out
}

func TestList_OnlyWhatEachUserCanRead(t *testing.T) {
	s, gh, now := newService(t, nil)
	ctx := context.Background()
	cases := map[*userauth.User][]string{
		alice: {"example-org/apps:write", "example-org/platform:read"},
		bob:   {"example-org/apps:read"},
		carol: nil,
	}
	for u, want := range cases {
		got, err := s.List(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(got.Repositories), want) || got.Incomplete {
			t.Errorf("%s sees %v (incomplete %v), want %v", u.Login, names(got.Repositories), got.Incomplete, want)
		}
	}
	// one listing of the installation for everyone, and a permission
	// lookup per user and repository
	if gh.repositories.Load() != 1 || gh.permissions.Load() != 9 {
		t.Fatalf("listings %d, permission lookups %d", gh.repositories.Load(), gh.permissions.Load())
	}

	// the list reuses permissions for listPermissionTTL; opening a
	// repository needs one younger than the PermissionTTL
	*now = now.Add(DefaultPermissionTTL + time.Second)
	if _, err := s.List(ctx, alice); err != nil || gh.permissions.Load() != 9 {
		t.Fatalf("permission lookups %d, %v", gh.permissions.Load(), err)
	}
	if _, err := s.Require(ctx, alice, "example-org", "apps", true); err != nil || gh.permissions.Load() != 10 {
		t.Fatalf("permission lookups %d, %v", gh.permissions.Load(), err)
	}
	*now = now.Add(listPermissionTTL)
	if _, err := s.List(ctx, alice); err != nil || gh.permissions.Load() != 13 {
		t.Fatalf("permission lookups %d after the list's TTL, %v", gh.permissions.Load(), err)
	}
	if _, err := s.List(ctx, nil); err == nil {
		t.Error("listed for nobody")
	}
}

func TestList_WhatWasCheckedInTime(t *testing.T) {
	s, gh, _ := newService(t, nil)
	gh.stall = "example-org/platform"
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	got, err := s.List(ctx, alice)
	// apps is checked in time, platform is not, restricted is not alice's
	if err != nil || !got.Incomplete || !slices.Equal(names(got.Repositories), []string{"example-org/apps:write"}) {
		t.Fatalf("list = %+v, %v", got, err)
	}
	// knowing none in time is an empty list, not an error
	gh.stall = "example-org/apps"
	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if got, err := s.List(ctx, bob); err != nil || !got.Incomplete || len(got.Repositories) != 0 {
		t.Fatalf("bob's list = %+v, %v", got, err)
	}

	// the next list checks only what is missing
	gh.stall = ""
	before := gh.permissions.Load()
	got, err = s.List(context.Background(), alice)
	if err != nil || got.Incomplete || len(got.Repositories) != 2 || gh.permissions.Load() != before+1 {
		t.Fatalf("list = %+v, %v, %d lookups", got, err, gh.permissions.Load()-before)
	}
}

func TestList_PermissionChecksFailing(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	if _, err := s.Require(ctx, alice, "example-org", "apps", false); err != nil {
		t.Fatal(err)
	}
	gh.permErr = &githubapp.RateLimitError{Status: 403, RetryAt: time.Now().Add(time.Minute)}
	// what is known is listed; the rest is missing, and the list says so
	got, err := s.List(ctx, alice)
	if err != nil || !got.Incomplete || !slices.Equal(names(got.Repositories), []string{"example-org/apps:write"}) {
		t.Fatalf("list = %+v, %v", got, err)
	}
	// with nothing to show, the failure is the answer
	var limited *githubapp.RateLimitError
	if _, err := s.List(ctx, bob); !errors.As(err, &limited) {
		t.Fatalf("bob's list: %v", err)
	}
}

// cutShort lists some repositories, then fails.
type cutShort struct {
	GitHub
	err error
}

func (c cutShort) Repositories(ctx context.Context) ([]githubapp.Repository, error) {
	all, _ := c.GitHub.Repositories(ctx)
	return all[:1], c.err
}

func TestList_PartOfTheInstallation(t *testing.T) {
	s, gh, _ := newService(t, nil)
	s.gh = cutShort{GitHub: gh, err: errors.New("github returned 502")}
	got, err := s.List(context.Background(), alice)
	if err != nil || !got.Incomplete || !slices.Equal(names(got.Repositories), []string{"example-org/apps:write"}) {
		t.Fatalf("list = %+v, %v", got, err)
	}
	// a partial list is not kept
	if s.cache.installed.len() != 0 {
		t.Error("a partial list was kept")
	}
	// with nothing listed, the error is the answer
	s.gh = failing{GitHub: gh, err: errors.New("github returned 502")}
	if _, err := s.List(context.Background(), alice); err == nil {
		t.Fatal("an empty list hid the error")
	}
}

// failing fails every repository listing.
type failing struct {
	GitHub
	err error
}

func (f failing) Repositories(context.Context) ([]githubapp.Repository, error) { return nil, f.err }

func TestCache_SharedByEnvs(t *testing.T) {
	dev, gh, _ := newService(t, nil)
	prod, err := New(Options{
		GitHub: gh, Env: "prod", Cache: dev.cache,
		Annotations: manifest.Annotations{Env: manifest.DefaultEnvAnnotation, Region: manifest.DefaultRegionAnnotation},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, s := range []*Service{dev, prod} {
		if _, err := s.Require(ctx, alice, "example-org", "apps", true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.List(ctx, alice); err != nil {
			t.Fatal(err)
		}
	}
	// one lookup per repository, whichever env asked first
	if gh.permissions.Load() != 3 || gh.repositories.Load() != 1 {
		t.Errorf("permission lookups %d, listings %d, want 3 and 1", gh.permissions.Load(), gh.repositories.Load())
	}
	// parsing is each env's own: prod finds prod's documents
	devFiles, err := dev.Files(ctx, alice, "example-org", "apps", "")
	if err != nil {
		t.Fatal(err)
	}
	prodFiles, err := prod.Files(ctx, alice, "example-org", "apps", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(devFiles.Files) != 4 || len(prodFiles.Files) != 2 || prodFiles.Files[0].Documents[0].Namespace != "billing" {
		t.Fatalf("dev %d files, prod %+v", len(devFiles.Files), prodFiles.Files)
	}
	if gh.trees.Load() != 1 {
		t.Errorf("trees read = %d, want 1: the envs share the globs", gh.trees.Load())
	}
}

func TestRequire(t *testing.T) {
	s, _, _ := newService(t, nil)
	ctx := context.Background()
	cases := []struct {
		user        *userauth.User
		owner, name string
		write       bool
		want        error
	}{
		{alice, "example-org", "apps", true, nil},
		{alice, "Example-Org", "APPS", true, nil},
		{alice, "example-org", "platform", false, nil},
		{alice, "example-org", "platform", true, ErrForbidden},
		{alice, "example-org", "restricted", false, ErrNotFound},
		{alice, "example-org", "missing", false, ErrNotFound},
		{alice, "example-org", "..", false, ErrNotFound},
		{carol, "example-org", "apps", false, ErrNotFound},
	}
	for _, tc := range cases {
		if _, err := s.Require(ctx, tc.user, tc.owner, tc.name, tc.write); !errors.Is(err, tc.want) {
			t.Errorf("%s on %s/%s (write %v): %v, want %v", tc.user.Login, tc.owner, tc.name, tc.write, err, tc.want)
		}
	}
}

func TestRequire_DeniesAnswersForAnotherUser(t *testing.T) {
	s, gh, _ := newService(t, nil)
	gh.answerFor = 9999 // the login now belongs to someone else
	if _, err := s.Require(context.Background(), alice, "example-org", "apps", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFiles(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	l, err := s.Files(ctx, alice, "example-org", "apps", "")
	if err != nil {
		t.Fatal(err)
	}
	if l.Branch != "main" || !githubapp.ValidSHA(l.Commit) || l.Repo.Access != "write" || l.Truncated {
		t.Fatalf("listing = %+v", l)
	}
	var paths []string
	for _, f := range l.Files {
		paths = append(paths, f.Path)
	}
	// reports (prod only) and deployment.yaml (no match) are left out
	if !slices.Equal(paths, []string{"deploy/billing/sealed-secret.yaml", "deploy/legacy/sealed-secret.yaml", "deploy/search/sealed-secret.yaml", "deploy/worker/sealed-secret.yaml"}) {
		t.Fatalf("paths = %v", paths)
	}
	if billing := l.Files[0]; len(billing.Documents) != 3 || !githubapp.ValidSHA(billing.Blob) {
		t.Errorf("billing = %+v", billing)
	}
	if legacy := l.Files[1].Documents[0]; legacy.Sealable() || legacy.Scope != manifest.ScopeClusterWide {
		t.Errorf("legacy = %+v", legacy)
	}

	// blobs are parsed once
	blobs := gh.blobs.Load()
	if _, err := s.Files(ctx, bob, "example-org", "apps", ""); err != nil {
		t.Fatal(err)
	}
	if gh.blobs.Load() != blobs {
		t.Error("blobs were fetched again")
	}
	// and the repository's details are reused
	if gh.repository.Load() != 1 {
		t.Errorf("repository read %d times, want 1", gh.repository.Load())
	}
	if _, err := s.Files(ctx, carol, "example-org", "apps", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("carol: %v", err)
	}
}

func TestFiles_UnreadableAndCustomGlobs(t *testing.T) {
	repos := []mockgithub.Repo{{
		Owner: "example-org", Name: "odd", DefaultBranch: "trunk",
		Permissions: map[string]string{"alice": "read"},
		Files: map[string]string{
			"a/sealed.yaml":         "a: [unclosed",
			"b/sealed.yml":          "kind: SealedSecret\nmetadata: {namespace: x, namespace: y}\n",
			"secrets/dev/creds.yml": "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata: {name: c, namespace: ns, annotations: {k8s-sealed-secrets-sealer/env: dev}}\nspec: {encryptedData: {}}\n",
		},
	}}
	s, _, _ := newService(t, repos)
	l, err := s.Files(context.Background(), alice, "example-org", "odd", "")
	if err != nil {
		t.Fatal(err)
	}
	if l.Branch != "trunk" || len(l.Files) != 2 || l.Files[0].Error != manifest.ErrInvalidYAML.Error() || l.Files[1].Error != manifest.ErrDuplicateKey.Error() {
		t.Fatalf("files = %+v", l.Files)
	}

	// a glob with a slash matches whole paths; other globs, other
	// candidates
	s.globs = []string{"secrets/*/*.yml"}
	l, err = s.Files(context.Background(), alice, "example-org", "odd", "")
	if err != nil || len(l.Files) != 1 || l.Files[0].Path != "secrets/dev/creds.yml" {
		t.Fatalf("files = %+v, %v", l.Files, err)
	}
	if _, err := New(Options{FileGlobs: []string{"[bad"}}); err == nil || !strings.Contains(err.Error(), "glob") {
		t.Errorf("bad glob: %v", err)
	}
}

func TestHeadAndFile(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()

	r, head, err := s.Head(ctx, alice, "Example-Org", "APPS", true)
	if err != nil || r.FullName != "example-org/apps" || r.Access != "write" || !githubapp.ValidSHA(head) {
		t.Fatalf("Head = %+v, %s, %v", r, head, err)
	}
	if _, _, err := s.Head(ctx, bob, "example-org", "apps", true); !errors.Is(err, ErrForbidden) {
		t.Errorf("bob's write head: %v", err)
	}

	// a listing at a commit, then single files at it, share one tree read
	l, err := s.Files(ctx, alice, "example-org", "apps", head)
	if err != nil || l.Commit != head || len(l.Files) != 4 {
		t.Fatalf("Files at %s = %+v, %v", head, l, err)
	}
	f, err := s.File(ctx, alice, "example-org", "apps", head, "deploy/billing/sealed-secret.yaml", true)
	if err != nil || len(f.Documents) != 3 || f.Error != "" {
		t.Fatalf("File = %+v, %v", f, err)
	}
	if n := gh.trees.Load(); n != 1 {
		t.Errorf("trees read = %d, want 1", n)
	}

	cases := map[string]struct {
		user   *userauth.User
		commit string
		path   string
		write  bool
		want   error
	}{
		"not matching the globs": {alice, head, "deploy/billing/deployment.yaml", true, ErrFileNotFound},
		"missing":                {alice, head, "deploy/nothing/sealed-secret.yaml", true, ErrFileNotFound},
		"invalid commit":         {alice, "main", "deploy/billing/sealed-secret.yaml", true, ErrCommitNotFound},
		"unknown commit":         {alice, strings.Repeat("0", 40), "deploy/billing/sealed-secret.yaml", true, ErrCommitNotFound},
		"read only":              {bob, head, "deploy/billing/sealed-secret.yaml", true, ErrForbidden},
		"no access":              {carol, head, "deploy/billing/sealed-secret.yaml", false, ErrNotFound},
	}
	for name, tc := range cases {
		if _, err := s.File(ctx, tc.user, "example-org", "apps", tc.commit, tc.path, tc.write); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestFiles_ConcurrentListingsReadEachBlobOnce(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	_, head, err := s.Head(ctx, alice, "example-org", "apps", false)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if l, err := s.Files(ctx, alice, "example-org", "apps", head); err != nil || len(l.Files) != 4 {
				t.Errorf("files = %+v, %v", l, err)
			}
		})
	}
	wg.Wait()
	// five files match the globs, and the tree is read once
	if gh.blobs.Load() != 5 || gh.trees.Load() != 1 {
		t.Errorf("blobs read %d, trees %d", gh.blobs.Load(), gh.trees.Load())
	}
}

func TestFile_GitHubFailuresAreErrors(t *testing.T) {
	s, gh, _ := newService(t, nil)
	ctx := context.Background()
	_, head, err := s.Head(ctx, alice, "example-org", "apps", true)
	if err != nil {
		t.Fatal(err)
	}
	gh.blobErr = &githubapp.StatusError{Status: http.StatusBadGateway, Message: "Server Error"}

	// sealing needs the file: GitHub's failure is the answer
	if f, err := s.File(ctx, alice, "example-org", "apps", head, "deploy/billing/sealed-secret.yaml", true); err == nil || f.Error != "" {
		t.Fatalf("file = %+v, %v", f, err)
	}
	// a listing names the files it could not read
	l, err := s.Files(ctx, alice, "example-org", "apps", head)
	if err != nil || len(l.Files) != 5 || l.Files[0].Error != "file could not be read from GitHub" {
		t.Fatalf("files = %+v, %v", l, err)
	}
	// unless the rate limit is why
	gh.blobErr = fmt.Errorf("failed to read blob: %w", &githubapp.RateLimitError{Status: 403, RetryAt: time.Now().Add(time.Minute)})
	var limited *githubapp.RateLimitError
	if _, err := s.Files(ctx, alice, "example-org", "apps", head); !errors.As(err, &limited) {
		t.Fatalf("rate limited files: %v", err)
	}
	// none of that was kept: the files parse once GitHub answers
	gh.blobErr = nil
	if f, err := s.File(ctx, alice, "example-org", "apps", head, "deploy/billing/sealed-secret.yaml", true); err != nil || len(f.Documents) != 3 {
		t.Fatalf("file = %+v, %v", f, err)
	}
}

func TestRepository_DetailsReusedBriefly(t *testing.T) {
	s, gh, now := newService(t, nil)
	ctx := context.Background()
	for range 3 {
		if _, _, err := s.Head(ctx, alice, "example-org", "apps", true); err != nil {
			t.Fatal(err)
		}
	}
	if gh.repository.Load() != 1 {
		t.Fatalf("repository read %d times, want 1", gh.repository.Load())
	}
	*now = now.Add(repositoryTTL + time.Second)
	if _, _, err := s.Head(ctx, alice, "example-org", "apps", true); err != nil || gh.repository.Load() != 2 {
		t.Fatalf("repository read %d times after its TTL, %v", gh.repository.Load(), err)
	}
}

func TestLRU(t *testing.T) {
	c := newLRU[int](2)
	now := time.Now()
	c.put("a", 1, time.Time{})
	c.put("b", 2, time.Time{})
	if _, ok := c.get("a", now); !ok { // a is now the most recently used
		t.Fatal("a is missing")
	}
	c.put("c", 3, time.Time{})
	if _, ok := c.get("b", now); ok {
		t.Error("b, the least recently used, was kept")
	}
	if v, ok := c.get("a", now); !ok || v != 1 {
		t.Error("a was dropped")
	}
	c.put("a", 4, now.Add(time.Minute))
	if v, ok := c.get("a", now); !ok || v != 4 {
		t.Errorf("a = %d, %v", v, ok)
	}
	if _, ok := c.get("a", now.Add(time.Minute)); ok || c.len() != 1 {
		t.Errorf("an expired entry was returned or kept: %d entries", c.len())
	}
}
