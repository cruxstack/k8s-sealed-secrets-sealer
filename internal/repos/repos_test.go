package repos

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
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
	permissions atomic.Int32
	blobs       atomic.Int32
	trees       atomic.Int32
	// answerFor, when set, makes permission answers claim another user
	answerFor int64
	mock      *mockgithub.Server
}

func (c *counting) Permission(ctx context.Context, owner, repo, login string) (githubapp.Permission, error) {
	c.permissions.Add(1)
	p, err := c.GitHub.Permission(ctx, owner, repo, login)
	if c.answerFor != 0 {
		p.UserID = c.answerFor
	}
	return p, err
}

func (c *counting) Blob(ctx context.Context, owner, repo, sha string) ([]byte, error) {
	c.blobs.Add(1)
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
		if !slices.Equal(names(got), want) {
			t.Errorf("%s sees %v, want %v", u.Login, names(got), want)
		}
	}

	// permissions are reused until they expire
	before := gh.permissions.Load()
	if _, err := s.List(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if gh.permissions.Load() != before {
		t.Error("permissions were looked up again within their TTL")
	}
	*now = now.Add(DefaultPermissionTTL + time.Second)
	if _, err := s.List(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if gh.permissions.Load() == before {
		t.Error("expired permissions were reused")
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

	// a glob with a slash matches whole paths
	s.globs = []string{"secrets/*/*.yml"}
	s.snapshots = map[string]snapshot{}
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
