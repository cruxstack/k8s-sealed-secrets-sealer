package githubapp

import (
	"context"
	"strings"
	"testing"
)

func TestCreatePullRequest(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	head, err := c.BranchHead(ctx, "example-org", "apps", "main")
	if err != nil {
		t.Fatal(err)
	}
	pr := NewPullRequest{
		Base:    "main",
		Parent:  head,
		Branch:  "sealer/dev/alice-1",
		Message: "Seal api-token\n\nRequested-by: alice",
		Title:   "Seal api-token",
		Body:    "body",
		Files: []FileChange{
			{Path: "deploy/billing/sealed-secret.yaml", Mode: "100644", Content: []byte("new billing\n")},
			{Path: "deploy/search/sealed-secret.yaml", Mode: "100644", Content: []byte("new search\n")},
		},
	}
	got, err := c.CreatePullRequest(ctx, "example-org", "apps", pr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Number != 1 || got.Branch != pr.Branch || !ValidSHA(got.Commit) || !strings.HasSuffix(got.URL, "/example-org/apps/pull/1") {
		t.Fatalf("pull request = %+v", got)
	}
	view, ok := f.mock.PullRequest("example-org", "apps", 1)
	if !ok {
		t.Fatal("the mock has no pull request")
	}
	if view.Title != pr.Title || view.Body != pr.Body || view.Base != "main" || view.Head != pr.Branch ||
		view.Message != pr.Message || len(view.Commits) != 1 || view.Commits[0] != got.Commit {
		t.Fatalf("pull request in the mock = %+v", view)
	}
	if len(view.Files) != 2 || view.Files[0].After != "new billing\n" || view.Files[1].After != "new search\n" ||
		!strings.Contains(view.Files[0].Before, "kind: SealedSecret") {
		t.Fatalf("changed files = %+v", view.Files)
	}
	// the base branch is untouched
	if now, _ := c.BranchHead(ctx, "example-org", "apps", "main"); now != head {
		t.Fatalf("main moved to %s", now)
	}

	// the same branch again: GitHub refuses to create it
	if _, err := c.CreatePullRequest(ctx, "example-org", "apps", pr); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second pull request on the same branch: %v", err)
	}
}

func TestCreatePullRequest_DeletesTheBranchWhenThePullRequestFails(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	head, err := c.BranchHead(ctx, "example-org", "apps", "main")
	if err != nil {
		t.Fatal(err)
	}
	pr := NewPullRequest{
		Base: "no-such-branch", Parent: head, Branch: "sealer/dev/alice-2",
		Message: "m", Title: "t",
		Files: []FileChange{{Path: "a.yaml", Mode: "100644", Content: []byte("a\n")}},
	}
	if _, err := c.CreatePullRequest(ctx, "example-org", "apps", pr); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := c.BranchHead(ctx, "example-org", "apps", pr.Branch); err == nil {
		t.Fatal("the branch was left behind")
	}
}

func TestCreatePullRequest_MintsAWriteTokenForWrites(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	head, err := c.BranchHead(ctx, "example-org", "apps", "main")
	if err != nil {
		t.Fatal(err)
	}
	reads := f.minted.Load()
	_, err = c.CreatePullRequest(ctx, "example-org", "apps", NewPullRequest{
		Base: "main", Parent: head, Branch: "sealer/dev/x", Message: "m", Title: "t",
		Files: []FileChange{{Path: "a.yaml", Mode: "100644", Content: []byte("a\n")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// one more token, with write permissions: the mock refuses writes with
	// the read-only one
	if f.minted.Load() != reads+1 {
		t.Fatalf("tokens minted: %d before, %d after", reads, f.minted.Load())
	}
	if _, err := c.BranchHead(ctx, "example-org", "apps", "sealer/dev/x"); err != nil {
		t.Fatal(err)
	}
}

func TestCreatePullRequest_Refuses(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	sha := strings.Repeat("a", 40)
	good := NewPullRequest{
		Base: "main", Parent: sha, Branch: "sealer/dev/a", Message: "m", Title: "t",
		Files: []FileChange{{Path: "a.yaml", Mode: "100644", Content: []byte("a")}},
	}
	tests := map[string]func(*NewPullRequest){
		"bad parent":       func(p *NewPullRequest) { p.Parent = "main" },
		"bad branch":       func(p *NewPullRequest) { p.Branch = "sealer/../main" },
		"branch is base":   func(p *NewPullRequest) { p.Branch = "main" },
		"lock branch":      func(p *NewPullRequest) { p.Branch = "a.lock" },
		"no title":         func(p *NewPullRequest) { p.Title = " " },
		"no files":         func(p *NewPullRequest) { p.Files = nil },
		"absolute path":    func(p *NewPullRequest) { p.Files[0].Path = "/a.yaml" },
		"parent path":      func(p *NewPullRequest) { p.Files[0].Path = "../a.yaml" },
		"unclean path":     func(p *NewPullRequest) { p.Files[0].Path = "a//b.yaml" },
		"symlink":          func(p *NewPullRequest) { p.Files[0].Mode = "120000" },
		"same file twice":  func(p *NewPullRequest) { p.Files = append(p.Files, p.Files[0]) },
		"too many files":   func(p *NewPullRequest) { p.Files = make([]FileChange, MaxPullRequestFiles+1) },
		"empty file path":  func(p *NewPullRequest) { p.Files[0].Path = "" },
		"no commit msg":    func(p *NewPullRequest) { p.Message = "" },
		"branch ends dot":  func(p *NewPullRequest) { p.Branch = "sealer/a." },
		"branch has space": func(p *NewPullRequest) { p.Branch = "sealer/a b" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pr := good
			pr.Files = append([]FileChange(nil), good.Files...)
			mutate(&pr)
			if _, err := c.CreatePullRequest(context.Background(), "example-org", "apps", pr); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if f.minted.Load() != 0 {
		t.Fatal("a token was minted for a request that was refused up front")
	}
}
