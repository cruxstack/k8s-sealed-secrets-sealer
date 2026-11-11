package githubapp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/mockgithub"
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

	// the same branch again, as a retry would: the same pull request,
	// untouched
	again, err := c.CreatePullRequest(ctx, "example-org", "apps", pr)
	if err != nil || again != got {
		t.Fatalf("second pull request on the same branch = %+v, %v; want %+v", again, err, got)
	}
	if _, ok := f.mock.PullRequest("example-org", "apps", 2); ok {
		t.Fatal("a second pull request was opened")
	}
}

// newPull is a pull request of one file on a session's branch.
func newPull(t *testing.T, c *Client, branch, content string) NewPullRequest {
	t.Helper()
	head, err := c.BranchHead(context.Background(), "example-org", "apps", "main")
	if err != nil {
		t.Fatal(err)
	}
	return NewPullRequest{
		Base: "main", Parent: head, Branch: branch, Message: "Seal\n", Title: "Seal " + content, Body: "body " + content,
		Files: []FileChange{{Path: "deploy/billing/sealed-secret.yaml", Mode: "100644", Content: []byte(content + "\n")}},
	}
}

func TestCreatePullRequest_RetriesWhereGitHubActedButTheAnswerWasLost(t *testing.T) {
	cases := map[string]struct {
		path  string
		fault mockgithub.Fault
	}{
		"branch created, then the client timed out":      {"/git/refs", mockgithub.Stall},
		"branch created, then the answer was lost":       {"/git/refs", mockgithub.LoseAnswer},
		"pull request opened, then the client timed out": {"/pulls", mockgithub.Stall},
		"pull request opened, then the answer was lost":  {"/pulls", mockgithub.LoseAnswer},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c := f.client(t, nil)
			pr := newPull(t, c, "sealer/dev/alice-01j", "sealed")
			f.mock.FailNext(http.MethodPost, tc.path, tc.fault)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := c.CreatePullRequest(ctx, "example-org", "apps", pr); err == nil {
				t.Fatal("the first attempt succeeded")
			}
			// the branch is kept: a pull request may be open from it
			first, err := c.BranchHead(context.Background(), "example-org", "apps", pr.Branch)
			if err != nil {
				t.Fatalf("the branch was not kept: %v", err)
			}

			got, err := c.CreatePullRequest(context.Background(), "example-org", "apps", pr)
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			// the earlier attempt's commit holds the same files, so it stays
			if got.Number != 1 || got.Commit != first || got.Branch != pr.Branch {
				t.Fatalf("retry = %+v, want #1 at %s", got, first)
			}
			view, ok := f.mock.PullRequest("example-org", "apps", 1)
			if !ok || view.State != "open" || len(view.Files) != 1 || view.Files[0].After != "sealed\n" || view.Title != pr.Title {
				t.Fatalf("pull request = %+v", view)
			}
			if _, ok := f.mock.PullRequest("example-org", "apps", 2); ok {
				t.Fatal("a second pull request was opened")
			}
		})
	}
}

func TestCreatePullRequest_MovesABranchThatHoldsOtherFiles(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()

	// a pull request is open from the branch, and another value was sealed
	// since: the branch moves, and the pull request says so
	first, err := c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-01j", "one value"))
	if err != nil {
		t.Fatal(err)
	}
	pr := newPull(t, c, "sealer/dev/alice-01j", "two values")
	got, err := c.CreatePullRequest(ctx, "example-org", "apps", pr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Number != first.Number || got.Commit == first.Commit {
		t.Fatalf("pull request = %+v, first = %+v", got, first)
	}
	view, _ := f.mock.PullRequest("example-org", "apps", 1)
	if view.Files[0].After != "two values\n" || view.Title != pr.Title || view.Body != pr.Body || len(view.Commits) != 1 {
		t.Fatalf("pull request = %+v", view)
	}

	// a branch left without a pull request moves, and gets one
	f.mock.FailNext(http.MethodPost, "/git/refs", mockgithub.LoseAnswer)
	if _, err := c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-02j", "stale")); err == nil {
		t.Fatal("the answer was not lost")
	}
	got, err = c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-02j", "fresh"))
	if err != nil || got.Number != 2 {
		t.Fatalf("pull request = %+v, %v", got, err)
	}
	if view, _ := f.mock.PullRequest("example-org", "apps", 2); view.Files[0].After != "fresh\n" || view.State != "open" {
		t.Fatalf("pull request = %+v", view)
	}
}

// An attempt can move the branch and fail before it updates the pull
// request's text; the next finds the branch right, and must still bring
// the title and description up to date.
func TestCreatePullRequest_UpdatesTheTextOfAPullRequestItReuses(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	if _, err := c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-01j", "one value")); err != nil {
		t.Fatal(err)
	}
	pr := newPull(t, c, "sealer/dev/alice-01j", "two values")
	f.mock.FailNext(http.MethodPatch, "/pulls/1", mockgithub.ServerError)
	if _, err := c.CreatePullRequest(ctx, "example-org", "apps", pr); err == nil {
		t.Fatal("the update did not fail")
	}
	got, err := c.CreatePullRequest(ctx, "example-org", "apps", pr)
	if err != nil || got.Number != 1 {
		t.Fatalf("retry = %+v, %v", got, err)
	}
	view, _ := f.mock.PullRequest("example-org", "apps", 1)
	if view.Files[0].After != "two values\n" || view.Title != pr.Title || view.Body != pr.Body {
		t.Fatalf("pull request = %+v", view)
	}
}

// A retry must not force the branch over commits someone else pushed to
// the pull request since, such as a reviewer's.
func TestCreatePullRequest_LeavesABranchWithOthersCommits(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	first, err := c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-01j", "one value"))
	if err != nil {
		t.Fatal(err)
	}
	reviewed, ok := f.mock.Push("example-org", "apps", "sealer/dev/alice-01j", "reviewer", map[string]string{"README.md": "fixed\n"})
	if !ok {
		t.Fatal("push failed")
	}
	_, err = c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-01j", "two values"))
	if !errors.Is(err, ErrBranchChanged) {
		t.Fatalf("retry over a reviewer's commit = %v, want ErrBranchChanged", err)
	}
	if head, _ := c.BranchHead(ctx, "example-org", "apps", "sealer/dev/alice-01j"); head != reviewed {
		t.Fatalf("branch at %s, want the reviewer's %s", head, reviewed)
	}
	if view, _ := f.mock.PullRequest("example-org", "apps", first.Number); view.Title != "Seal one value" {
		t.Fatalf("pull request = %+v", view)
	}

	// nor over someone else's commit on the session's base
	theirs, _ := f.mock.Push("example-org", "apps", "sealer/dev/alice-02j", "someone", map[string]string{"README.md": "theirs\n"})
	_, err = c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, "sealer/dev/alice-02j", "mine"))
	if !errors.Is(err, ErrBranchChanged) {
		t.Fatalf("pull request over someone else's commit = %v, want ErrBranchChanged", err)
	}
	if head, _ := c.BranchHead(ctx, "example-org", "apps", "sealer/dev/alice-02j"); head != theirs {
		t.Fatalf("branch at %s, want %s", head, theirs)
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

func TestPullRequestState(t *testing.T) {
	f := newFixture(t)
	c := f.client(t, nil)
	ctx := context.Background()
	for _, branch := range []string{"sealer/dev/a", "sealer/dev/b"} {
		if _, err := c.CreatePullRequest(ctx, "example-org", "apps", newPull(t, c, branch, branch)); err != nil {
			t.Fatal(err)
		}
	}
	st, err := c.PullRequestState(ctx, "example-org", "apps", 1)
	if err != nil || !st.Open || st.Merged {
		t.Fatalf("open = %+v, %v", st, err)
	}
	// one merged, one closed
	if !f.mock.ClosePullRequest("example-org", "apps", 1, true) || !f.mock.ClosePullRequest("example-org", "apps", 2, false) {
		t.Fatal("close")
	}
	if st, err := c.PullRequestState(ctx, "example-org", "apps", 1); err != nil || st.Open || !st.Merged || st.MergedAt == nil || st.ClosedAt == nil {
		t.Fatalf("merged = %+v, %v", st, err)
	}
	if st, err := c.PullRequestState(ctx, "example-org", "apps", 2); err != nil || st.Open || st.Merged || st.ClosedAt == nil {
		t.Fatalf("closed = %+v, %v", st, err)
	}
	if _, err := c.PullRequestState(ctx, "example-org", "apps", 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown = %v", err)
	}
	// a merge moved the base branch to the pull request's head
	if head, _ := c.BranchHead(ctx, "example-org", "apps", "main"); head == "" {
		t.Fatal("no head")
	}
	if content, _ := f.mock.File("example-org", "apps", "main", "deploy/billing/sealed-secret.yaml"); content != "sealer/dev/a\n" {
		t.Fatalf("main after the merge = %q", content)
	}
}
