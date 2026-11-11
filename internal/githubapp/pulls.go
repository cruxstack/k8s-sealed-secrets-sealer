package githubapp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
)

// Write is what opening a pull request needs: a blob, tree, commit and
// branch (contents) and the pull request itself. Each token is minted for
// one use and only these.
var Write = Permissions{"contents": "write", "metadata": "read", "pull_requests": "write"}

// Limits on a pull request.
const (
	// MaxPullRequestFiles bounds the files one pull request changes.
	MaxPullRequestFiles = 100
	// blobConcurrency bounds parallel blob uploads.
	blobConcurrency = 4
)

var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

// ErrBranchChanged is returned when a branch an earlier attempt left holds
// a commit the App did not make on Parent, such as a reviewer's pushed to
// its pull request: the branch is not moved over it.
var ErrBranchChanged = errors.New("the branch has commits the sealer did not make")

// ValidBranch reports whether s is a branch name the client creates: a
// conservative subset of what Git allows.
func ValidBranch(s string) bool {
	return branchPattern.MatchString(s) &&
		!strings.Contains(s, "..") && !strings.Contains(s, "//") && !strings.Contains(s, "/.") &&
		!strings.HasSuffix(s, "/") && !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, ".lock")
}

// FileChange is a file's new content.
type FileChange struct {
	Path string
	// Mode is the file's Git mode, 100644 or 100755.
	Mode    string
	Content []byte
}

// NewPullRequest is one commit on a new branch, and the pull request that
// proposes it.
type NewPullRequest struct {
	// Base is the branch the pull request merges into.
	Base string
	// Parent is the commit the new commit builds on.
	Parent string
	// Branch is created for the commit. One left by an earlier attempt is
	// reused (CreatePullRequest).
	Branch  string
	Message string
	Files   []FileChange
	Title   string
	Body    string
}

// PullRequest is an opened pull request.
type PullRequest struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	Branch string `json:"branch"`
	Commit string `json:"commit"`
}

func (p NewPullRequest) check() error {
	switch {
	case !ValidSHA(p.Parent):
		return fmt.Errorf("invalid parent commit %q", p.Parent)
	case !ValidBranch(p.Branch):
		return fmt.Errorf("invalid branch name %q", p.Branch)
	case p.Base == "" || p.Base == p.Branch:
		return errors.New("invalid base branch")
	case strings.TrimSpace(p.Title) == "" || strings.TrimSpace(p.Message) == "":
		return errors.New("a title and a commit message are required")
	case len(p.Files) == 0 || len(p.Files) > MaxPullRequestFiles:
		return fmt.Errorf("%d files; between 1 and %d can be changed", len(p.Files), MaxPullRequestFiles)
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if f.Path == "" || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, "../") || f.Path == ".." {
			return fmt.Errorf("invalid file path %q", f.Path)
		}
		if f.Mode != "100644" && f.Mode != "100755" {
			return fmt.Errorf("file %s has mode %q; only regular files can be changed", f.Path, f.Mode)
		}
		if seen[f.Path] {
			return fmt.Errorf("file %s is changed twice", f.Path)
		}
		seen[f.Path] = true
	}
	return nil
}

// CreatePullRequest commits files on Branch, based on Parent, and opens a
// pull request from it into Base. The commit is made through the API
// without an author, so GitHub signs it as the App.
//
// It is safe to call again after it failed part way, or after GitHub acted
// but its answer was lost: a Branch left by an earlier attempt is kept when
// it already holds these files and moved to the new commit otherwise, and a
// pull request open from it is returned, its title and description brought
// up to date, instead of opening another. A branch is moved only from the
// App's own commit on Parent; one with anyone else's commits, such as a
// reviewer's, fails with ErrBranchChanged. A branch it created is deleted
// again only when GitHub refuses the pull request outright: after a timeout
// the pull request may exist, and deleting its branch would close it.
func (c *Client) CreatePullRequest(ctx context.Context, owner, repo string, pr NewPullRequest) (PullRequest, error) {
	if err := pr.check(); err != nil {
		return PullRequest{}, fmt.Errorf("failed to create a pull request: %w", err)
	}
	tok, err := c.Token(ctx, Write)
	if err != nil {
		return PullRequest{}, err
	}

	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	entries := make([]treeEntry, len(pr.Files))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(blobConcurrency)
	for i, f := range pr.Files {
		g.Go(func() error {
			var out struct {
				SHA string `json:"sha"`
			}
			in := map[string]string{"content": base64.StdEncoding.EncodeToString(f.Content), "encoding": "base64"}
			if err := c.do(gctx, http.MethodPost, c.repoURL(owner, repo, "git", "blobs"), tok, in, maxResponseBytes, &out); err != nil {
				return fmt.Errorf("failed to upload %s: %w", f.Path, err)
			}
			if !ValidSHA(out.SHA) {
				return fmt.Errorf("failed to upload %s: github returned no object id", f.Path)
			}
			entries[i] = treeEntry{Path: f.Path, Mode: f.Mode, Type: "blob", SHA: out.SHA}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return PullRequest{}, err
	}

	parent, err := c.readCommit(ctx, tok, owner, repo, pr.Parent)
	if err != nil {
		return PullRequest{}, err
	}
	parentTree := parent.Tree.SHA
	var tree struct {
		SHA string `json:"sha"`
	}
	treeIn := map[string]any{"base_tree": parentTree, "tree": entries}
	if err := c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "git", "trees"), tok, treeIn, maxResponseBytes, &tree); err != nil {
		return PullRequest{}, fmt.Errorf("failed to create a tree: %w", err)
	}
	if !ValidSHA(tree.SHA) {
		return PullRequest{}, errors.New("failed to create a tree: github returned no object id")
	}
	var commit gitCommit
	commitIn := map[string]any{"message": pr.Message, "tree": tree.SHA, "parents": []string{pr.Parent}}
	if err := c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "git", "commits"), tok, commitIn, maxResponseBytes, &commit); err != nil {
		return PullRequest{}, fmt.Errorf("failed to create a commit: %w", err)
	}
	if !ValidSHA(commit.SHA) {
		return PullRequest{}, errors.New("failed to create a commit: github returned no object id")
	}
	commit.Tree.SHA = tree.SHA

	head, err := c.pushBranch(ctx, tok, owner, repo, pr, commit)
	if err != nil {
		return PullRequest{}, err
	}
	if !head.created {
		open, ok, err := c.openPull(ctx, tok, owner, repo, pr.Branch)
		if err != nil {
			return PullRequest{}, err
		}
		if ok {
			return c.reusePull(ctx, tok, owner, repo, open, pr, head.sha)
		}
	}

	var out ghPull
	prIn := map[string]any{"title": pr.Title, "body": pr.Body, "head": pr.Branch, "base": pr.Base}
	err = c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "pulls"), tok, prIn, maxResponseBytes, &out)
	if err == nil && (out.Number <= 0 || !webURL(out.HTMLURL)) {
		err = errors.New("github returned no pull request")
	}
	if err == nil {
		return PullRequest{Number: out.Number, URL: out.HTMLURL, Branch: pr.Branch, Commit: head.sha}, nil
	}
	// an attempt whose answer was lost may have opened it already
	var refusal *StatusError
	if errors.As(err, &refusal) && refusal.Status == http.StatusUnprocessableEntity {
		if open, ok, lookupErr := c.openPull(ctx, tok, owner, repo, pr.Branch); lookupErr == nil && ok {
			return c.reusePull(ctx, tok, owner, repo, open, pr, head.sha)
		}
	}
	// leave no branch behind when GitHub said no for good, and there is
	// time left to delete it; otherwise a retry reuses it
	if head.created && refused(err) && ctx.Err() == nil {
		if delErr := c.do(ctx, http.MethodDelete, c.repoURL(owner, repo, branchRef(pr.Branch)...), tok, nil, maxResponseBytes, nil); delErr != nil {
			return PullRequest{}, fmt.Errorf("failed to open the pull request: %w (and failed to delete branch %s: %w)", err, pr.Branch, delErr)
		}
	}
	return PullRequest{}, fmt.Errorf("failed to open the pull request: %w", err)
}

// reusePull returns a pull request an earlier attempt opened from the
// branch, with the title and description brought up to date: the attempt
// that changed the branch may have failed before it changed them.
func (c *Client) reusePull(ctx context.Context, tok, owner, repo string, open ghPull, pr NewPullRequest, head string) (PullRequest, error) {
	if open.Title != pr.Title || open.Body != pr.Body {
		update := map[string]string{"title": pr.Title, "body": pr.Body}
		if err := c.do(ctx, http.MethodPatch, c.repoURL(owner, repo, "pulls", strconv.Itoa(open.Number)), tok, update, maxResponseBytes, nil); err != nil {
			return PullRequest{}, fmt.Errorf("failed to update pull request #%d: %w", open.Number, err)
		}
	}
	return PullRequest{Number: open.Number, URL: open.HTMLURL, Branch: pr.Branch, Commit: head}, nil
}

// branchState is where pushBranch left a branch.
type branchState struct {
	sha string
	// created is set for a branch that did not exist
	created bool
}

// pushBranch points pr's branch at commit. It creates the branch or, when
// an earlier attempt left it behind, keeps it if its commit has the same
// tree, and moves it to commit otherwise. It moves it only from a commit
// the App made on pr.Parent, an earlier attempt's: moving it by force then
// loses nothing but that attempt. Anyone else's commit, such as a
// reviewer's pushed to the pull request, fails with ErrBranchChanged.
func (c *Client) pushBranch(ctx context.Context, tok, owner, repo string, pr NewPullRequest, commit gitCommit) (branchState, error) {
	branch := pr.Branch
	refIn := map[string]string{"ref": "refs/heads/" + branch, "sha": commit.SHA}
	err := c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "git", "refs"), tok, refIn, maxResponseBytes, nil)
	if err == nil {
		return branchState{sha: commit.SHA, created: true}, nil
	}
	// GitHub refuses a branch that exists with 422
	var refusal *StatusError
	if !errors.As(err, &refusal) || refusal.Status != http.StatusUnprocessableEntity {
		return branchState{}, fmt.Errorf("failed to create branch %s: %w", branch, err)
	}
	existing, headErr := c.branchHead(ctx, tok, owner, repo, branch)
	if errors.Is(headErr, ErrNotFound) {
		return branchState{}, fmt.Errorf("failed to create branch %s: %w", branch, err)
	}
	if headErr != nil {
		return branchState{}, headErr
	}
	head, err := c.readCommit(ctx, tok, owner, repo, existing)
	if err != nil {
		return branchState{}, err
	}
	if head.Tree.SHA == commit.Tree.SHA {
		return branchState{sha: existing}, nil
	}
	if !commit.madeLike(head, pr.Parent) {
		return branchState{}, fmt.Errorf("failed to update branch %s: %w", branch, ErrBranchChanged)
	}
	move := map[string]any{"sha": commit.SHA, "force": true}
	if err := c.do(ctx, http.MethodPatch, c.repoURL(owner, repo, branchRef(branch)...), tok, move, maxResponseBytes, nil); err != nil {
		return branchState{}, fmt.Errorf("failed to move branch %s: %w", branch, err)
	}
	return branchState{sha: commit.SHA}, nil
}

// gitCommit is a commit as GitHub's Git database API describes it.
type gitCommit struct {
	SHA  string `json:"sha"`
	Tree struct {
		SHA string `json:"sha"`
	} `json:"tree"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
	// Committer is the App's bot for commits the App made through the API
	Committer struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"committer"`
}

// madeLike reports whether other was made as c was, by the same committer
// on parent alone: an earlier attempt's commit, not someone else's.
func (c gitCommit) madeLike(other gitCommit, parent string) bool {
	return c.Committer.Name != "" && other.Committer == c.Committer &&
		len(other.Parents) == 1 && other.Parents[0].SHA == parent
}

// readCommit reads a commit.
func (c *Client) readCommit(ctx context.Context, tok, owner, repo, sha string) (gitCommit, error) {
	var out gitCommit
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo, "git", "commits", sha), tok, nil, maxResponseBytes, &out); err != nil {
		return gitCommit{}, fmt.Errorf("failed to read commit %s: %w", sha, err)
	}
	if !ValidSHA(out.Tree.SHA) {
		return gitCommit{}, fmt.Errorf("failed to read commit %s: it has no tree", sha)
	}
	out.SHA = sha
	return out, nil
}

type ghPull struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

// openPull returns the pull request open from a branch of the repository, if
// there is one.
func (c *Client) openPull(ctx context.Context, tok, owner, repo, branch string) (ghPull, bool, error) {
	q := url.Values{"head": {owner + ":" + branch}, "state": {"open"}, "per_page": {"10"}}
	var out []ghPull
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo, "pulls")+"?"+q.Encode(), tok, nil, maxResponseBytes, &out); err != nil {
		return ghPull{}, false, fmt.Errorf("failed to look up the pull request from %s: %w", branch, err)
	}
	for _, p := range out {
		if p.Head.Ref == branch && p.Number > 0 && webURL(p.HTMLURL) {
			return p, true, nil
		}
	}
	return ghPull{}, false, nil
}

// refused reports whether GitHub turned a request down for good: a 4xx
// other than a timeout or a rate limit, so trying again would not help.
func refused(err error) bool {
	var refusal *StatusError
	return errors.As(err, &refusal) && refusal.Status >= 400 && refusal.Status < 500 && refusal.Status != http.StatusRequestTimeout
}

// branchRef is the path of a branch's reference: git/refs/heads/<branch>.
func branchRef(branch string) []string {
	return append([]string{"git", "refs", "heads"}, strings.Split(branch, "/")...)
}

// webURL reports whether s is an http(s) URL, safe to show as a link.
func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}
