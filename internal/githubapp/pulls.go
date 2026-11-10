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
	"strings"
	"time"

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
	// cleanupTimeout bounds deleting a branch whose pull request failed.
	cleanupTimeout = 15 * time.Second
)

var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

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
	// Branch is created for the commit; it must not exist yet.
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

// CreatePullRequest commits files on a new branch, based on Parent, and
// opens a pull request from it into Base. The commit is made through the
// API without an author, so GitHub signs it as the App. If the pull request
// cannot be opened, the branch is deleted again.
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

	var parent struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo, "git", "commits", pr.Parent), tok, nil, maxResponseBytes, &parent); err != nil {
		return PullRequest{}, fmt.Errorf("failed to read commit %s: %w", pr.Parent, err)
	}
	if !ValidSHA(parent.Tree.SHA) {
		return PullRequest{}, fmt.Errorf("failed to read commit %s: it has no tree", pr.Parent)
	}

	var tree struct {
		SHA string `json:"sha"`
	}
	treeIn := map[string]any{"base_tree": parent.Tree.SHA, "tree": entries}
	if err := c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "git", "trees"), tok, treeIn, maxResponseBytes, &tree); err != nil {
		return PullRequest{}, fmt.Errorf("failed to create a tree: %w", err)
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	commitIn := map[string]any{"message": pr.Message, "tree": tree.SHA, "parents": []string{pr.Parent}}
	if err := c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "git", "commits"), tok, commitIn, maxResponseBytes, &commit); err != nil {
		return PullRequest{}, fmt.Errorf("failed to create a commit: %w", err)
	}
	if !ValidSHA(commit.SHA) {
		return PullRequest{}, errors.New("failed to create a commit: github returned no object id")
	}

	refIn := map[string]string{"ref": "refs/heads/" + pr.Branch, "sha": commit.SHA}
	if err := c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "git", "refs"), tok, refIn, maxResponseBytes, nil); err != nil {
		return PullRequest{}, fmt.Errorf("failed to create branch %s: %w", pr.Branch, err)
	}

	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	prIn := map[string]any{"title": pr.Title, "body": pr.Body, "head": pr.Branch, "base": pr.Base}
	err = c.do(ctx, http.MethodPost, c.repoURL(owner, repo, "pulls"), tok, prIn, maxResponseBytes, &out)
	if err == nil && (out.Number <= 0 || !webURL(out.HTMLURL)) {
		err = errors.New("github returned no pull request")
	}
	if err != nil {
		// leave no branch behind; the request's context may be what failed
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		segments := append([]string{"git", "refs", "heads"}, strings.Split(pr.Branch, "/")...)
		if delErr := c.do(cleanup, http.MethodDelete, c.repoURL(owner, repo, segments...), tok, nil, maxResponseBytes, nil); delErr != nil {
			return PullRequest{}, fmt.Errorf("failed to open the pull request: %w (and failed to delete branch %s: %w)", err, pr.Branch, delErr)
		}
		return PullRequest{}, fmt.Errorf("failed to open the pull request: %w", err)
	}
	return PullRequest{Number: out.Number, URL: out.HTMLURL, Branch: pr.Branch, Commit: commit.SHA}, nil
}

// webURL reports whether s is an http(s) URL, safe to show as a link.
func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}
