// Package githubapp calls GitHub as the GitHub App: it signs App JWTs,
// exchanges them for installation tokens, and reads repositories with them.
//
// The installation token reaches every repository the App is installed on,
// so callers must check the signed-in user's own permission (Permission)
// before acting for them. Each token is minted with only the permissions
// its use needs.
package githubapp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrNotFound is returned when GitHub answers 404: the repository, branch or
// object does not exist, or the App cannot see it.
var ErrNotFound = errors.New("not found on GitHub")

// Limits on what is read from GitHub.
const (
	maxResponseBytes = 4 << 20
	maxTreeBytes     = 32 << 20
	// MaxBlobBytes is the largest file the App reads.
	MaxBlobBytes = 1 << 20
	// maxRepoPages bounds installation repository listing (100 per page).
	maxRepoPages = 20
	// tokenRefreshBefore renews an installation token this long before it
	// expires.
	tokenRefreshBefore = 5 * time.Minute
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	shaPattern  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)

// ValidName reports whether s can be a GitHub owner or repository name.
func ValidName(s string) bool {
	return namePattern.MatchString(s) && s != "." && s != ".."
}

// ValidSHA reports whether s is a full Git object ID.
func ValidSHA(s string) bool { return shaPattern.MatchString(s) }

// Permissions is the set of permissions an installation token is minted
// with, as GitHub names them.
type Permissions map[string]string

// ReadOnly is enough to list repositories, read files and look up
// collaborator permissions.
var ReadOnly = Permissions{"contents": "read", "metadata": "read"}

// Options configures a Client.
type Options struct {
	// APIURL is the REST API, normally https://api.github.com.
	APIURL string
	// AppID is the GitHub App's ID (or client ID), the JWT issuer.
	AppID string
	// PrivateKey is the App's private key, PEM (PKCS#1 or PKCS#8).
	PrivateKey []byte
	// Org is the organization the App is installed on.
	Org string
	// InstallationID skips looking the installation up by Org.
	InstallationID int64
	// HTTPClient defaults to one with a 15-second timeout.
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client is a GitHub App client for one installation.
type Client struct {
	apiURL string
	appID  string
	key    *rsa.PrivateKey
	org    string
	http   *http.Client
	now    func() time.Time

	mu             sync.Mutex
	installationID int64
	tokens         map[string]token
}

type token struct {
	value   string
	expires time.Time
}

// New returns a Client. It makes no network calls.
func New(opts Options) (*Client, error) {
	key, err := parsePrivateKey(opts.PrivateKey)
	if err != nil {
		return nil, err
	}
	if opts.AppID == "" {
		return nil, errors.New("failed to configure github app: an app id is required")
	}
	if opts.Org == "" && opts.InstallationID == 0 {
		return nil, errors.New("failed to configure github app: an org or installation id is required")
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	// GitHub redirects renamed repositories; follow nothing silently
	noRedirects := *hc
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		apiURL:         strings.TrimSuffix(opts.APIURL, "/"),
		appID:          opts.AppID,
		key:            key,
		org:            opts.Org,
		http:           &noRedirects,
		now:            now,
		installationID: opts.InstallationID,
		tokens:         map[string]token{},
	}, nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to read github app private key: not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to read github app private key: not an RSA key")
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to read github app private key: not an RSA key")
	}
	return k, nil
}

// appJWT signs a JWT that authenticates as the App, valid for 9 minutes
// (GitHub allows 10) and backdated a minute for clock skew.
func (c *Client) appJWT() (string, error) {
	now := c.now()
	claims := jwt.RegisteredClaims{
		Issuer:    c.appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(c.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign github app jwt: %w", err)
	}
	return signed, nil
}

// installation returns the installation ID, looking it up by org once.
func (c *Client) installation(ctx context.Context) (int64, error) {
	c.mu.Lock()
	id := c.installationID
	c.mu.Unlock()
	if id != 0 {
		return id, nil
	}
	appToken, err := c.appJWT()
	if err != nil {
		return 0, err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, c.apiURL+"/orgs/"+url.PathEscape(c.org)+"/installation", appToken, nil, maxResponseBytes, &out); err != nil {
		return 0, fmt.Errorf("failed to find the github app installation on %s: %w", c.org, err)
	}
	if out.ID == 0 {
		return 0, fmt.Errorf("failed to find the github app installation on %s", c.org)
	}
	c.mu.Lock()
	c.installationID = out.ID
	c.mu.Unlock()
	return out.ID, nil
}

// Token returns an installation token with exactly perms, minting one when
// none is cached or the cached one is about to expire.
func (c *Client) Token(ctx context.Context, perms Permissions) (string, error) {
	cacheKey := permissionsKey(perms)
	c.mu.Lock()
	if t, ok := c.tokens[cacheKey]; ok && c.now().Before(t.expires.Add(-tokenRefreshBefore)) {
		c.mu.Unlock()
		return t.value, nil
	}
	c.mu.Unlock()

	id, err := c.installation(ctx)
	if err != nil {
		return "", err
	}
	appToken, err := c.appJWT()
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	endpoint := c.apiURL + "/app/installations/" + strconv.FormatInt(id, 10) + "/access_tokens"
	if err := c.do(ctx, http.MethodPost, endpoint, appToken, map[string]any{"permissions": perms}, maxResponseBytes, &out); err != nil {
		return "", fmt.Errorf("failed to get a github app installation token: %w", err)
	}
	if out.Token == "" {
		return "", errors.New("failed to get a github app installation token: empty token")
	}
	c.mu.Lock()
	c.tokens[cacheKey] = token{value: out.Token, expires: out.ExpiresAt}
	c.mu.Unlock()
	return out.Token, nil
}

func permissionsKey(p Permissions) string {
	b, _ := json.Marshal(p) // map keys are sorted
	return string(b)
}

// Repository is a repository the App is installed on.
type Repository struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
}

type ghRepository struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (r ghRepository) repository() Repository {
	return Repository{
		Owner:         r.Owner.Login,
		Name:          r.Name,
		FullName:      r.FullName,
		Private:       r.Private,
		Archived:      r.Archived,
		DefaultBranch: r.DefaultBranch,
	}
}

// Repositories lists the repositories the installation can reach.
func (c *Client) Repositories(ctx context.Context) ([]Repository, error) {
	tok, err := c.Token(ctx, ReadOnly)
	if err != nil {
		return nil, err
	}
	var out []Repository
	for page := 1; page <= maxRepoPages; page++ {
		var resp struct {
			TotalCount   int            `json:"total_count"`
			Repositories []ghRepository `json:"repositories"`
		}
		endpoint := fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", c.apiURL, page)
		if err := c.do(ctx, http.MethodGet, endpoint, tok, nil, maxResponseBytes, &resp); err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}
		for _, r := range resp.Repositories {
			out = append(out, r.repository())
		}
		if len(resp.Repositories) < 100 || len(out) >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// Repository returns one repository.
func (c *Client) Repository(ctx context.Context, owner, repo string) (Repository, error) {
	tok, err := c.Token(ctx, ReadOnly)
	if err != nil {
		return Repository{}, err
	}
	var r ghRepository
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo), tok, nil, maxResponseBytes, &r); err != nil {
		return Repository{}, fmt.Errorf("failed to read repository %s/%s: %w", owner, repo, err)
	}
	return r.repository(), nil
}

// Permission is a user's effective permission on a repository.
type Permission struct {
	// UserID is who GitHub answered for; logins can change hands, IDs
	// cannot.
	UserID int64
	Read   bool
	Write  bool
}

// Permission returns a user's effective permission on a repository. A user
// who is not a collaborator has neither read nor write.
func (c *Client) Permission(ctx context.Context, owner, repo, login string) (Permission, error) {
	if !ValidName(login) {
		return Permission{}, fmt.Errorf("failed to check permission: invalid login %q", login)
	}
	tok, err := c.Token(ctx, ReadOnly)
	if err != nil {
		return Permission{}, err
	}
	var out struct {
		Permission string `json:"permission"`
		User       struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	err = c.do(ctx, http.MethodGet, c.repoURL(owner, repo, "collaborators", login, "permission"), tok, nil, maxResponseBytes, &out)
	if errors.Is(err, ErrNotFound) {
		return Permission{}, nil
	}
	if err != nil {
		return Permission{}, fmt.Errorf("failed to check %s's permission on %s/%s: %w", login, owner, repo, err)
	}
	// "permission" is the legacy summary: maintain reads as write, triage
	// as read
	p := Permission{UserID: out.User.ID}
	switch out.Permission {
	case "admin", "write":
		p.Read, p.Write = true, true
	case "read":
		p.Read = true
	}
	return p, nil
}

// BranchHead returns the commit a branch points at.
func (c *Client) BranchHead(ctx context.Context, owner, repo, branch string) (string, error) {
	tok, err := c.Token(ctx, ReadOnly)
	if err != nil {
		return "", err
	}
	var out struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	segments := append([]string{"git", "ref", "heads"}, strings.Split(branch, "/")...)
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo, segments...), tok, nil, maxResponseBytes, &out); err != nil {
		return "", fmt.Errorf("failed to read branch %s of %s/%s: %w", branch, owner, repo, err)
	}
	if out.Object.Type != "commit" || !ValidSHA(out.Object.SHA) {
		return "", fmt.Errorf("failed to read branch %s of %s/%s: it does not point at a commit", branch, owner, repo)
	}
	return out.Object.SHA, nil
}

// TreeEntry is a file in a tree.
type TreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

// Tree is a commit's whole file tree.
type Tree struct {
	Entries []TreeEntry
	// Truncated is set when GitHub returned only part of a very large tree.
	Truncated bool
}

// Tree returns the recursive tree of a commit.
func (c *Client) Tree(ctx context.Context, owner, repo, commit string) (Tree, error) {
	if !ValidSHA(commit) {
		return Tree{}, fmt.Errorf("failed to read tree: invalid commit %q", commit)
	}
	tok, err := c.Token(ctx, ReadOnly)
	if err != nil {
		return Tree{}, err
	}
	var out struct {
		Tree      []TreeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo, "git", "trees", commit)+"?recursive=1", tok, nil, maxTreeBytes, &out); err != nil {
		return Tree{}, fmt.Errorf("failed to read the tree of %s/%s at %s: %w", owner, repo, commit, err)
	}
	return Tree{Entries: out.Tree, Truncated: out.Truncated}, nil
}

// Blob returns a file's content by its object ID.
func (c *Client) Blob(ctx context.Context, owner, repo, sha string) ([]byte, error) {
	if !ValidSHA(sha) {
		return nil, fmt.Errorf("failed to read blob: invalid object id %q", sha)
	}
	tok, err := c.Token(ctx, ReadOnly)
	if err != nil {
		return nil, err
	}
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Size     int64  `json:"size"`
	}
	// base64 adds a third, plus line breaks
	limit := int64(MaxBlobBytes)*3/2 + 4096
	if err := c.do(ctx, http.MethodGet, c.repoURL(owner, repo, "git", "blobs", sha), tok, nil, limit, &out); err != nil {
		return nil, fmt.Errorf("failed to read blob %s of %s/%s: %w", sha, owner, repo, err)
	}
	if out.Size > MaxBlobBytes {
		return nil, fmt.Errorf("failed to read blob %s of %s/%s: larger than %d bytes", sha, owner, repo, MaxBlobBytes)
	}
	if out.Encoding != "base64" {
		return nil, fmt.Errorf("failed to read blob %s of %s/%s: unexpected encoding %q", sha, owner, repo, out.Encoding)
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob %s of %s/%s: %w", sha, owner, repo, err)
	}
	return data, nil
}

// repoURL builds /repos/{owner}/{repo}/... with every segment escaped.
func (c *Client) repoURL(owner, repo string, segments ...string) string {
	var b strings.Builder
	b.WriteString(c.apiURL + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo))
	for _, s := range segments {
		b.WriteString("/" + url.PathEscape(s))
	}
	return b.String()
}

// do sends a request and decodes a JSON response of at most limit bytes.
func (c *Client) do(ctx context.Context, method, endpoint, bearer string, in any, limit int64, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "k8s-sealed-secrets-sealer")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("response larger than %d bytes", limit)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("github returned %d: %s", resp.StatusCode, truncate(e.Message, 200))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to decode github response: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
