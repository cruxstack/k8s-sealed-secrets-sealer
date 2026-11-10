package userauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHub is the OAuth side of GitHub: the code exchange and the calls made
// with the user's token.
type GitHub struct {
	clientID     string
	clientSecret string
	tokenURL     string
	apiURL       string
	http         *http.Client
}

// GitHubOptions configures a GitHub client.
type GitHubOptions struct {
	ClientID     string
	ClientSecret string
	// TokenURL is the OAuth token endpoint, normally
	// https://github.com/login/oauth/access_token.
	TokenURL string
	// APIURL is the REST API, normally https://api.github.com.
	APIURL string
	// HTTPClient defaults to one with a 10-second timeout. Redirects are
	// never followed either way.
	HTTPClient *http.Client
}

// NewGitHub returns a GitHub client. It makes no network calls.
func NewGitHub(opts GitHubOptions) *GitHub {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// The org membership endpoint answers a non-member caller with a
	// redirect to the public members list; following it would turn "no"
	// into a different question.
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &GitHub{
		clientID:     opts.ClientID,
		clientSecret: opts.ClientSecret,
		tokenURL:     opts.TokenURL,
		apiURL:       strings.TrimSuffix(opts.APIURL, "/"),
		http:         &noRedirects,
	}
}

// Exchange trades an authorization code for a user access token.
func (g *GitHub) Exchange(ctx context.Context, code, redirectURI string) (string, error) {
	form := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	status, err := g.do(req, &out)
	switch {
	case err != nil:
		return "", err
	case status != http.StatusOK:
		return "", fmt.Errorf("failed to exchange oauth code: github returned %d", status)
	case out.Error != "":
		return "", fmt.Errorf("failed to exchange oauth code: %s", out.Error)
	case out.AccessToken == "":
		return "", errors.New("failed to exchange oauth code: empty access token")
	}
	return out.AccessToken, nil
}

// User returns the user the token belongs to.
func (g *GitHub) User(ctx context.Context, token string) (*User, error) {
	var u User
	status, err := g.get(ctx, token, "/user", &u)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || u.ID == 0 || u.Login == "" {
		return nil, fmt.Errorf("failed to get github user: status %d", status)
	}
	return &u, nil
}

// OrgMember reports whether login is a member of org.
func (g *GitHub) OrgMember(ctx context.Context, token, org, login string) (bool, error) {
	status, err := g.get(ctx, token, "/orgs/"+url.PathEscape(org)+"/members/"+url.PathEscape(login), nil)
	if err != nil {
		return false, err
	}
	return status == http.StatusNoContent, nil
}

// TeamMember reports whether login is an active member of org's team.
func (g *GitHub) TeamMember(ctx context.Context, token, org, team, login string) (bool, error) {
	var m struct {
		State string `json:"state"`
	}
	status, err := g.get(ctx, token, "/orgs/"+url.PathEscape(org)+"/teams/"+url.PathEscape(team)+"/memberships/"+url.PathEscape(login), &m)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK && m.State == "active", nil
}

// get calls the API with the user's token. A 404 is an answer, not an
// error; out is decoded only for 200.
func (g *GitHub) get(ctx context.Context, token, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL+path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to build github request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return g.do(req, out)
}

func (g *GitHub) do(req *http.Request, out any) (int, error) {
	resp, err := g.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to call github %s: %w", req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("failed to read github response from %s: %w", req.URL.Path, err)
	}
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, out); err != nil {
			return 0, fmt.Errorf("failed to decode github response from %s: %w", req.URL.Path, err)
		}
	}
	return resp.StatusCode, nil
}
