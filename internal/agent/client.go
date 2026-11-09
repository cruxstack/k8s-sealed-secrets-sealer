package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// maxTokenFileBytes bounds the projected token file.
const maxTokenFileBytes = 16 << 10

// sessionRefreshBefore renews a session this long before it expires.
const sessionRefreshBefore = time.Minute

// errUnauthorized marks a 401 from the control plane.
var errUnauthorized = errors.New("control plane rejected the agent's credentials")

// Client talks to the control plane's agent API. It logs in with the
// projected service-account token and keeps the session token it gets back.
type Client struct {
	base      string
	http      *http.Client
	tokenFile string
	userAgent string
	now       func() time.Time

	mu      sync.Mutex
	session string
	expires time.Time
	agentID string
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// BaseURL is the control plane's URL.
	BaseURL   string
	TokenFile string
	Version   string
	// HTTPClient defaults to one with a 30-second timeout.
	HTTPClient *http.Client
	Now        func() time.Time
}

// NewClient returns a Client. It makes no network calls.
func NewClient(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		base:      strings.TrimSuffix(opts.BaseURL, "/"),
		http:      hc,
		tokenFile: opts.TokenFile,
		userAgent: "k8s-sealed-secrets-sealer-agent/" + opts.Version,
		now:       now,
	}
}

// AgentID is the ID the control plane knows this agent by, once logged in.
func (c *Client) AgentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agentID
}

// CheckIn reports the agent's state, logging in first when needed and once
// more if the session was rejected.
func (c *Client) CheckIn(ctx context.Context, in protocol.CheckIn) (*protocol.CheckInResponse, error) {
	var out protocol.CheckInResponse
	for attempt := 0; ; attempt++ {
		session, err := c.ensureSession(ctx)
		if err != nil {
			return nil, err
		}
		err = c.post(ctx, "/agent/v1/checkin", session, in, &out)
		if errors.Is(err, errUnauthorized) && attempt == 0 {
			c.dropSession(session)
			continue
		}
		if err != nil {
			return nil, err
		}
		return &out, nil
	}
}

func (c *Client) ensureSession(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.session != "" && c.now().Before(c.expires.Add(-sessionRefreshBefore)) {
		s := c.session
		c.mu.Unlock()
		return s, nil
	}
	c.mu.Unlock()

	token, err := readTokenFile(c.tokenFile)
	if err != nil {
		return "", err
	}
	var resp protocol.SessionResponse
	if err := c.post(ctx, "/agent/v1/session", "", protocol.SessionRequest{Method: protocol.MethodK8sOIDC, Token: token}, &resp); err != nil {
		return "", fmt.Errorf("failed to log in to the control plane: %w", err)
	}
	if resp.Token == "" {
		return "", errors.New("failed to log in to the control plane: empty session")
	}
	c.mu.Lock()
	c.session, c.expires, c.agentID = resp.Token, resp.ExpiresAt, resp.AgentID
	c.mu.Unlock()
	return resp.Token, nil
}

func (c *Client) dropSession(session string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == session {
		c.session = ""
	}
}

func (c *Client) post(ctx context.Context, path, session string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("failed to encode request to %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to build request to %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if session != "" {
		req.Header.Set("Authorization", "Bearer "+session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call control plane %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read control plane response from %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		var e protocol.Error
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("control plane %s returned %d: %s", path, resp.StatusCode, e.Error)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to decode control plane response from %s: %w", path, err)
	}
	return nil
}

// readTokenFile reads the projected token on every login: the kubelet
// rotates it, so it must not be cached.
func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open identity token %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read identity token %s: %w", path, err)
	}
	if len(data) > maxTokenFileBytes {
		return "", fmt.Errorf("failed to read identity token %s: file is too large", path)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("failed to read identity token %s: file is empty", path)
	}
	return token, nil
}
