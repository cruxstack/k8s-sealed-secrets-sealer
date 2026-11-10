package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// sessionRefreshBefore renews a session this long before it expires.
const sessionRefreshBefore = time.Minute

// errUnauthorized marks a 401 from the control plane.
var errUnauthorized = errors.New("control plane rejected the agent's credentials")

// errNotFound marks a 404 from the control plane.
var errNotFound = errors.New("not found")

// Client talks to the control plane's agent API. It logs in with its
// Identity and keeps the session token it gets back.
type Client struct {
	base      string
	http      *http.Client
	identity  Identity
	env       string
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
	BaseURL  string
	Identity Identity
	// Env is the env this agent belongs to. A control plane serving another
	// env is refused at login.
	Env     string
	Version string
	// HTTPClient defaults to one with a 60-second timeout, above the
	// longest commands poll.
	HTTPClient *http.Client
	Now        func() time.Time
}

// NewClient returns a Client. It makes no network calls.
func NewClient(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		base:      strings.TrimSuffix(opts.BaseURL, "/"),
		http:      hc,
		identity:  opts.Identity,
		env:       opts.Env,
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

// CheckIn reports the agent's state.
func (c *Client) CheckIn(ctx context.Context, in protocol.CheckIn) (*protocol.CheckInResponse, error) {
	var out protocol.CheckInResponse
	if err := c.call(ctx, http.MethodPost, "/agent/v1/checkin", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Commands leases the agent's queued commands, waiting up to wait for one.
func (c *Client) Commands(ctx context.Context, wait time.Duration) ([]protocol.Command, error) {
	var out protocol.CommandsResponse
	path := fmt.Sprintf("/agent/v1/commands?wait=%d", int(wait/time.Second))
	if err := c.call(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}

// Result reports a command's outcome.
func (c *Client) Result(ctx context.Context, id string, res protocol.CommandResult) error {
	var out map[string]string
	return c.call(ctx, http.MethodPost, "/agent/v1/commands/"+url.PathEscape(id)+"/result", res, &out)
}

// PutEscrow uploads an escrowed key.
func (c *Client) PutEscrow(ctx context.Context, fingerprint string, in protocol.EscrowUpload) error {
	var out map[string]bool
	return c.call(ctx, http.MethodPut, "/agent/v1/escrow/"+protocol.FingerprintPath(fingerprint), in, &out)
}

// GetEscrow downloads an escrowed key.
func (c *Client) GetEscrow(ctx context.Context, fingerprint string) (protocol.EscrowRecord, error) {
	var out protocol.EscrowRecord
	if err := c.call(ctx, http.MethodGet, "/agent/v1/escrow/"+protocol.FingerprintPath(fingerprint), nil, &out); err != nil {
		return protocol.EscrowRecord{}, err
	}
	return out, nil
}

// call sends an authenticated request, logging in first when needed and
// once more if the session was rejected.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	for attempt := 0; ; attempt++ {
		session, err := c.ensureSession(ctx)
		if err != nil {
			return err
		}
		err = c.do(ctx, method, path, session, in, out)
		if errors.Is(err, errUnauthorized) && attempt == 0 {
			c.dropSession(session)
			continue
		}
		return err
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

	login, err := c.identity.LoginRequest(ctx)
	if err != nil {
		return "", err
	}
	var resp protocol.SessionResponse
	if err := c.do(ctx, http.MethodPost, "/agent/v1/session", "", login, &resp); err != nil {
		return "", fmt.Errorf("failed to log in to the control plane: %w", err)
	}
	if resp.Token == "" {
		return "", errors.New("failed to log in to the control plane: empty session")
	}
	if c.env != "" && resp.Env != c.env {
		return "", fmt.Errorf("failed to log in to the control plane: it serves env %q, this agent belongs to %q", resp.Env, c.env)
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

func (c *Client) do(ctx context.Context, method, path, session string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("failed to encode request to %s: %w", path, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("failed to build request to %s: %w", path, err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", c.userAgent)
	// a control plane serving several envs sends the request to this one
	if c.env != "" {
		req.Header.Set(protocol.EnvHeader, c.env)
	}
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
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return errUnauthorized
	case http.StatusNotFound:
		return fmt.Errorf("control plane %s: %w", path, errNotFound)
	default:
		var e protocol.Error
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("control plane %s returned %d: %s", path, resp.StatusCode, e.Error)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to decode control plane response from %s: %w", path, err)
	}
	return nil
}
