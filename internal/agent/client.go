package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// sessionRefreshBefore renews a session this long before it expires.
const sessionRefreshBefore = time.Minute

// maxResponseBytes bounds a control plane response. It is above the 6 MB a
// Lambda response can be, so no response the control plane can send is cut;
// a larger one fails as too large rather than as broken JSON.
const maxResponseBytes = 8 << 20

// Clock skew, measured against the control plane's Date header.
const (
	// minSkew ignores differences the Date header's whole seconds and the
	// network cause.
	minSkew = 2 * time.Second
	// warnSkew logs a clock this far off.
	warnSkew = time.Minute
)

// errUnauthorized marks a 401 from the control plane.
var errUnauthorized = errors.New("control plane rejected the agent's credentials")

// errNotFound marks a 404 from the control plane.
var errNotFound = errors.New("not found")

// statusError is a response the control plane refused.
type statusError struct {
	path string
	code int
	msg  string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("control plane %s returned %d: %s", e.path, e.code, e.msg)
}

// retryable reports whether a failed call may succeed if sent again: the
// control plane could not be reached, or answered that it is busy or
// failing. A refusal is final.
func retryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= 500
	}
	var ue *url.Error
	return errors.As(err, &ue)
}

// Client talks to the control plane's agent API. It logs in with its
// Identity and keeps the session token it gets back.
type Client struct {
	base      string
	http      *http.Client
	identity  Identity
	env       string
	userAgent string
	logger    *slog.Logger
	now       func() time.Time

	// login holds one login at a time
	login chan struct{}

	mu      sync.Mutex
	session string
	expires time.Time
	agentID string
	skew    time.Duration
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
	// longest commands poll. Redirects are never followed.
	HTTPClient *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
}

// NewClient returns a Client. It makes no network calls.
func NewClient(opts ClientOptions) *Client {
	hc := &http.Client{Timeout: 60 * time.Second}
	if opts.HTTPClient != nil {
		copied := *opts.HTTPClient
		hc = &copied
	}
	// a redirect would resend a signed login or an escrowed key to another
	// URL; the control plane never sends one
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
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
		logger:    logger,
		now:       now,
		login:     make(chan struct{}, 1),
	}
}

// AgentID is the ID the control plane knows this agent by, once logged in.
func (c *Client) AgentID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.agentID
}

// Now is the control plane's time as this agent best knows it: its own
// clock, corrected by how far it was off the control plane's in the last
// response. Commands and sessions expire in the control plane's time.
func (c *Client) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Add(c.skew)
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

// ensureSession returns a session that is not about to expire, logging in
// when there is none. Logins happen one at a time: the check-in and command
// loops start together, and two AWS logins signed in the same second are
// the same request, which the control plane accepts only once.
func (c *Client) ensureSession(ctx context.Context) (string, error) {
	if s, ok := c.currentSession(); ok {
		return s, nil
	}
	select {
	case c.login <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-c.login }()
	// another caller may have logged in meanwhile
	if s, ok := c.currentSession(); ok {
		return s, nil
	}

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

// currentSession returns the session unless it is about to expire, in the
// control plane's time, which set its expiry.
func (c *Client) currentSession() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == "" || !c.now().Add(c.skew).Before(c.expires.Add(-sessionRefreshBefore)) {
		return "", false
	}
	return c.session, true
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
	c.noteClock(ctx, resp.Header.Get("Date"))
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("failed to read control plane response from %s: %w", path, err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("failed to read control plane response from %s: larger than %d bytes", path, maxResponseBytes)
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
		return &statusError{path: path, code: resp.StatusCode, msg: e.Error}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to decode control plane response from %s: %w", path, err)
	}
	return nil
}

// noteClock measures how far this agent's clock is off the control plane's,
// from a response's Date header. Commands and sessions expire in the control
// plane's time, so a clock a few minutes fast would otherwise drop every
// command as expired.
func (c *Client) noteClock(ctx context.Context, date string) {
	served, err := http.ParseTime(date)
	if err != nil {
		return
	}
	skew := served.Sub(c.now())
	if skew.Abs() < minSkew {
		skew = 0
	}
	c.mu.Lock()
	was := c.skew
	c.skew = skew
	c.mu.Unlock()
	if skew.Abs() >= warnSkew && was.Abs() < warnSkew {
		c.logger.WarnContext(ctx, "this agent's clock is off the control plane's; using the control plane's time",
			"event", "agent.clock_skew", "skew", skew.Round(time.Second).String())
	}
}
