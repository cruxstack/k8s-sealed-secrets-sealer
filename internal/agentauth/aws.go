package agentauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
)

// SigV4 limits. STS accepts a signature for 15 minutes either side of its
// date, so a used signature is remembered a little longer than that.
const (
	maxSignatureSkew = 15 * time.Minute
	replayTTL        = 2*maxSignatureSkew + 5*time.Minute
	maxHeaderValue   = 8 << 10
	maxSTSResponse   = 64 << 10
)

// headers an agent may send with its signed request; anything else is
// refused rather than forwarded
var allowedSTSHeaders = []string{
	"Authorization",
	"X-Amz-Date",
	"X-Amz-Security-Token",
	"Content-Type",
	http.CanonicalHeaderKey(protocol.AWSAudienceHeader),
}

var (
	regionalSTSHost = regexp.MustCompile(`^sts\.[a-z]{2}(-gov)?-[a-z]+-[0-9]+\.amazonaws\.com$`)
	sigV4Auth       = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/,\s]+)/([0-9]{8})/([a-z0-9-]+)/sts/aws4_request, ?SignedHeaders=([a-z0-9;-]+), ?Signature=([0-9a-f]{64})$`)
	assumedRoleARN  = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):sts::([0-9]{12}):assumed-role/([\w+=,.@-]{1,64})/[\w+=,.@-]+$`)
)

// ReplayStore remembers one-time keys.
type ReplayStore interface {
	PutReplayIfAbsent(ctx context.Context, key string, expires time.Time) (bool, error)
}

// AWSVerifier verifies agents that log in with a signed
// sts:GetCallerIdentity request (the scheme Vault's AWS auth method uses).
type AWSVerifier struct {
	reg       *registry.Registry
	audience  string
	allowHost func(string) bool
	http      *http.Client
	replays   ReplayStore
	now       func() time.Time
}

// AWSOptions configures an AWSVerifier.
type AWSOptions struct {
	Registry *registry.Registry
	// Audience must equal the signed audience header: this control plane's
	// URL.
	Audience string
	// AllowedHosts lists the only STS hosts requests may target. Empty allows
	// sts.amazonaws.com and the regional sts.<region>.amazonaws.com hosts.
	AllowedHosts []string
	// HTTPClient calls STS. It must not follow redirects; the default does
	// not.
	HTTPClient *http.Client
	Replays    ReplayStore
	Now        func() time.Time
}

// NewAWSVerifier returns an AWSVerifier. It makes no network calls.
func NewAWSVerifier(opts AWSOptions) (*AWSVerifier, error) {
	if opts.Audience == "" || opts.Replays == nil || opts.Registry == nil {
		return nil, errors.New("failed to create aws verifier: registry, audience and replay store are required")
	}
	allow := func(host string) bool { return host == "sts.amazonaws.com" || regionalSTSHost.MatchString(host) }
	if len(opts.AllowedHosts) > 0 {
		hosts := slices.Clone(opts.AllowedHosts)
		allow = func(host string) bool { return slices.Contains(hosts, host) }
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// never follow a redirect away from the allowed host
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &AWSVerifier{
		reg:       opts.Registry,
		audience:  opts.Audience,
		allowHost: allow,
		http:      &noRedirects,
		replays:   opts.Replays,
		now:       now,
	}, nil
}

// VerifyLogin checks a signed request, has STS confirm it, and returns the
// agent registered for the role STS reports. Each signed request logs in at
// most once.
func (v *AWSVerifier) VerifyLogin(ctx context.Context, req protocol.SessionRequest) (*registry.Agent, error) {
	sr := req.AWS
	if sr == nil || req.Token != "" {
		return nil, fmt.Errorf("%w: aws-sts login needs a signed request and nothing else", ErrUnauthorized)
	}
	target, err := v.checkTarget(sr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	signature, signedAt, err := v.checkSignatureShape(sr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}

	identity, err := v.callSTS(ctx, target, sr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	m := assumedRoleARN.FindStringSubmatch(identity.Arn)
	if m == nil {
		return nil, fmt.Errorf("%w: caller %q is not an assumed role", ErrUnauthorized, identity.Arn)
	}
	agent, ok := v.reg.AgentByAWSRole(registry.AWSRole{Partition: m[1], Account: m[2], Name: m[3]})
	if !ok {
		return nil, fmt.Errorf("%w: role %q in account %s is not a registered agent", ErrUnauthorized, m[3], m[2])
	}
	if id := agent.Identity.AWS.RoleID; id != "" && !strings.HasPrefix(identity.UserID, id+":") {
		return nil, fmt.Errorf("%w: role %q has a different unique id than registered", ErrUnauthorized, m[3])
	}

	// only after STS accepted it, so forged requests cannot fill the store
	sum := sha256.Sum256([]byte(signature))
	fresh, err := v.replays.PutReplayIfAbsent(ctx, "aws-sts:"+hex.EncodeToString(sum[:]), signedAt.Add(replayTTL))
	if err != nil {
		return nil, fmt.Errorf("failed to record login: %w", err)
	}
	if !fresh {
		return nil, fmt.Errorf("%w: signed request was already used", ErrUnauthorized)
	}
	return agent, nil
}

// checkTarget allows only a POST of the exact GetCallerIdentity call to an
// allowed STS host, so the control plane can't be made to call anything else.
func (v *AWSVerifier) checkTarget(sr *protocol.SignedRequest) (*url.URL, error) {
	u, err := url.Parse(sr.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || !v.allowHost(u.Host) {
		return nil, fmt.Errorf("sts url %q is not allowed", sr.URL)
	}
	if sr.Body != protocol.AWSGetCallerIdentityBody {
		return nil, errors.New("signed request is not sts:GetCallerIdentity")
	}
	return u, nil
}

// checkSignatureShape checks the headers before anything is sent to STS: only
// known headers, the audience header present, ours and signed, and a fresh
// signature date. STS itself verifies the signature.
func (v *AWSVerifier) checkSignatureShape(sr *protocol.SignedRequest) (string, time.Time, error) {
	for name, value := range sr.Headers {
		if !slices.Contains(allowedSTSHeaders, http.CanonicalHeaderKey(name)) {
			return "", time.Time{}, fmt.Errorf("header %q is not allowed", name)
		}
		if len(value) > maxHeaderValue {
			return "", time.Time{}, fmt.Errorf("header %q is too large", name)
		}
	}
	get := func(name string) string {
		for k, v := range sr.Headers {
			if strings.EqualFold(k, name) {
				return v
			}
		}
		return ""
	}
	if get(protocol.AWSAudienceHeader) != v.audience {
		return "", time.Time{}, errors.New("signed request is for another audience")
	}
	m := sigV4Auth.FindStringSubmatch(get("Authorization"))
	if m == nil {
		return "", time.Time{}, errors.New("authorization is not a sigv4 signature for sts")
	}
	signed := strings.Split(m[4], ";")
	for _, required := range []string{"host", "x-amz-date", strings.ToLower(protocol.AWSAudienceHeader)} {
		if !slices.Contains(signed, required) {
			return "", time.Time{}, fmt.Errorf("header %q is not signed", required)
		}
	}
	signedAt, err := time.Parse("20060102T150405Z", get("X-Amz-Date"))
	if err != nil {
		return "", time.Time{}, errors.New("x-amz-date is missing or malformed")
	}
	if skew := v.now().Sub(signedAt); skew > maxSignatureSkew || skew < -maxSignatureSkew {
		return "", time.Time{}, fmt.Errorf("signature date is %s away from now", skew.Round(time.Second))
	}
	return m[5], signedAt, nil
}

type callerIdentity struct {
	Arn    string `xml:"GetCallerIdentityResult>Arn"`
	UserID string `xml:"GetCallerIdentityResult>UserId"`
}

func (v *AWSVerifier) callSTS(ctx context.Context, target *url.URL, sr *protocol.SignedRequest) (*callerIdentity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(sr.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to build sts request: %w", err)
	}
	for name, value := range sr.Headers {
		req.Header.Set(name, value)
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call sts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSTSResponse))
	if err != nil {
		return nil, fmt.Errorf("failed to read sts response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sts rejected the signed request (%d)", resp.StatusCode)
	}
	var id callerIdentity
	if err := xml.Unmarshal(data, &id); err != nil || id.Arn == "" {
		return nil, errors.New("failed to parse sts response")
	}
	return &id, nil
}
