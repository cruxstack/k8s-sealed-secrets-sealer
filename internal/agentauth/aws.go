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

	"golang.org/x/time/rate"

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

// Default limit on calls to STS, per env and process. A login that passes
// every local check costs one STS call, and anyone can make one, so the calls
// are limited. The burst lets an env's whole fleet, up to 100 agents, log in
// at once after a restart. The rate is far above steady use: each agent logs
// in every 14 minutes (15-minute sessions, renewed a minute early), so 100
// agents need about 0.12 calls a second.
const (
	DefaultSTSCallsPerSecond = 1
	DefaultSTSBurst          = 100
)

// ErrTooManyLogins is returned, instead of calling STS, while logins exceed
// the STS call limit.
var ErrTooManyLogins = errors.New("too many logins")

// NewSTSLimiter returns a limiter with the default STS call limit.
func NewSTSLimiter() *rate.Limiter {
	return rate.NewLimiter(DefaultSTSCallsPerSecond, DefaultSTSBurst)
}

// headers an agent may send with its signed request; anything else is
// refused rather than forwarded
var allowedSTSHeaders = []string{
	"Authorization",
	"X-Amz-Date",
	"X-Amz-Security-Token",
	"Content-Type",
	http.CanonicalHeaderKey(protocol.AWSAudienceHeader),
}

// knownSTSRegions are the regions whose public STS endpoints agents may sign
// for unless AllowedHosts replaces them. An agent in a region missing here,
// or behind a VPC endpoint, needs AllowedHosts.
var knownSTSRegions = []string{
	"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2",
	"ap-northeast-3", "ap-south-1", "ap-south-2", "ap-southeast-1",
	"ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5",
	"ap-southeast-6", "ap-southeast-7", "ca-central-1", "ca-west-1",
	"eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "il-central-1", "me-central-1",
	"me-south-1", "mx-central-1", "sa-east-1", "us-east-1", "us-east-2",
	"us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2",
}

var knownChinaSTSRegions = []string{"cn-north-1", "cn-northwest-1"}

var (
	sigV4Auth      = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/,\s]+)/([0-9]{8})/([a-z0-9-]+)/sts/aws4_request, ?SignedHeaders=([a-z0-9;-]+), ?Signature=([0-9a-f]{64})$`)
	assumedRoleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):sts::([0-9]{12}):assumed-role/([\w+=,.@-]{1,64})/[\w+=,.@-]+$`)
)

// ReplayStore remembers one-time keys.
type ReplayStore interface {
	PutReplayIfAbsent(ctx context.Context, key string, expires time.Time) (bool, error)
}

// AWSVerifier verifies agents that log in with a signed
// sts:GetCallerIdentity request (the scheme Vault's AWS auth method uses).
type AWSVerifier struct {
	reg      *registry.Registry
	audience string
	// endpoints maps each allowed STS host to the URL requests go to. The
	// URL comes from this table, built from trusted values, never from the
	// agent's request.
	endpoints map[string]string
	http      *http.Client
	replays   ReplayStore
	stsLimit  *rate.Limiter
	now       func() time.Time
}

// AWSOptions configures an AWSVerifier.
type AWSOptions struct {
	Registry *registry.Registry
	// Audience must equal the signed audience header: this control plane's
	// URL.
	Audience string
	// AllowedHosts lists the only STS hosts requests may target. Empty allows
	// sts.amazonaws.com and the regional hosts of known AWS regions.
	AllowedHosts []string
	// HTTPClient calls STS. It must not follow redirects; the default does
	// not.
	HTTPClient *http.Client
	Replays    ReplayStore
	// STSLimiter limits calls to STS. Pass the same one to every verifier
	// built for an env, so a registry change does not reset it. Nil uses
	// NewSTSLimiter.
	STSLimiter *rate.Limiter
	Now        func() time.Time
}

// NewAWSVerifier returns an AWSVerifier. It makes no network calls.
func NewAWSVerifier(opts AWSOptions) (*AWSVerifier, error) {
	if opts.Audience == "" || opts.Replays == nil || opts.Registry == nil {
		return nil, errors.New("failed to create aws verifier: registry, audience and replay store are required")
	}
	endpoints := map[string]string{}
	if len(opts.AllowedHosts) > 0 {
		for _, h := range opts.AllowedHosts {
			endpoints[h] = "https://" + h + "/"
		}
	} else {
		endpoints["sts.amazonaws.com"] = "https://sts.amazonaws.com/"
		for _, r := range knownSTSRegions {
			h := "sts." + r + ".amazonaws.com"
			endpoints[h] = "https://" + h + "/"
		}
		for _, r := range knownChinaSTSRegions {
			h := "sts." + r + ".amazonaws.com.cn"
			endpoints[h] = "https://" + h + "/"
		}
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
	limit := opts.STSLimiter
	if limit == nil {
		limit = NewSTSLimiter()
	}
	return &AWSVerifier{
		reg:       opts.Registry,
		audience:  opts.Audience,
		endpoints: endpoints,
		http:      &noRedirects,
		replays:   opts.Replays,
		stsLimit:  limit,
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
	// the headers checked here are the ones sent to STS, and the signature
	// remembered below is the one STS verified
	headers, err := canonicalHeaders(sr.Headers)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	signature, signedAt, err := v.checkSignatureShape(headers)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	if !v.stsLimit.AllowN(v.now(), 1) {
		return nil, fmt.Errorf("%w: sts call limit reached", ErrTooManyLogins)
	}

	identity, err := v.callSTS(ctx, target, headers)
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
// allowed STS host, so the control plane can't be made to call anything
// else. It returns the URL to call, taken from the endpoint table.
func (v *AWSVerifier) checkTarget(sr *protocol.SignedRequest) (string, error) {
	u, err := url.Parse(sr.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("sts url %q is not allowed", sr.URL)
	}
	endpoint, ok := v.endpoints[u.Host]
	if !ok {
		return "", fmt.Errorf("sts host %q is not allowed", u.Host)
	}
	if sr.Body != protocol.AWSGetCallerIdentityBody {
		return "", errors.New("signed request is not sts:GetCallerIdentity")
	}
	return endpoint, nil
}

// canonicalHeaders returns the agent's headers as they are sent to STS:
// only known headers, each given once. Names differing only in case are the
// same header, and with two of them the checks and STS could each read a
// different one.
func canonicalHeaders(in map[string]string) (http.Header, error) {
	h := make(http.Header, len(in))
	for name, value := range in {
		key := http.CanonicalHeaderKey(name)
		if !slices.Contains(allowedSTSHeaders, key) {
			return nil, fmt.Errorf("header %q is not allowed", name)
		}
		if len(value) > maxHeaderValue {
			return nil, fmt.Errorf("header %q is too large", name)
		}
		if _, dup := h[key]; dup {
			return nil, fmt.Errorf("header %q is given more than once", key)
		}
		h[key] = []string{value}
	}
	return h, nil
}

// checkSignatureShape checks the headers before anything is sent to STS: the
// audience header present, ours and signed, and a fresh signature date. STS
// itself verifies the signature.
func (v *AWSVerifier) checkSignatureShape(h http.Header) (string, time.Time, error) {
	if h.Get(protocol.AWSAudienceHeader) != v.audience {
		return "", time.Time{}, errors.New("signed request is for another audience")
	}
	m := sigV4Auth.FindStringSubmatch(h.Get("Authorization"))
	if m == nil {
		return "", time.Time{}, errors.New("authorization is not a sigv4 signature for sts")
	}
	signed := strings.Split(m[4], ";")
	for _, required := range []string{"host", "x-amz-date", strings.ToLower(protocol.AWSAudienceHeader)} {
		if !slices.Contains(signed, required) {
			return "", time.Time{}, fmt.Errorf("header %q is not signed", required)
		}
	}
	signedAt, err := time.Parse("20060102T150405Z", h.Get("X-Amz-Date"))
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

func (v *AWSVerifier) callSTS(ctx context.Context, endpoint string, headers http.Header) (*callerIdentity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(protocol.AWSGetCallerIdentityBody))
	if err != nil {
		return nil, fmt.Errorf("failed to build sts request: %w", err)
	}
	req.Header = headers.Clone()
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
