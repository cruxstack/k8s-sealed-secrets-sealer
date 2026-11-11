package agentauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/time/rate"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agent"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

const (
	awsAudience = "https://sealer.dev.example.com"
	roleARN     = "arn:aws:sts::123456789012:assumed-role/use1-blue/eks-blue-agent-abc"
	roleUserID  = "AROA1234567890ABCDEFG:eks-blue-agent-abc"
)

var agentCreds = aws.Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "agent-secret", SessionToken: "agent-session-token"}

var scopeRegion = regexp.MustCompile(`Credential=[^/]+/[0-9]{8}/([a-z0-9-]+)/sts/aws4_request`)
var signedHeaders = regexp.MustCompile(`SignedHeaders=([a-z0-9;-]+)`)

// fakeSTS answers sts:GetCallerIdentity like STS does: it re-signs the
// request it receives with the agent's credentials and rejects it unless the
// signatures match.
type fakeSTS struct {
	creds  aws.Credentials
	arn    string
	userID string
	calls  atomic.Int32
}

func (f *fakeSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	body, _ := io.ReadAll(r.Body)
	auth := r.Header.Get("Authorization")
	date, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	region := scopeRegion.FindStringSubmatch(auth)
	signed := signedHeaders.FindStringSubmatch(auth)
	if err != nil || region == nil || signed == nil {
		http.Error(w, "malformed", http.StatusBadRequest)
		return
	}
	clone, _ := http.NewRequest(http.MethodPost, "https://"+r.Host+r.URL.Path, bytes.NewReader(body))
	for _, h := range strings.Split(signed[1], ";") {
		if h != "host" && h != "content-length" {
			clone.Header.Set(h, r.Header.Get(h))
		}
	}
	sum := sha256.Sum256(body)
	_ = v4.NewSigner().SignHTTP(context.Background(), f.creds, clone, hex.EncodeToString(sum[:]), "sts", region[1], date)
	if clone.Header.Get("Authorization") != auth || string(body) != protocol.AWSGetCallerIdentityBody {
		http.Error(w, "<Error><Code>SignatureDoesNotMatch</Code></Error>", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>%s</Arn><UserId>%s</UserId><Account>123456789012</Account></GetCallerIdentityResult>
  <ResponseMetadata><RequestId>test</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`, f.arn, f.userID)
}

type awsHarness struct {
	sts      *fakeSTS
	srv      *httptest.Server
	verifier *AWSVerifier
}

func newAWSHarness(t *testing.T, roleID string) *awsHarness {
	t.Helper()
	return newLimitedAWSHarness(t, roleID, nil)
}

func newLimitedAWSHarness(t *testing.T, roleID string, limit *STSLimiter) *awsHarness {
	t.Helper()
	sts := &fakeSTS{creds: agentCreds, arn: roleARN, userID: roleUserID}
	srv := httptest.NewTLSServer(sts)
	t.Cleanup(srv.Close)

	identity := `{roleArn: "arn:aws:iam::123456789012:role/sealer/use1-blue"}`
	if roleID != "" {
		identity = `{roleArn: "arn:aws:iam::123456789012:role/sealer/use1-blue", roleId: ` + roleID + `}`
	}
	reg, err := registry.Parse([]byte(`
agents:
  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal], identity: {aws: `+identity+`}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewAWSVerifier(AWSOptions{
		Registry:     reg,
		Audience:     awsAudience,
		AllowedHosts: []string{srv.Listener.Addr().String()},
		HTTPClient:   srv.Client(),
		Replays:      store.NewMemory(),
		STSLimiter:   limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &awsHarness{sts: sts, srv: srv, verifier: v}
}

// signed returns a login request signed by the agent's real AWS identity.
func (h *awsHarness) signed(t *testing.T, audience string, now time.Time, creds aws.Credentials) protocol.SessionRequest {
	t.Helper()
	id, err := agent.NewAWSIdentity(agent.AWSIdentityOptions{
		Credentials: credentials.StaticCredentialsProvider{Value: creds},
		Region:      "us-east-1",
		Audience:    audience,
		Endpoint:    h.srv.URL + "/",
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := id.LoginRequest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestAWSVerifier_AcceptsRegisteredRoleOnce(t *testing.T) {
	h := newAWSHarness(t, "AROA1234567890ABCDEFG")
	req := h.signed(t, awsAudience, time.Now(), agentCreds)

	agent, err := h.verifier.VerifyLogin(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyLogin: %v", err)
	}
	if agent.ID != "use1-blue" {
		t.Errorf("agent = %q", agent.ID)
	}
	if _, err := h.verifier.VerifyLogin(context.Background(), req); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replayed login: %v", err)
	}
}

func TestAWSVerifier_AcceptsHeaderNamesInAnyCase(t *testing.T) {
	h := newAWSHarness(t, "")
	req := h.signed(t, awsAudience, time.Now(), agentCreds)
	lower := map[string]string{}
	for k, v := range req.AWS.Headers {
		lower[strings.ToLower(k)] = v
	}
	req.AWS.Headers = lower
	if _, err := h.verifier.VerifyLogin(context.Background(), req); err != nil {
		t.Fatalf("VerifyLogin with lower-case header names: %v", err)
	}
}

// A header given twice, in two cases, could be checked in one spelling and
// sent to STS in the other. Map order is random, so each attack is tried
// many times; before headers were made canonical, some attempts got in.
func TestAWSVerifier_RefusesHeadersGivenTwice(t *testing.T) {
	h := newAWSHarness(t, "")
	ctx := context.Background()

	// a used login, replayed with a second authorization header carrying a
	// new, random signature: the replay record must not be dodged
	used := h.signed(t, awsAudience, time.Now(), agentCreds)
	if _, err := h.verifier.VerifyLogin(ctx, used); err != nil {
		t.Fatalf("first login: %v", err)
	}
	auth := used.AWS.Headers["Authorization"]
	prefix := auth[:strings.LastIndex(auth, "Signature=")+len("Signature=")]
	for i := range 200 {
		req := copyLogin(used)
		sig := sha256.Sum256(fmt.Appendf(nil, "fake-%d", i))
		req.AWS.Headers["authorization"] = prefix + hex.EncodeToString(sig[:])
		if _, err := h.verifier.VerifyLogin(ctx, req); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("replay with a second authorization header = %v, want ErrUnauthorized", err)
		}
	}

	// a login signed for another deployment, with an unsigned audience
	// header naming this one
	for i := range 100 {
		req := h.signed(t, "https://sealer.other.example.com", time.Now().Add(-time.Duration(i)*time.Second), agentCreds)
		req.AWS.Headers[strings.ToLower(protocol.AWSAudienceHeader)] = awsAudience
		if _, err := h.verifier.VerifyLogin(ctx, req); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("foreign login with a second audience header = %v, want ErrUnauthorized", err)
		}
	}
	if n := h.sts.calls.Load(); n != 1 {
		t.Errorf("STS was called %d times, want once, for the first login", n)
	}
}

func copyLogin(req protocol.SessionRequest) protocol.SessionRequest {
	signed := *req.AWS
	signed.Headers = map[string]string{}
	for k, v := range req.AWS.Headers {
		signed.Headers[k] = v
	}
	req.AWS = &signed
	return req
}

func TestAWSVerifier_LimitsSTSCalls(t *testing.T) {
	// two calls, and none more until tokens are added
	h := newLimitedAWSHarness(t, "", newSTSLimiter(rate.NewLimiter(0, 2), time.Hour, 10))
	ctx := context.Background()
	for i := range 2 {
		if _, err := h.verifier.VerifyLogin(ctx, h.signed(t, awsAudience, time.Now().Add(-time.Duration(i)*time.Second), agentCreds)); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
	// a request refused before STS uses no call
	bad := h.signed(t, "https://sealer.other.example.com", time.Now(), agentCreds)
	if _, err := h.verifier.VerifyLogin(ctx, bad); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign login = %v", err)
	}
	if _, err := h.verifier.VerifyLogin(ctx, h.signed(t, awsAudience, time.Now().Add(-5*time.Second), agentCreds)); !errors.Is(err, ErrTooManyLogins) {
		t.Fatalf("login past the limit = %v, want ErrTooManyLogins", err)
	}
	if n := h.sts.calls.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2", n)
	}
}

// forged builds a login that passes every local check with no AWS
// credentials: the public audience, a fresh date and a random signature.
func forged(t *testing.T, h *awsHarness, now time.Time) protocol.SessionRequest {
	t.Helper()
	sig := make([]byte, 32)
	_, _ = rand.Read(sig)
	return protocol.SessionRequest{
		Method: protocol.MethodAWSSTS,
		AWS: &protocol.SignedRequest{
			URL:  "https://" + h.srv.Listener.Addr().String() + "/",
			Body: protocol.AWSGetCallerIdentityBody,
			Headers: map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAFORGED/" + now.UTC().Format("20060102") +
					"/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;" +
					"x-k8s-sealed-secrets-sealer-audience, Signature=" + hex.EncodeToString(sig),
				"X-Amz-Date":               now.UTC().Format("20060102T150405Z"),
				"Content-Type":             "application/x-www-form-urlencoded; charset=utf-8",
				protocol.AWSAudienceHeader: awsAudience,
			},
		},
	}
}

// Anyone can send a login that STS must check. One source sending them
// must not use up the calls the agents need, and an agent's own logins
// must not use up its address's.
func TestAWSVerifier_LimitsSTSCallsPerSource(t *testing.T) {
	h := newLimitedAWSHarness(t, "", NewSTSLimiter())
	attacker := WithSource(context.Background(), "198.51.100.7:40000")
	agentAddr := WithSource(context.Background(), "203.0.113.9:50000")

	// the attacker's forged logins: refused by STS, then before it
	refused := 0
	for range 200 {
		_, err := h.verifier.VerifyLogin(attacker, forged(t, h, time.Now()))
		if errors.Is(err, ErrTooManyLogins) {
			refused++
		}
	}
	if calls := h.sts.calls.Load(); calls != sourceSTSBurst || refused != 200-sourceSTSBurst {
		t.Fatalf("STS calls = %d, refused = %d; want %d calls", calls, refused, sourceSTSBurst)
	}
	// the agent, from its own address, still logs in, again and again
	signedAt := time.Now()
	for i := range 2 * sourceSTSBurst {
		if _, err := h.verifier.VerifyLogin(agentAddr, h.signed(t, awsAudience, signedAt.Add(-time.Duration(i)*time.Second), agentCreds)); err != nil {
			t.Fatalf("agent login %d: %v", i, err)
		}
	}
	// an IPv6 attacker is one source for its whole /64
	for i := range 2 * sourceSTSBurst {
		ctx := WithSource(context.Background(), fmt.Sprintf("[2001:db8:1:2::%x]:443", i+1))
		_, _ = h.verifier.VerifyLogin(ctx, forged(t, h, time.Now()))
	}
	if calls := h.sts.calls.Load(); calls != 2*sourceSTSBurst+2*sourceSTSBurst {
		t.Fatalf("STS calls = %d after the IPv6 /64's forged logins", calls)
	}
}

func TestSource(t *testing.T) {
	cases := map[string]string{
		"192.0.2.1:1234":               "192.0.2.1",
		"192.0.2.1":                    "192.0.2.1",
		"[::ffff:192.0.2.1]:80":        "192.0.2.1",
		"[2001:db8:1:2:3:4:5:6]:443":   "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::1]:65535": "2001:db8:1:2::/64",
		"":                             "",
		"not an address":               "",
		// a proxy's, most likely, which every agent would share
		"10.0.3.7:5000":      "",
		"172.16.0.1:5000":    "",
		"192.168.1.1:5000":   "",
		"127.0.0.1:5000":     "",
		"[::1]:5000":         "",
		"[fd00::1]:5000":     "",
		"[fe80::1%eth0]:443": "",
	}
	for in, want := range cases {
		if got := source(in); got != want {
			t.Errorf("source(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSTSLimiter_ForgetsSourcesWithEveryCallLeft(t *testing.T) {
	l := newSTSLimiter(rate.NewLimiter(rate.Inf, 0), time.Second, 2)
	now := time.Now()
	for i := range maxSTSSources - 1 {
		if err := l.take(fmt.Sprintf("198.18.%d.%d", i/256, i%256), now); err != nil {
			t.Fatal(err)
		}
	}
	busy := "192.0.2.1"
	for range 2 {
		if err := l.take(busy, now); err != nil {
			t.Fatal(err)
		}
	}
	// a second on, the others have every call back and are forgotten; the
	// busy source has one of its two back and is kept
	later := now.Add(time.Second)
	if err := l.take("192.0.2.2", later); err != nil {
		t.Fatal(err)
	}
	if n := len(l.sources); n != 2 {
		t.Fatalf("sources = %d, want the two still counting", n)
	}
	if err := l.take(busy, later); err != nil {
		t.Fatalf("busy source's call back = %v", err)
	}
	if err := l.take(busy, later); !errors.Is(err, ErrTooManyLogins) {
		t.Fatalf("busy source = %v, want ErrTooManyLogins", err)
	}
	// with none to forget, every source is
	for i := range maxSTSSources {
		_ = l.take(fmt.Sprintf("198.19.%d.%d", i/256, i%256), later)
	}
	if n := len(l.sources); n > maxSTSSources {
		t.Fatalf("sources = %d, past the bound", n)
	}
}

func TestAWSVerifier_RejectsBeforeCallingSTS(t *testing.T) {
	h := newAWSHarness(t, "")
	now := time.Now()
	good := func() protocol.SessionRequest { return h.signed(t, awsAudience, now, agentCreds) }
	with := func(f func(*protocol.SessionRequest)) protocol.SessionRequest {
		r := good()
		f(&r)
		return r
	}
	cases := map[string]protocol.SessionRequest{
		"other host":          with(func(r *protocol.SessionRequest) { r.AWS.URL = "https://sts.amazonaws.com.evil.example.com/" }),
		"metadata endpoint":   with(func(r *protocol.SessionRequest) { r.AWS.URL = "https://169.254.169.254/" }),
		"plain http":          with(func(r *protocol.SessionRequest) { r.AWS.URL = strings.Replace(r.AWS.URL, "https://", "http://", 1) }),
		"query string":        with(func(r *protocol.SessionRequest) { r.AWS.URL += "?Action=AssumeRole" }),
		"other action":        with(func(r *protocol.SessionRequest) { r.AWS.Body = "Action=AssumeRole&Version=2011-06-15" }),
		"extra header":        with(func(r *protocol.SessionRequest) { r.AWS.Headers["X-Forwarded-Host"] = "evil" }),
		"other audience":      h.signed(t, "https://sealer.prod.example.com", now, agentCreds),
		"stale signature":     h.signed(t, awsAudience, now.Add(-20*time.Minute), agentCreds),
		"future signature":    h.signed(t, awsAudience, now.Add(20*time.Minute), agentCreds),
		"token alongside aws": with(func(r *protocol.SessionRequest) { r.Token = "x" }),
		"no signed request":   {Method: protocol.MethodAWSSTS},
		"audience not signed": with(func(r *protocol.SessionRequest) {
			r.AWS.Headers["Authorization"] = strings.Replace(r.AWS.Headers["Authorization"], ";"+strings.ToLower(protocol.AWSAudienceHeader), "", 1)
		}),
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := h.verifier.VerifyLogin(context.Background(), req); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("VerifyLogin = %v, want ErrUnauthorized", err)
			}
		})
	}
	if n := h.sts.calls.Load(); n != 0 {
		t.Errorf("STS was called %d times for requests that should never leave the control plane", n)
	}
}

func TestAWSVerifier_RejectsWhatSTSReports(t *testing.T) {
	cases := map[string]struct {
		roleID string
		mutate func(*fakeSTS)
		creds  aws.Credentials
	}{
		"bad signature":     {creds: aws.Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "wrong", SessionToken: "agent-session-token"}},
		"unregistered role": {mutate: func(f *fakeSTS) { f.arn = "arn:aws:sts::123456789012:assumed-role/other/s" }},
		"other account":     {mutate: func(f *fakeSTS) { f.arn = "arn:aws:sts::999999999999:assumed-role/use1-blue/s" }},
		"iam user":          {mutate: func(f *fakeSTS) { f.arn = "arn:aws:iam::123456789012:user/use1-blue" }},
		"recreated role":    {roleID: "AROAOTHERROLEID00000", creds: agentCreds},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newAWSHarness(t, tc.roleID)
			if tc.mutate != nil {
				tc.mutate(h.sts)
			}
			creds := tc.creds
			if creds.AccessKeyID == "" {
				creds = agentCreds
			}
			if _, err := h.verifier.VerifyLogin(context.Background(), h.signed(t, awsAudience, time.Now(), creds)); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("VerifyLogin = %v, want ErrUnauthorized", err)
			}
			if h.sts.calls.Load() != 1 {
				t.Errorf("STS calls = %d, want 1", h.sts.calls.Load())
			}
		})
	}
}

func TestAWSVerifier_DefaultHosts(t *testing.T) {
	v, err := NewAWSVerifier(AWSOptions{Registry: &registry.Registry{}, Audience: awsAudience, Replays: store.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"sts.amazonaws.com":                  true,
		"sts.us-east-1.amazonaws.com":        true,
		"sts.us-gov-west-1.amazonaws.com":    true,
		"sts.cn-north-1.amazonaws.com.cn":    true,
		"sts.xx-nowhere-9.amazonaws.com":     false,
		"sts.amazonaws.com:8443":             false,
		"sts.us-east-1.amazonaws.com.evil.x": false,
		"evilsts.us-east-1.amazonaws.com":    false,
		"169.254.169.254":                    false,
		"localhost":                          false,
	} {
		_, err := v.checkTarget(&protocol.SignedRequest{URL: "https://" + host + "/", Body: protocol.AWSGetCallerIdentityBody})
		if got := err == nil; got != want {
			t.Errorf("host %q allowed = %v, want %v", host, got, want)
		}
	}
}

func TestK8sVerifier_RejectsAWSRequest(t *testing.T) {
	v := fileVerifier(t, testRSA(t))
	_, err := v.VerifyLogin(context.Background(), protocol.SessionRequest{Method: protocol.MethodK8sOIDC, AWS: &protocol.SignedRequest{}})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("VerifyLogin = %v", err)
	}
}
