package agentauth

import (
	"bytes"
	"context"
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
