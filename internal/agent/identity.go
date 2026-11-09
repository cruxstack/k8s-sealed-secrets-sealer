package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// maxTokenFileBytes bounds the projected token file.
const maxTokenFileBytes = 16 << 10

// Identity builds the request the agent logs in to the control plane with.
type Identity interface {
	LoginRequest(ctx context.Context) (protocol.SessionRequest, error)
}

// K8sTokenIdentity logs in with the projected service-account token the
// kubelet keeps in TokenFile.
type K8sTokenIdentity struct {
	TokenFile string
}

// LoginRequest reads the token on every login: the kubelet rotates it, so it
// must not be cached.
func (k K8sTokenIdentity) LoginRequest(context.Context) (protocol.SessionRequest, error) {
	f, err := os.Open(k.TokenFile)
	if err != nil {
		return protocol.SessionRequest{}, fmt.Errorf("failed to open identity token %s: %w", k.TokenFile, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return protocol.SessionRequest{}, fmt.Errorf("failed to read identity token %s: %w", k.TokenFile, err)
	}
	if len(data) > maxTokenFileBytes {
		return protocol.SessionRequest{}, fmt.Errorf("failed to read identity token %s: file is too large", k.TokenFile)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return protocol.SessionRequest{}, fmt.Errorf("failed to read identity token %s: file is empty", k.TokenFile)
	}
	return protocol.SessionRequest{Method: protocol.MethodK8sOIDC, Token: token}, nil
}

// AWSIdentity logs in with the pod's IAM role: it signs an
// sts:GetCallerIdentity request that the control plane forwards to STS. The
// credentials themselves never leave the agent.
type AWSIdentity struct {
	creds    aws.CredentialsProvider
	region   string
	audience string
	endpoint string
	signer   *v4.Signer
	now      func() time.Time
}

// AWSIdentityOptions configures an AWSIdentity.
type AWSIdentityOptions struct {
	Credentials aws.CredentialsProvider
	// Region selects the regional STS endpoint to sign for.
	Region string
	// Audience names the control plane; it is signed into the request.
	Audience string
	// Endpoint overrides https://sts.<region>.amazonaws.com, for tests.
	Endpoint string
	Now      func() time.Time
}

// NewAWSIdentity returns an AWSIdentity. It makes no network calls.
func NewAWSIdentity(opts AWSIdentityOptions) (*AWSIdentity, error) {
	if opts.Credentials == nil || opts.Region == "" || opts.Audience == "" {
		return nil, errors.New("failed to set up aws identity: credentials, region and audience are required")
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = "https://sts." + opts.Region + ".amazonaws.com/"
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &AWSIdentity{
		creds:    opts.Credentials,
		region:   opts.Region,
		audience: opts.Audience,
		endpoint: endpoint,
		signer:   v4.NewSigner(),
		now:      now,
	}, nil
}

// LoginRequest signs a fresh sts:GetCallerIdentity request. Each one can be
// used to log in once.
func (a *AWSIdentity) LoginRequest(ctx context.Context) (protocol.SessionRequest, error) {
	creds, err := a.creds.Retrieve(ctx)
	if err != nil {
		return protocol.SessionRequest{}, fmt.Errorf("failed to get aws credentials: %w", err)
	}
	body := protocol.AWSGetCallerIdentityBody
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(body))
	if err != nil {
		return protocol.SessionRequest{}, fmt.Errorf("failed to build sts request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set(protocol.AWSAudienceHeader, a.audience)
	sum := sha256.Sum256([]byte(body))
	if err := a.signer.SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "sts", a.region, a.now().UTC()); err != nil {
		return protocol.SessionRequest{}, fmt.Errorf("failed to sign sts request: %w", err)
	}
	headers := map[string]string{}
	for name := range req.Header {
		headers[name] = req.Header.Get(name)
	}
	return protocol.SessionRequest{
		Method: protocol.MethodAWSSTS,
		AWS:    &protocol.SignedRequest{URL: a.endpoint, Headers: headers, Body: body},
	}, nil
}
