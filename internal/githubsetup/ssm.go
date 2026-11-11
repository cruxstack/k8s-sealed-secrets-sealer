package githubsetup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// SSMClient is the part of the SSM API the store uses.
type SSMClient interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// SSMStore keeps the credentials in one SSM SecureString parameter, as
// JSON, encrypted with the account's aws/ssm key. It is written once: a
// parameter that exists is never overwritten.
type SSMStore struct {
	client SSMClient
	arn    string
	name   string
}

// NewSSMStore returns a store for the parameter arn names, called in the
// parameter's region; endpoint overrides SSM's, for local emulators. It
// makes no network calls.
func NewSSMStore(awsCfg aws.Config, arn, endpoint string) (*SSMStore, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[2] != "ssm" {
		return nil, fmt.Errorf("failed to configure the github app parameter: %s is not an ssm parameter arn", arn)
	}
	client := ssm.NewFromConfig(awsCfg, func(o *ssm.Options) {
		o.Region = parts[3]
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	return newSSMStore(client, arn)
}

func newSSMStore(client SSMClient, arn string) (*SSMStore, error) {
	name, ok := parameterName(arn)
	if !ok {
		return nil, fmt.Errorf("failed to configure the github app parameter: %s is not an ssm parameter arn", arn)
	}
	return &SSMStore{client: client, arn: arn, name: name}, nil
}

// parameterName returns the name of the parameter an ARN names, which
// PutParameter takes where GetParameter takes the ARN: a hierarchical name
// (/sealer/github-app) has its leading slash left out of the ARN.
func parameterName(arn string) (string, bool) {
	_, rest, ok := strings.Cut(arn, ":parameter/")
	if !ok || rest == "" {
		return "", false
	}
	if strings.Contains(rest, "/") {
		return "/" + rest, true
	}
	return rest, true
}

// Load reads the parameter, or returns ErrNotSetUp when it does not exist.
func (s *SSMStore) Load(ctx context.Context) (Credentials, error) {
	out, err := s.client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(s.arn), WithDecryption: aws.Bool(true)})
	var notFound *ssmtypes.ParameterNotFound
	if errors.As(err, &notFound) {
		return Credentials{}, ErrNotSetUp
	}
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to read the github app parameter %s: %w", s.arn, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return Credentials{}, fmt.Errorf("failed to read the github app parameter %s: it has no value", s.arn)
	}
	c, err := parseCredentials(*out.Parameter.Value)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to read the github app parameter %s: %w", s.arn, err)
	}
	return c, nil
}

// Create writes the parameter if it does not exist, then reads it back
// through its ARN: a parameter written in this account but named by an ARN
// in another would never be read.
func (s *SSMStore) Create(ctx context.Context, c Credentials) error {
	value, err := c.encode()
	if err != nil {
		return err
	}
	_, err = s.client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:        aws.String(s.name),
		Value:       aws.String(value),
		Type:        ssmtypes.ParameterTypeSecureString,
		Overwrite:   aws.Bool(false),
		Description: aws.String("GitHub App credentials of k8s-sealed-secrets-sealer, written by its setup page"),
	})
	var exists *ssmtypes.ParameterAlreadyExists
	if errors.As(err, &exists) {
		return ErrAlreadySetUp
	}
	if err != nil {
		return fmt.Errorf("failed to write the github app parameter %s: %w", s.name, err)
	}
	got, err := s.Load(ctx)
	switch {
	case errors.Is(err, ErrNotSetUp):
		return fmt.Errorf("failed to read back the github app parameter: wrote %s in this account, but %s names another", s.name, s.arn)
	case err != nil:
		return err
	case got.AppID != c.AppID:
		// another instance wrote it first, between the write and the read
		return ErrAlreadySetUp
	}
	return nil
}

// MemoryStore keeps credentials in memory, for tests.
type MemoryStore struct {
	mu    sync.Mutex
	creds *Credentials
	err   error
}

// NewMemoryStore returns a store holding c, or nothing when c is nil.
func NewMemoryStore(c *Credentials) *MemoryStore { return &MemoryStore{creds: c} }

// Fail makes Load and Create return err; nil makes them work again.
func (m *MemoryStore) Fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// Load returns the credentials, or ErrNotSetUp.
func (m *MemoryStore) Load(context.Context) (Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return Credentials{}, m.err
	}
	if m.creds == nil {
		return Credentials{}, ErrNotSetUp
	}
	return *m.creds, nil
}

// Create stores c unless credentials are stored already.
func (m *MemoryStore) Create(_ context.Context, c Credentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.creds != nil {
		return ErrAlreadySetUp
	}
	if err := c.Validate(); err != nil {
		return err
	}
	m.creds = &c
	return nil
}
