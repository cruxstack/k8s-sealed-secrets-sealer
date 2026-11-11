// Package githubsetup creates the control plane's GitHub App in its org
// with GitHub's manifest flow, and keeps the App's credentials in an SSM
// SecureString parameter that is written once (docs/design.md, section 12,
// "GitHub App setup").
package githubsetup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNotSetUp means no GitHub App's credentials are stored yet.
var ErrNotSetUp = errors.New("the github app is not set up")

// ErrAlreadySetUp means credentials are stored already, and are kept.
var ErrAlreadySetUp = errors.New("the github app is already set up")

// Credentials are what the control plane needs of its GitHub App: its ID
// and private key to read repositories and open pull requests, and its
// client ID and secret to sign people in. Slug names the App on GitHub.
type Credentials struct {
	AppID        string `json:"app_id"`
	Slug         string `json:"slug"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	PrivateKey   string `json:"private_key"`
}

var (
	appIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
	// a GitHub App's slug: lowercase letters, digits and dashes
	slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)
)

// Validate reports every problem with the credentials, naming fields but
// never their values.
func (c Credentials) Validate() error {
	var errs []error
	if !appIDPattern.MatchString(c.AppID) {
		errs = append(errs, errors.New("app_id must be a number"))
	}
	if !slugPattern.MatchString(c.Slug) {
		errs = append(errs, errors.New("slug must be a github app slug"))
	}
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, errors.New("client_id is required"))
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		errs = append(errs, errors.New("client_secret is required"))
	}
	if !strings.Contains(c.PrivateKey, "PRIVATE KEY-----") {
		errs = append(errs, errors.New("private_key must be a PEM private key"))
	}
	return errors.Join(errs...)
}

// encode returns the credentials as the parameter holds them.
func (c Credentials) encode() (string, error) {
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("invalid github app credentials: %w", err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to encode github app credentials: %w", err)
	}
	return string(b), nil
}

// parseCredentials reads credentials as the parameter holds them.
func parseCredentials(value string) (Credentials, error) {
	var c Credentials
	dec := json.NewDecoder(strings.NewReader(value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		// the decoder's error may quote the value
		return Credentials{}, errors.New("invalid github app credentials: not the JSON the setup page writes")
	}
	if err := c.Validate(); err != nil {
		return Credentials{}, fmt.Errorf("invalid github app credentials: %w", err)
	}
	return c, nil
}

// Store keeps the GitHub App's credentials.
type Store interface {
	// Load returns the stored credentials, or ErrNotSetUp.
	Load(ctx context.Context) (Credentials, error)
	// Create stores credentials when none are, or returns ErrAlreadySetUp
	// and keeps those that are.
	Create(ctx context.Context, c Credentials) error
}
