package config

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestIsSSMParameterARN(t *testing.T) {
	for v, want := range map[string]bool{
		"arn:aws:ssm:us-east-1:123456789012:parameter/sealer/dev/github-app-key": true,
		"arn:aws:ssm:eu-west-1:123456789012:parameter/plain-name":                true,
		"arn:aws-us-gov:ssm:us-gov-west-1:123456789012:parameter/x":              true,
		"arn:aws-cn:ssm:cn-north-1:123456789012:parameter/x":                     true,
		"arn:aws:ssm:us-east-1:123456789012:parameter/":                          false,
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:x":                 false,
		"arn:aws:ssm:us-east-1:1234:parameter/x":                                 false,
		"https://arn:aws:ssm:us-east-1:123456789012:parameter/x":                 false,
		"xarn:aws:ssm:us-east-1:123456789012:parameter/x":                        false,
		"alias/sealer-transit":                                                   false,
		"":                                                                       false,
	} {
		if got := IsSSMParameterARN(v); got != want {
			t.Errorf("IsSSMParameterARN(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestResolveParameters(t *testing.T) {
	const keyARN = "arn:aws:ssm:us-east-1:123456789012:parameter/sealer/dev/github-app-key"
	const registryARN = "arn:aws:ssm:eu-west-1:123456789012:parameter/sealer/dev/registry"
	environ := []string{
		"APP_ENV_NAME=dev",
		"APP_GITHUB_APP_PRIVATE_KEY=" + keyARN,
		"APP_REGISTRY=" + registryARN,
		// only APP_ settings are read from SSM
		"OTHER=" + keyARN,
		"MALFORMED",
	}
	var mu sync.Mutex
	var read []string
	reader := func(context.Context) (ParameterReader, error) {
		return func(_ context.Context, arn string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			read = append(read, arn)
			return map[string]string{keyARN: "-----BEGIN RSA PRIVATE KEY-----\nk\n", registryARN: "agents: []\n"}[arn], nil
		}, nil
	}
	lookup, err := resolveParameters(context.Background(), environ, reader)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(read)
	if strings.Join(read, ",") != registryARN+","+keyARN {
		t.Fatalf("parameters read: %v", read)
	}
	for key, want := range map[string]string{
		"APP_ENV_NAME":               "dev",
		"APP_GITHUB_APP_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nk\n",
		"APP_REGISTRY":               "agents: []\n",
		"OTHER":                      keyARN,
	} {
		if got, _ := lookup(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if _, ok := lookup("UNSET"); ok {
		t.Error("an unset variable reads as set")
	}
}

func TestResolveParameters_NeedsNoAWSWithoutARNs(t *testing.T) {
	reader := func(context.Context) (ParameterReader, error) {
		t.Fatal("the SSM reader was created with no parameter to read")
		return nil, nil
	}
	lookup, err := resolveParameters(context.Background(), []string{"APP_ENV_NAME=dev"}, reader)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := lookup("APP_ENV_NAME"); v != "dev" {
		t.Fatalf("APP_ENV_NAME = %q", v)
	}
}

func TestResolveParameters_ReportsEveryFailureWithoutValues(t *testing.T) {
	const a = "arn:aws:ssm:us-east-1:123456789012:parameter/a"
	const b = "arn:aws:ssm:us-east-1:123456789012:parameter/b"
	reader := func(context.Context) (ParameterReader, error) {
		return func(_ context.Context, arn string) (string, error) {
			return "", errors.New("AccessDeniedException: not authorized to read " + arn)
		}, nil
	}
	_, err := resolveParameters(context.Background(), []string{"APP_USER_SESSION_KEY=" + a, "APP_AGENT_SESSION_KEY=" + b}, reader)
	if err == nil || !strings.Contains(err.Error(), "APP_USER_SESSION_KEY: failed to read SSM parameter "+a) ||
		!strings.Contains(err.Error(), "APP_AGENT_SESSION_KEY: failed to read SSM parameter "+b) {
		t.Fatalf("error = %v", err)
	}

	broken := func(context.Context) (ParameterReader, error) { return nil, errors.New("no credentials") }
	if _, err := resolveParameters(context.Background(), []string{"APP_X=" + a}, broken); err == nil {
		t.Fatal("expected an error")
	}
}

func TestLoadControlPlane_RegistryInlineOrFile(t *testing.T) {
	inline := controlPlaneEnv(map[string]string{"APP_REGISTRY": "agents: []\n"})
	delete(inline, "APP_REGISTRY_FILE")
	cfg, err := loadControlPlane(env(inline))
	if err != nil || string(cfg.Registry) != "agents: []" || cfg.RegistryFile != "" {
		t.Fatalf("inline registry: %q, file %q, %v", cfg.Registry, cfg.RegistryFile, err)
	}
	both := controlPlaneEnv(map[string]string{"APP_REGISTRY": "agents: []\n"})
	if _, err := loadControlPlane(env(both)); err == nil || !strings.Contains(err.Error(), "exactly one of APP_REGISTRY_FILE and APP_REGISTRY") {
		t.Fatalf("both: %v", err)
	}
}
