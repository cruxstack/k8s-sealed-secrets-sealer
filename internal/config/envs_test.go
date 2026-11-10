package config

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// sharedEnv is the control plane's settings without the env-scoped ones,
// which APP_ENVS gives.
func sharedEnv(envs string, extra map[string]string) map[string]string {
	vars := controlPlaneEnv(nil)
	for _, k := range envScoped {
		delete(vars, k)
	}
	vars["APP_PUBLIC_URL"] = "https://sealer.example.com"
	vars["APP_ENVS"] = envs
	for k, v := range extra {
		vars[k] = v
	}
	return vars
}

const twoEnvs = `
envs:
  - name: dev
    dynamodbTable: sealer-dev
    kmsTransitKeyId: arn:aws:kms:us-east-2:111111111111:key/mrk-dev
    registryFile: /etc/sealer/dev.yaml
    adminTeams: [platform]
  - name: prod
    dynamodbTable: sealer-prod
    kmsTransitKeyId: arn:aws:kms:us-east-2:222222222222:key/mrk-prod
    kmsRegion: us-east-2
    registry:
      issuers: []
      agents: [{id: prod-use1-blue}]
    allowedTeams: [prod-sealers]
    adminTeams: []
    keyRenewPeriod: 240h
`

func noSSM(string) (string, error) { return "", errors.New("no ssm in this test") }

func TestLoadControlPlanes_OneEnv(t *testing.T) {
	cfgs, err := loadControlPlanes(env(controlPlaneEnv(nil)), noSSM)
	if err != nil || len(cfgs) != 1 || cfgs[0].EnvName != "dev" {
		t.Fatalf("one env = %+v, %v", cfgs, err)
	}
	// its session keys are as configured
	if string(cfgs[0].AgentSessionKey) != strings.Repeat("k", 32) {
		t.Error("the agent session key of a single env was changed")
	}
	if _, err := loadControlPlanes(env(controlPlaneEnv(map[string]string{"APP_ENV_NAME": "secrets"})), noSSM); err == nil ||
		!strings.Contains(err.Error(), "web UI's own paths") {
		t.Errorf("an env named like a UI path = %v", err)
	}
}

func TestLoadControlPlanes_SeveralEnvs(t *testing.T) {
	cfgs, err := loadControlPlanes(env(sharedEnv(twoEnvs, map[string]string{
		"APP_GITHUB_ALLOWED_TEAMS": "sealers",
		"APP_GITHUB_ADMIN_TEAMS":   "sealer-admins",
		"APP_ENV_ANNOTATION":       "example.com/env",
	})), noSSM)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("%d envs", len(cfgs))
	}
	dev, prod := cfgs[0], cfgs[1]
	if dev.EnvName != "dev" || dev.DynamoDBTable != "sealer-dev" || dev.RegistryFile != "/etc/sealer/dev.yaml" ||
		dev.KMSTransitKeyID != "arn:aws:kms:us-east-2:111111111111:key/mrk-dev" {
		t.Errorf("dev = %+v", dev)
	}
	if prod.EnvName != "prod" || prod.DynamoDBTable != "sealer-prod" || prod.KMSRegion != "us-east-2" ||
		!strings.Contains(string(prod.Registry), "prod-use1-blue") || prod.KeyRenewPeriod != 240*time.Hour {
		t.Errorf("prod = %+v", prod)
	}
	// both are on the one URL, and share what they don't set themselves
	for _, cfg := range cfgs {
		if cfg.PublicURL != "https://sealer.example.com" || cfg.AgentAudience != "https://sealer.example.com" ||
			cfg.EnvAnnotation != "example.com/env" || cfg.GitHubOrg != "example-org" {
			t.Errorf("%s = %+v", cfg.EnvName, cfg)
		}
	}
	// teams an env gives replace the shared ones, even when empty
	if strings.Join(dev.GitHubAllowedTeams, ",") != "sealers" || strings.Join(dev.GitHubAdminTeams, ",") != "platform" {
		t.Errorf("dev teams = %v, %v", dev.GitHubAllowedTeams, dev.GitHubAdminTeams)
	}
	if strings.Join(prod.GitHubAllowedTeams, ",") != "prod-sealers" || len(prod.GitHubAdminTeams) != 0 {
		t.Errorf("prod teams = %v, %v", prod.GitHubAllowedTeams, prod.GitHubAdminTeams)
	}
	// one sign-in for every env; agents' sessions apart per env
	if !bytes.Equal(dev.UserSessionKey, prod.UserSessionKey) {
		t.Error("the envs sign people in with different keys")
	}
	if bytes.Equal(dev.AgentSessionKey, prod.AgentSessionKey) || string(dev.AgentSessionKey) == strings.Repeat("k", 32) {
		t.Error("the envs' agent session keys are not their own")
	}
}

func TestLoadControlPlanes_RegistryFromSSM(t *testing.T) {
	const arn = "arn:aws:ssm:us-east-2:222222222222:parameter/sealer/prod/registry"
	doc := `
envs:
  - {name: prod, dynamodbTable: t, kmsTransitKeyId: k, registry: "` + arn + `"}
`
	cfgs, err := loadControlPlanes(env(sharedEnv(doc, nil)), func(got string) (string, error) {
		if got != arn {
			return "", errors.New("unexpected parameter " + got)
		}
		return "agents: [{id: from-ssm}]", nil
	})
	if err != nil || !strings.Contains(string(cfgs[0].Registry), "from-ssm") {
		t.Fatalf("registry from ssm = %v", err)
	}
}

func TestLoadControlPlanes_Refuses(t *testing.T) {
	cases := map[string]struct {
		vars map[string]string
		want []string
	}{
		"env-scoped settings outside APP_ENVS": {
			sharedEnv(twoEnvs, map[string]string{"APP_DYNAMODB_TABLE": "sealer", "APP_ENV_NAME": "dev"}),
			[]string{"APP_DYNAMODB_TABLE cannot be set with APP_ENVS", "APP_ENV_NAME cannot be set with APP_ENVS"},
		},
		"no envs":       {sharedEnv("envs: []", nil), []string{"APP_ENVS lists no envs"}},
		"unknown field": {sharedEnv("envs: [{name: dev, tabel: x}]", nil), []string{"APP_ENVS:", "tabel"}},
		"envs that clash": {sharedEnv(`
envs:
  - {name: dev, dynamodbTable: t, kmsTransitKeyId: k, registryFile: r}
  - {name: dev, dynamodbTable: u, kmsTransitKeyId: k, registryFile: r}
  - {name: prod, dynamodbTable: t, kmsTransitKeyId: k, registryFile: r}
  - {name: fleet, dynamodbTable: v, kmsTransitKeyId: k, registryFile: r}
  - {dynamodbTable: w}
`, nil), []string{
			"APP_ENVS[dev]: the name is used twice",
			`APP_ENVS[prod]: table "t" is also dev's`,
			`APP_ENVS[fleet]: "fleet" is one of the web UI's own paths`,
			"APP_ENVS[4]: name is required",
		}},
		"an env missing its own settings": {
			sharedEnv("envs: [{name: dev}]", nil),
			[]string{"APP_ENVS[dev]:", "APP_DYNAMODB_TABLE is required", "APP_KMS_TRANSIT_KEY_ID is required", "APP_REGISTRY"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadControlPlanes(env(tc.vars), noSSM)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not say %q", err, want)
				}
			}
		})
	}
}

func TestKMSKeyRegion(t *testing.T) {
	for id, want := range map[string]string{
		"arn:aws:kms:us-east-1:111111111111:key/mrk-0123":        "us-east-1",
		"arn:aws:kms:us-east-2:111111111111:alias/sealer":        "us-east-2",
		"arn:aws-us-gov:kms:us-gov-west-1:111111111111:key/abcd": "us-gov-west-1",
		"alias/sealer-transit":                                   "",
		"mrk-0123":                                               "",
		"arn:aws:ssm:us-east-1:111111111111:parameter/x":         "",
	} {
		if got := KMSKeyRegion(id); got != want {
			t.Errorf("KMSKeyRegion(%q) = %q, want %q", id, got, want)
		}
	}
}
