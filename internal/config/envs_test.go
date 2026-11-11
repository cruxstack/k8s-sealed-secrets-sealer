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

func TestLoadControlPlanes_AdminTokenPerEnv(t *testing.T) {
	const arn = "arn:aws:ssm:us-east-2:222222222222:parameter/sealer/prod/admin-token"
	shared, devToken, prodToken := strings.Repeat("s", 32), strings.Repeat("d", 32), strings.Repeat("p", 32)
	doc := `
envs:
  - {name: dev, dynamodbTable: a, kmsTransitKeyId: alias/dev, registryFile: r, adminToken: ` + devToken + `}
  - {name: prod, dynamodbTable: b, kmsTransitKeyId: alias/prod, registryFile: r, adminToken: "` + arn + `", adminTokenKeyChanges: true}
  - {name: test, dynamodbTable: c, kmsTransitKeyId: alias/test, registryFile: r}
`
	cfgs, err := loadControlPlanes(env(sharedEnv(doc, map[string]string{"APP_ADMIN_TOKEN": shared})), func(got string) (string, error) {
		if got != arn {
			return "", errors.New("unexpected parameter " + got)
		}
		return prodToken, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// an env's own token replaces the shared one, which the rest keep
	for i, want := range []string{devToken, prodToken, shared} {
		if cfgs[i].AdminToken != want {
			t.Errorf("%s's admin token is not its own", cfgs[i].EnvName)
		}
	}
	// only the env that allows it lets its token change keys
	for i, want := range []bool{false, true, false} {
		if cfgs[i].AdminTokenKeyChanges != want {
			t.Errorf("%s: admin token key changes = %v, want %v", cfgs[i].EnvName, cfgs[i].AdminTokenKeyChanges, want)
		}
	}

	_, err = loadControlPlanes(env(sharedEnv(`
envs: [{name: dev, dynamodbTable: a, kmsTransitKeyId: k, registryFile: r, adminToken: short}]
`, nil)), noSSM)
	if err == nil || !strings.Contains(err.Error(), "APP_ENVS[dev]: APP_ADMIN_TOKEN must be at least 32 bytes") || strings.Contains(err.Error(), "short") {
		t.Fatalf("a short admin token = %v", err)
	}
}

func TestLoadControlPlanes_RegistryParameter(t *testing.T) {
	const arn = "arn:aws:ssm:us-east-2:111111111111:parameter/sealer/dev/registry"
	read := func(got string) (string, error) {
		if got != arn {
			return "", errors.New("unexpected parameter " + got)
		}
		return "agents: [{id: from-ssm}]", nil
	}
	// one env: APP_REGISTRY is read here, and its ARN kept to read again
	vars := controlPlaneEnv(map[string]string{"APP_REGISTRY": arn})
	delete(vars, "APP_REGISTRY_FILE")
	cfgs, err := loadControlPlanes(env(vars), read)
	if err != nil || string(cfgs[0].Registry) != "agents: [{id: from-ssm}]" || cfgs[0].RegistryParameter != arn {
		t.Fatalf("one env's registry from ssm = %q from %q, %v", cfgs[0].Registry, cfgs[0].RegistryParameter, err)
	}
	if _, err := loadControlPlanes(env(vars), noSSM); err == nil || !strings.Contains(err.Error(), "APP_REGISTRY: failed to read SSM parameter "+arn) {
		t.Fatalf("unreadable registry parameter = %v", err)
	}

	// several envs: only a registry read from SSM has a parameter
	cfgs, err = loadControlPlanes(env(sharedEnv(`
envs:
  - {name: dev, dynamodbTable: a, kmsTransitKeyId: alias/dev, registry: "`+arn+`"}
  - {name: prod, dynamodbTable: b, kmsTransitKeyId: alias/prod, registry: "agents: [{id: inline}]"}
  - {name: test, dynamodbTable: c, kmsTransitKeyId: alias/test, registryFile: /etc/sealer/test.yaml}
`, nil)), read)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{arn, "", ""} {
		if cfgs[i].RegistryParameter != want {
			t.Errorf("%s's registry parameter = %q, want %q", cfgs[i].EnvName, cfgs[i].RegistryParameter, want)
		}
	}
}

func TestLoadControlPlanes_TransitKeyPerEnv(t *testing.T) {
	envs := func(devKey, devRegion, prodKey, prodRegion string) string {
		return `
envs:
  - {name: dev, dynamodbTable: a, registryFile: r, kmsTransitKeyId: "` + devKey + `", kmsRegion: "` + devRegion + `"}
  - {name: prod, dynamodbTable: b, registryFile: r, kmsTransitKeyId: "` + prodKey + `", kmsRegion: "` + prodRegion + `"}
`
	}
	const (
		devARN  = "arn:aws:kms:us-east-2:111111111111:key/0123"
		mrkUse1 = "arn:aws:kms:us-east-1:111111111111:key/mrk-0123"
		mrkUse2 = "arn:aws:kms:us-east-2:111111111111:key/mrk-0123"
	)
	for name, tc := range map[string]struct {
		doc    string
		shared bool
	}{
		"the same key ARN":               {envs(devARN, "", devARN, ""), true},
		"replicas of a multi-Region key": {envs(mrkUse1, "", mrkUse2, ""), true},
		"a multi-Region key by its ID":   {envs("mrk-0123", "us-east-1", "mrk-0123", "us-east-2"), true},
		"the same alias in one region":   {envs("alias/transit", "", "alias/transit", ""), true},
		"the same alias in two regions":  {envs("alias/transit", "us-east-1", "alias/transit", "us-east-2"), false},
		"keys in two accounts":           {envs(devARN, "", strings.Replace(devARN, "111111111111", "222222222222", 1), ""), false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadControlPlanes(env(sharedEnv(tc.doc, nil)), noSSM)
			refused := err != nil && strings.Contains(err.Error(), "APP_ENVS[prod]: transit key") &&
				strings.Contains(err.Error(), "is also dev's; each env needs its own")
			if refused != tc.shared || (!tc.shared && err != nil) {
				t.Fatalf("loadControlPlanes = %v, want refused %v", err, tc.shared)
			}
		})
	}
}

func TestLoadControlPlanes_Refuses(t *testing.T) {
	cases := map[string]struct {
		vars map[string]string
		want []string
	}{
		"env-scoped settings outside APP_ENVS": {
			sharedEnv(twoEnvs, map[string]string{"APP_DYNAMODB_TABLE": "sealer", "APP_ENV_NAME": "dev", "APP_ADMIN_TOKEN_KEY_CHANGES": "true"}),
			[]string{"APP_DYNAMODB_TABLE cannot be set with APP_ENVS", "APP_ENV_NAME cannot be set with APP_ENVS",
				"APP_ADMIN_TOKEN_KEY_CHANGES cannot be set with APP_ENVS"},
		},
		"key changes without an admin token": {
			sharedEnv("envs: [{name: dev, dynamodbTable: a, kmsTransitKeyId: k, registryFile: r, adminTokenKeyChanges: true}]", nil),
			[]string{"APP_ENVS[dev]: APP_ADMIN_TOKEN_KEY_CHANGES (adminTokenKeyChanges) needs an admin token"},
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
