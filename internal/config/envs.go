package config

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// envScoped are the settings that belong to one env. In multi-env mode they
// come from APP_ENVS and nowhere else; every other setting is shared, and
// an env's entry may override some of those.
var envScoped = []string{
	"APP_ENV_NAME", "APP_REGISTRY", "APP_REGISTRY_FILE", "APP_DYNAMODB_TABLE", "APP_KMS_TRANSIT_KEY_ID",
}

// reservedEnvNames are the web UI's and the host's own top-level paths,
// which env names, the first segment of the UI's other paths, cannot be.
var reservedEnvNames = []string{
	"agent", "api", "assets", "auth", "fleet", "healthz", "login", "readyz", "repos", "secrets", "static",
}

// envEntry is one env in APP_ENVS. Settings it leaves out are shared: they
// come from the APP_ variables of the same name.
type envEntry struct {
	Name string `yaml:"name"`
	// Registry is the agent registry: inline, as a mapping or a YAML
	// document in a string, or the ARN of an SSM parameter holding it.
	Registry     yaml.Node `yaml:"registry"`
	RegistryFile string    `yaml:"registryFile"`

	DynamoDBTable   string `yaml:"dynamodbTable"`
	KMSTransitKeyID string `yaml:"kmsTransitKeyId"`
	KMSRegion       string `yaml:"kmsRegion"`

	AllowedTeams       []string `yaml:"allowedTeams"`
	AdminTeams         []string `yaml:"adminTeams"`
	EnvAnnotation      string   `yaml:"envAnnotation"`
	RegionAnnotation   string   `yaml:"regionAnnotation"`
	DiscoveryFileGlobs []string `yaml:"discoveryFileGlobs"`
	KeyRenewPeriod     string   `yaml:"keyRenewPeriod"`
}

// LoadControlPlanes reads the envs one control plane serves on its URL:
// the one the APP_ variables describe or, with APP_ENVS, several, each with
// its own registry, table, transit key and teams, and the rest of the
// settings shared. Settings given as SSM parameter ARNs are read from SSM,
// as an env's registry may be.
func LoadControlPlanes(ctx context.Context) ([]*ControlPlane, error) {
	var read ParameterReader
	lookup, err := resolveParameters(ctx, os.Environ(), func(ctx context.Context) (ParameterReader, error) {
		r, err := newSSMReader(ctx)
		read = r
		return r, err
	})
	if err != nil {
		return nil, err
	}
	resolve := func(arn string) (string, error) {
		if read == nil {
			if read, err = newSSMReader(ctx); err != nil {
				return "", err
			}
		}
		ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		defer cancel()
		return read(ctx, arn)
	}
	return loadControlPlanes(lookup, resolve)
}

func loadControlPlanes(lookup lookupFunc, resolve func(arn string) (string, error)) ([]*ControlPlane, error) {
	doc, ok := lookup("APP_ENVS")
	if !ok || strings.TrimSpace(doc) == "" {
		cfg, err := loadControlPlane(lookup)
		if err != nil {
			return nil, err
		}
		if slices.Contains(reservedEnvNames, cfg.EnvName) {
			return nil, fmt.Errorf("invalid configuration: APP_ENV_NAME: %q is one of the web UI's own paths", cfg.EnvName)
		}
		return []*ControlPlane{cfg}, nil
	}

	r := &reader{lookup: lookup}
	for _, k := range envScoped {
		if _, ok := lookup(k); ok {
			r.fail("%s cannot be set with APP_ENVS; set it for each env in APP_ENVS", k)
		}
	}
	var parsed struct {
		Envs []envEntry `yaml:"envs"`
	}
	dec := yaml.NewDecoder(strings.NewReader(doc))
	dec.KnownFields(true)
	if err := dec.Decode(&parsed); err != nil {
		r.fail("APP_ENVS: %v", err)
	} else if len(parsed.Envs) == 0 {
		r.fail("APP_ENVS lists no envs")
	}
	if err := r.err(); err != nil {
		return nil, err
	}

	var out []*ControlPlane
	names := map[string]bool{}
	tables := map[string]string{}
	for i, e := range parsed.Envs {
		where := fmt.Sprintf("APP_ENVS[%d]", i)
		if e.Name != "" {
			where = fmt.Sprintf("APP_ENVS[%s]", e.Name)
		}
		switch {
		case e.Name == "":
			r.fail("%s: name is required", where)
			continue
		case names[e.Name]:
			r.fail("%s: the name is used twice", where)
			continue
		case slices.Contains(reservedEnvNames, e.Name):
			r.fail("%s: %q is one of the web UI's own paths", where, e.Name)
			continue
		}
		names[e.Name] = true
		if e.DynamoDBTable != "" {
			if other, ok := tables[e.DynamoDBTable]; ok {
				r.fail("%s: table %q is also %s's; each env needs its own", where, e.DynamoDBTable, other)
			}
			tables[e.DynamoDBTable] = e.Name
		}

		overlay, err := e.settings(resolve)
		if err != nil {
			r.fail("%s: %v", where, err)
			continue
		}
		cfg, err := loadControlPlane(func(key string) (string, bool) {
			if v, ok := overlay[key]; ok {
				return v, true
			}
			if slices.Contains(envScoped, key) {
				return "", false
			}
			return lookup(key)
		})
		if err != nil {
			r.fail("%s: %v", where, strings.TrimPrefix(err.Error(), "invalid configuration: "))
			continue
		}
		// an agent's session from one env never verifies in another, even
		// if a token's own env check were wrong; people sign in once for
		// every env, so their session key is shared
		cfg.AgentSessionKey = deriveKey(cfg.AgentSessionKey, "agent-session:"+e.Name)
		out = append(out, cfg)
	}
	if err := r.err(); err != nil {
		return nil, err
	}
	return out, nil
}

// settings returns the APP_ settings an env's entry sets.
func (e envEntry) settings(resolve func(string) (string, error)) (map[string]string, error) {
	s := map[string]string{"APP_ENV_NAME": e.Name}
	set := func(key, v string) {
		if v != "" {
			s[key] = v
		}
	}
	set("APP_DYNAMODB_TABLE", e.DynamoDBTable)
	set("APP_KMS_TRANSIT_KEY_ID", e.KMSTransitKeyID)
	set("APP_KMS_REGION", e.KMSRegion)
	set("APP_ENV_ANNOTATION", e.EnvAnnotation)
	set("APP_REGION_ANNOTATION", e.RegionAnnotation)
	set("APP_KEY_RENEW_PERIOD", e.KeyRenewPeriod)
	set("APP_DISCOVERY_FILE_GLOBS", strings.Join(e.DiscoveryFileGlobs, ","))
	// teams given for an env replace the shared ones, even when empty
	if e.AllowedTeams != nil {
		s["APP_GITHUB_ALLOWED_TEAMS"] = strings.Join(e.AllowedTeams, ",")
	}
	if e.AdminTeams != nil {
		s["APP_GITHUB_ADMIN_TEAMS"] = strings.Join(e.AdminTeams, ",")
	}

	set("APP_REGISTRY_FILE", e.RegistryFile)
	switch e.Registry.Kind {
	case 0:
	case yaml.ScalarNode:
		v := e.Registry.Value
		if IsSSMParameterARN(strings.TrimSpace(v)) {
			read, err := resolve(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("failed to read the registry from %s: %w", strings.TrimSpace(v), err)
			}
			v = read
		}
		set("APP_REGISTRY", v)
	default:
		b, err := yaml.Marshal(&e.Registry)
		if err != nil {
			return nil, fmt.Errorf("registry: %w", err)
		}
		s["APP_REGISTRY"] = string(b)
	}
	return s, nil
}

// deriveKey derives a key for one purpose from a configured secret.
func deriveKey(secret []byte, purpose string) []byte {
	key, err := hkdf.Key(sha256.New, secret, nil, "k8s-sealed-secrets-sealer "+purpose, 32)
	if err != nil {
		// only for lengths HKDF cannot produce; 32 bytes it always can
		panic(err)
	}
	return key
}

// KMSKeyRegion returns the region in a KMS key or alias ARN, which is where
// the key must be called, or "" for a key ID or alias name. Keys in another
// account can only be named by ARN.
func KMSKeyRegion(keyID string) string {
	parts := strings.SplitN(keyID, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "kms" {
		return ""
	}
	return parts[3]
}
