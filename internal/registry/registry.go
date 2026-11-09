// Package registry loads the agent registry: the agents allowed to log in to
// this control plane, the identity each logs in with, and the capabilities
// each may use. It is managed as infrastructure code; there is no enrollment
// API, so an identity not listed here is rejected.
package registry

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// File is the registry file's format.
//
//	issuers:
//	  - name: use1-blue
//	    url: https://oidc.example.com/id/ABC        # the tokens' iss claim
//	    jwksURL: https://oidc.example.com/id/ABC/keys
//	agents:
//	  - id: use1-blue
//	    cluster: blue
//	    region: use1
//	    capabilities: [seal, keys]
//	    identity:
//	      k8s:
//	        issuer: use1-blue
//	        subject: system:serviceaccount:sealer:sealer-agent
//	  - id: use2-blue
//	    cluster: blue
//	    region: use2
//	    capabilities: [seal]
//	    identity:
//	      aws:
//	        roleArn: arn:aws:iam::123456789012:role/sealer/use2-blue
type File struct {
	Issuers []Issuer `json:"issuers"`
	Agents  []Agent  `json:"agents"`
}

// Issuer is a Kubernetes service-account token issuer agents log in with.
type Issuer struct {
	Name string `json:"name"`
	// URL is the issuer as it appears in the tokens' iss claim.
	URL string `json:"url"`
	// Exactly one of JWKSURL and JWKSFile gives the issuer's signing keys.
	// JWKSFile suits issuers that are not reachable from the control plane.
	JWKSURL  string `json:"jwksURL,omitempty"`
	JWKSFile string `json:"jwksFile,omitempty"`
	// CAFile optionally holds the CA bundle that serves JWKSURL.
	CAFile string `json:"caFile,omitempty"`
}

// Agent is one registered agent: one cluster's agent.
type Agent struct {
	ID           string   `json:"id"`
	Cluster      string   `json:"cluster"`
	Region       string   `json:"region"`
	Capabilities []string `json:"capabilities"`
	Identity     Identity `json:"identity"`
}

// Identity is how an agent logs in. Exactly one field is set.
type Identity struct {
	K8s *K8sIdentity `json:"k8s,omitempty"`
	AWS *AWSIdentity `json:"aws,omitempty"`
}

// AWSIdentity is the IAM role an agent's pods run as (EKS Pod Identity or
// IRSA). STS reports an assumed role without its path, so the role is
// matched by partition, account and name.
type AWSIdentity struct {
	RoleARN string `json:"roleArn"`
	// RoleID optionally pins the role's unique ID (AROA...), so a deleted and
	// recreated role with the same name is not accepted.
	RoleID string `json:"roleId,omitempty"`
}

// K8sIdentity is a Kubernetes service account behind a registered issuer.
type K8sIdentity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// HasCapability reports whether the agent is registered with c.
func (a *Agent) HasCapability(c string) bool { return slices.Contains(a.Capabilities, c) }

// Registry is a validated agent registry.
type Registry struct {
	Issuers []Issuer
	// Agents is sorted by ID.
	Agents []Agent

	byID  map[string]*Agent
	byK8s map[k8sKey]*Agent
	byAWS map[AWSRole]*Agent
}

type k8sKey struct{ issuer, subject string }

// AWSRole identifies an IAM role as STS reports it.
type AWSRole struct {
	Partition string
	Account   string
	Name      string
}

// Agent returns the agent registered with id.
func (r *Registry) Agent(id string) (*Agent, bool) {
	a, ok := r.byID[id]
	return a, ok
}

// AgentByK8s returns the agent registered for a service account behind the
// named issuer.
func (r *Registry) AgentByK8s(issuer, subject string) (*Agent, bool) {
	a, ok := r.byK8s[k8sKey{issuer, subject}]
	return a, ok
}

// AgentByAWSRole returns the agent registered for an IAM role.
func (r *Registry) AgentByAWSRole(role AWSRole) (*Agent, bool) {
	a, ok := r.byAWS[role]
	return a, ok
}

var (
	roleARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/(?:[\x21-\x7e]*/)?([\w+=,.@-]{1,64})$`)
	roleIDPattern  = regexp.MustCompile(`^AROA[A-Z0-9]{12,124}$`)
)

// ParseRoleARN splits an IAM role ARN into the parts STS reports.
func ParseRoleARN(arn string) (AWSRole, bool) {
	m := roleARNPattern.FindStringSubmatch(arn)
	if m == nil {
		return AWSRole{}, false
	}
	return AWSRole{Partition: m[1], Account: m[2], Name: m[3]}, true
}

// Load reads and validates a registry file. Relative JWKS and CA paths are
// resolved against the file's directory.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent registry %s: %w", path, err)
	}
	r, err := Parse(data, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("invalid agent registry %s: %w", path, err)
	}
	return r, nil
}

// Parse validates registry YAML, reporting every problem at once.
func Parse(data []byte, baseDir string) (*Registry, error) {
	var f File
	if err := yaml.UnmarshalStrict(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}

	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	issuers := map[string]bool{}
	for i := range f.Issuers {
		is := &f.Issuers[i]
		where := fmt.Sprintf("issuers[%d]", i)
		if !isLabel(is.Name) {
			fail("%s: name must be a DNS-1123 label", where)
		} else if issuers[is.Name] {
			fail("%s: duplicate issuer %q", where, is.Name)
		}
		issuers[is.Name] = true
		if u, err := url.Parse(is.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			fail("%s: url must be an absolute https URL", where)
		}
		switch {
		case (is.JWKSURL == "") == (is.JWKSFile == ""):
			fail("%s: set exactly one of jwksURL and jwksFile", where)
		case is.JWKSURL != "":
			if u, err := url.Parse(is.JWKSURL); err != nil || u.Scheme != "https" || u.Host == "" {
				fail("%s: jwksURL must be an absolute https URL", where)
			}
		case is.CAFile != "":
			fail("%s: caFile applies only with jwksURL", where)
		}
		is.JWKSFile = resolve(baseDir, is.JWKSFile)
		is.CAFile = resolve(baseDir, is.CAFile)
	}

	r := &Registry{
		Issuers: f.Issuers,
		byID:    map[string]*Agent{},
		byK8s:   map[k8sKey]*Agent{},
		byAWS:   map[AWSRole]*Agent{},
	}
	agents := append([]Agent(nil), f.Agents...)
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })
	if len(agents) == 0 {
		fail("agents: at least one agent is required")
	}
	for i := range agents {
		a := &agents[i]
		where := fmt.Sprintf("agent %q", a.ID)
		if !isLabel(a.ID) {
			fail("%s: id must be a DNS-1123 label", where)
		} else if _, dup := r.byID[a.ID]; dup {
			fail("%s: duplicate id", where)
		}
		if !isLabel(a.Cluster) {
			fail("%s: cluster must be a DNS-1123 label", where)
		}
		if !isLabel(a.Region) {
			fail("%s: region must be a DNS-1123 label", where)
		}
		seen := map[string]bool{}
		for _, c := range a.Capabilities {
			if !protocol.IsCapability(c) {
				fail("%s: unknown capability %q", where, c)
			} else if seen[c] {
				fail("%s: duplicate capability %q", where, c)
			}
			seen[c] = true
		}
		r.byID[a.ID] = a

		if (a.Identity.K8s == nil) == (a.Identity.AWS == nil) {
			fail("%s: set exactly one of identity.k8s and identity.aws", where)
			continue
		}
		if aws := a.Identity.AWS; aws != nil {
			role, ok := ParseRoleARN(aws.RoleARN)
			if !ok {
				fail("%s: roleArn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)", where)
				continue
			}
			if aws.RoleID != "" && !roleIDPattern.MatchString(aws.RoleID) {
				fail("%s: roleId must be a role's unique ID (AROA...)", where)
			}
			if other, dup := r.byAWS[role]; dup {
				fail("%s: role already registered for agent %q", where, other.ID)
			}
			r.byAWS[role] = a
			continue
		}
		k := a.Identity.K8s
		if !issuers[k.Issuer] {
			fail("%s: unknown issuer %q", where, k.Issuer)
		}
		if !isServiceAccountSubject(k.Subject) {
			fail("%s: subject must be system:serviceaccount:<namespace>:<name>", where)
		}
		key := k8sKey{k.Issuer, k.Subject}
		if other, dup := r.byK8s[key]; dup {
			fail("%s: identity already registered for agent %q", where, other.ID)
		}
		r.byK8s[key] = a
	}
	r.Agents = agents

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return r, nil
}

func resolve(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func isLabel(s string) bool { return s != "" && len(validation.IsDNS1123Label(s)) == 0 }

func isServiceAccountSubject(s string) bool {
	parts := strings.Split(s, ":")
	return len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" &&
		isLabel(parts[2]) && len(validation.IsDNS1123Subdomain(parts[3])) == 0
}
