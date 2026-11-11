package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/controlplane"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
)

// envRegistries holds the registry in force of every env on the URL, so no
// agent identity is registered in two of them: they share the agent
// audience, so a login made for one env would be accepted by the other.
type envRegistries struct {
	mu   sync.Mutex
	regs map[string]*registry.Registry
}

func newEnvRegistries() *envRegistries {
	return &envRegistries{regs: map[string]*registry.Registry{}}
}

// set makes reg env's registry, unless another env registers one of its
// identities or commit fails. Checking and committing under one lock keeps
// two envs from taking the same identity at once.
func (e *envRegistries) set(env string, reg *registry.Registry, commit func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	others := make([]string, 0, len(e.regs))
	for name := range e.regs {
		if name != env {
			others = append(others, name)
		}
	}
	slices.Sort(others)
	var errs []error
	for _, other := range others {
		for _, shared := range registry.SharedIdentities(reg, e.regs[other]) {
			errs = append(errs, fmt.Errorf("%s in env %s", shared, other))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("an agent identity is registered in another env: %w", errors.Join(errs...))
	}
	if err := commit(); err != nil {
		return err
	}
	e.regs[env] = reg
	return nil
}

// envLogins builds an env's login verifiers for each registry it is given,
// and keeps what must outlive a registry change: the STS call limit and the
// issuers' key sets with their refetch floor.
type envLogins struct {
	audience string
	stsHosts []string
	replays  agentauth.ReplayStore
	stsLimit *agentauth.STSLimiter
	k8s      *agentauth.K8sVerifier
}

func (l *envLogins) build(reg *registry.Registry) (map[string]controlplane.LoginVerifier, error) {
	k8s, err := agentauth.NewK8sVerifier(agentauth.K8sOptions{Registry: reg, Audience: l.audience, Previous: l.k8s})
	if err != nil {
		return nil, err
	}
	aws, err := agentauth.NewAWSVerifier(agentauth.AWSOptions{
		Registry:     reg,
		Audience:     l.audience,
		AllowedHosts: l.stsHosts,
		Replays:      l.replays,
		STSLimiter:   l.stsLimit,
	})
	if err != nil {
		return nil, err
	}
	l.k8s = k8s
	return map[string]controlplane.LoginVerifier{
		protocol.MethodK8sOIDC: k8s,
		protocol.MethodAWSSTS:  aws,
	}, nil
}

// envRegistry is one env's registry: where it is read from, and what is
// built from it.
type envRegistry struct {
	env    string
	cfg    *config.ControlPlane
	logins *envLogins
	all    *envRegistries
	// read reads an SSM parameter; made on first use
	read config.ParameterReader
	// last is the content of the registry in force and the files it
	// references, hashed (contentHash)
	last [sha256.Size]byte
}

// reloadable reports whether the registry can change while the control
// plane runs: one in a file or an SSM parameter can, one given inline
// cannot.
func (r *envRegistry) reloadable() bool {
	return r.cfg.RegistryFile != "" || r.cfg.RegistryParameter != ""
}

// start reads the registry at start. A registry from an SSM parameter was
// read with the rest of the configuration.
func (r *envRegistry) start(ctx context.Context) (*registry.Registry, map[string]controlplane.LoginVerifier, error) {
	data, baseDir := r.cfg.Registry, ""
	if r.cfg.RegistryFile != "" {
		var err error
		if data, baseDir, err = r.source(ctx); err != nil {
			return nil, nil, err
		}
	}
	reg, sum, err := r.parse(data, baseDir)
	if err != nil {
		return nil, nil, err
	}
	return r.use(reg, sum)
}

// reload reads the registry again, for controlplane.Options.ReloadRegistry.
// It returns a nil registry when neither it nor a JWKS or CA file it
// references has changed.
func (r *envRegistry) reload(ctx context.Context) (*registry.Registry, map[string]controlplane.LoginVerifier, error) {
	data, baseDir, err := r.source(ctx)
	if err != nil {
		return nil, nil, err
	}
	reg, sum, err := r.parse(data, baseDir)
	if err != nil {
		return nil, nil, err
	}
	if sum == r.last {
		return nil, nil, nil
	}
	return r.use(reg, sum)
}

// parse validates a registry and hashes it with the files it references.
func (r *envRegistry) parse(data []byte, baseDir string) (*registry.Registry, [sha256.Size]byte, error) {
	reg, err := registry.Parse(data, baseDir)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("invalid agent registry %s: %w", r.name(), err)
	}
	sum, err := contentHash(data, reg)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("invalid agent registry %s: %w", r.name(), err)
	}
	return reg, sum, nil
}

// contentHash hashes a registry with the JWKS and CA files it references,
// so a change to any of them is a change of the registry: the verifiers
// built for it hold what the files held when they were built.
func contentHash(data []byte, reg *registry.Registry) ([sha256.Size]byte, error) {
	h := sha256.New()
	// the configuration trims the registry it read at start
	writeField(h, bytes.TrimSpace(data))
	for _, is := range reg.Issuers {
		for _, path := range []string{is.JWKSFile, is.CAFile} {
			if path == "" {
				continue
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return [sha256.Size]byte{}, fmt.Errorf("failed to read issuer %s's file: %w", is.Name, err)
			}
			writeField(h, []byte(path))
			writeField(h, content)
		}
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum, nil
}

// writeField writes b with its length, so no two lists of fields hash the
// same.
func writeField(h hash.Hash, b []byte) {
	_ = binary.Write(h, binary.BigEndian, uint64(len(b)))
	h.Write(b)
}

// source reads the registry from its file or SSM parameter, or returns it
// as given inline, with the directory relative paths in it are against.
func (r *envRegistry) source(ctx context.Context) ([]byte, string, error) {
	switch {
	case r.cfg.RegistryFile != "":
		data, err := os.ReadFile(r.cfg.RegistryFile)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read agent registry %s: %w", r.cfg.RegistryFile, err)
		}
		return data, filepath.Dir(r.cfg.RegistryFile), nil
	case r.cfg.RegistryParameter != "":
		if r.read == nil {
			read, err := config.NewParameterReader(ctx)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read agent registry %s: %w", r.cfg.RegistryParameter, err)
			}
			r.read = read
		}
		v, err := r.read(ctx, r.cfg.RegistryParameter)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read agent registry %s: %w", r.cfg.RegistryParameter, err)
		}
		return []byte(v), "", nil
	default:
		return r.cfg.Registry, "", nil
	}
}

// use makes a registry the env's, unless another env registers one of its
// identities, and builds its login verifiers. sum is its contentHash.
func (r *envRegistry) use(reg *registry.Registry, sum [sha256.Size]byte) (*registry.Registry, map[string]controlplane.LoginVerifier, error) {
	var logins map[string]controlplane.LoginVerifier
	if err := r.all.set(r.env, reg, func() error {
		var buildErr error
		logins, buildErr = r.logins.build(reg)
		return buildErr
	}); err != nil {
		return nil, nil, err
	}
	r.last = sum
	return reg, logins, nil
}

// name says where the registry comes from.
func (r *envRegistry) name() string {
	switch {
	case r.cfg.RegistryFile != "":
		return r.cfg.RegistryFile
	case r.cfg.RegistryParameter != "":
		return r.cfg.RegistryParameter
	default:
		return "APP_REGISTRY"
	}
}
