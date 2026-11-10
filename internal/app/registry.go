package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"golang.org/x/time/rate"

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
	stsLimit *rate.Limiter
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
	// last is the registry in force, as read
	last []byte
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
	return r.use(data, baseDir)
}

// reload reads the registry again, for controlplane.Options.ReloadRegistry.
// It returns a nil registry when it has not changed.
func (r *envRegistry) reload(ctx context.Context) (*registry.Registry, map[string]controlplane.LoginVerifier, error) {
	data, baseDir, err := r.source(ctx)
	if err != nil {
		return nil, nil, err
	}
	// the configuration trims the registry it read at start
	if bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(r.last)) {
		return nil, nil, nil
	}
	return r.use(data, baseDir)
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

// use validates a registry and builds its login verifiers.
func (r *envRegistry) use(data []byte, baseDir string) (*registry.Registry, map[string]controlplane.LoginVerifier, error) {
	reg, err := registry.Parse(data, baseDir)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid agent registry %s: %w", r.name(), err)
	}
	var logins map[string]controlplane.LoginVerifier
	if err := r.all.set(r.env, reg, func() error {
		var buildErr error
		logins, buildErr = r.logins.build(reg)
		return buildErr
	}); err != nil {
		return nil, nil, err
	}
	r.last = data
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
