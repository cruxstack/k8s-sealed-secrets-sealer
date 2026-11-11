package fleet

import (
	"errors"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

func sealer(id, region string, ago time.Duration, keys ...store.KeyRef) Agent {
	last := now.Add(-ago)
	return Agent{
		ID: id, Cluster: "cluster-" + id, Region: region,
		RegisteredCapabilities: []string{protocol.CapabilitySeal},
		CheckedIn:              true, Healthy: ago <= HealthyWithin, InScope: true, LastCheckIn: &last,
		Capabilities: []string{protocol.CapabilitySeal},
		Commands:     []string{protocol.CommandSeal},
		Keys:         keys,
	}
}

func TestChooseSealer(t *testing.T) {
	env, other := key("SHA256:env", 30), key("SHA256:new", 1)
	envKey := env
	fleet := func(agents ...Agent) Fleet {
		return Fleet{Env: "dev", EnvKey: &envKey, KeysInSync: true, Agents: agents}
	}

	cases := map[string]struct {
		f        Fleet
		regions  []string
		inFlight map[string]int
		want     string
	}{
		"the target region first": {
			f:       fleet(sealer("a", "use1", time.Second, env), sealer("b", "use2", 2*time.Second, env)),
			regions: []string{"use2"},
			want:    "b",
		},
		"then the fewest commands in flight": {
			f:        fleet(sealer("a", "use1", time.Second, env), sealer("b", "use1", 2*time.Second, env)),
			regions:  []string{"use1"},
			inFlight: map[string]int{"a": 2, "b": 1},
			want:     "b",
		},
		"then the most recent check-in": {
			f:    fleet(sealer("a", "use1", 3*time.Second, env), sealer("b", "use1", time.Second, env)),
			want: "b",
		},
		"another region when none in the target's can seal": {
			f:       fleet(sealer("a", "use1", time.Hour, env), sealer("b", "use2", time.Second, env)),
			regions: []string{"use1"},
			want:    "b",
		},
		"an agent without the env key is skipped": {
			f:    fleet(sealer("a", "use1", time.Second, other), sealer("b", "use1", 9*time.Second, env, other)),
			want: "b",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ChooseSealer(tc.f, tc.regions, tc.inFlight)
			if err != nil || got.ID != tc.want {
				t.Fatalf("ChooseSealer = %s, %v; want %s", got.ID, err, tc.want)
			}
		})
	}

	// not able to seal: unhealthy, not registered for seal, not reporting it,
	// or not handling seal.v1
	unhealthy := sealer("a", "use1", time.Hour, env)
	unregistered := sealer("b", "use1", time.Second, env)
	unregistered.RegisteredCapabilities = nil
	unreported := sealer("c", "use1", time.Second, env)
	unreported.Capabilities = nil
	oldAgent := sealer("d", "use1", time.Second, env)
	oldAgent.Commands = []string{protocol.CommandKeysRestore}
	if _, err := ChooseSealer(fleet(unhealthy, unregistered, unreported, oldAgent), nil, nil); !errors.Is(err, ErrNoSealer) {
		t.Fatalf("no candidates: %v", err)
	}

	// no env key: name the clusters missing keys
	a, b := sealer("a", "use1", time.Second, env), sealer("b", "use1", time.Second, other)
	a.MissingKeys, b.MissingKeys = []string{other.Fingerprint}, []string{env.Fingerprint}
	_, err := ChooseSealer(Fleet{Agents: []Agent{b, a}}, nil, nil)
	var outOfSync *KeysOutOfSyncError
	if !errors.As(err, &outOfSync) || len(outOfSync.Clusters) != 2 || outOfSync.Clusters[0] != "cluster-a" {
		t.Fatalf("out of sync: %v", err)
	}
	// no env key, and none missing: every shared key is unusable
	if _, err := ChooseSealer(Fleet{NoUsableKey: true, Agents: []Agent{sealer("a", "use1", time.Second, env)}}, nil, nil); !errors.Is(err, ErrNoUsableKey) {
		t.Fatalf("no usable key: %v", err)
	}
}

func TestChooseResealer(t *testing.T) {
	env := key("SHA256:env", 30)
	envKey := env
	resealer := func(id, region string) Agent {
		a := sealer(id, region, time.Second, env)
		a.RegisteredCapabilities = []string{protocol.CapabilityKeys, protocol.CapabilityReseal}
		a.Capabilities = []string{protocol.CapabilityKeys, protocol.CapabilityReseal}
		a.Commands = []string{protocol.CommandKeysRestore, protocol.CommandReseal}
		a.Controller = &protocol.Controller{ActiveFingerprint: env.Fingerprint}
		return a
	}
	// a sealer without reseal is no candidate, nor one registered without
	// it, or one that does not handle reseal.v1
	unregistered := resealer("c", "use2")
	unregistered.RegisteredCapabilities = []string{protocol.CapabilityKeys}
	old := resealer("d", "use2")
	old.Commands = []string{protocol.CommandKeysRestore}
	f := Fleet{EnvKey: &envKey, Agents: []Agent{sealer("a", "use2", time.Second, env), resealer("b", "use1"), unregistered, old}}
	got, err := ChooseResealer(f, []string{"use2"}, nil)
	if err != nil || got.ID != "b" {
		t.Fatalf("ChooseResealer = %s, %v", got.ID, err)
	}
	// an agent whose controller seals with another key, made in the same
	// second say, is passed over for one whose seals with the env key
	other := resealer("a-other", "use2")
	other.Controller = &protocol.Controller{ActiveFingerprint: "SHA256:own"}
	f.Agents = append(f.Agents, other)
	if got, err := ChooseResealer(f, []string{"use2"}, nil); err != nil || got.ID != "b" {
		t.Fatalf("ChooseResealer with an agent sealing with another key = %s, %v", got.ID, err)
	}
	f.Agents = []Agent{sealer("a", "use2", time.Second, env), other}
	if _, err := ChooseResealer(f, nil, nil); !errors.Is(err, ErrEnvKeyNotActive) {
		t.Fatalf("no controller seals with the env key: %v", err)
	}
	f.Agents = f.Agents[:1]
	if _, err := ChooseResealer(f, nil, nil); !errors.Is(err, ErrNoResealer) {
		t.Fatalf("no candidates: %v", err)
	}
	if _, err := ChooseSealer(f, nil, nil); err != nil {
		t.Fatalf("the sealer still seals: %v", err)
	}
}
