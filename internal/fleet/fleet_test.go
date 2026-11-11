package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func testRegistry(t *testing.T, ids ...string) *registry.Registry {
	t.Helper()
	y := "issuers: [{name: local, url: \"https://k8s.example.com\", jwksFile: k.json}]\nagents:\n"
	for _, id := range ids {
		y += "  - {id: " + id + ", cluster: " + id + ", region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:" + id + ":agent\"}}}\n"
	}
	r, err := registry.Parse([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func key(fp string, ageDays int) store.KeyRef {
	nb := now.Add(-time.Duration(ageDays) * 24 * time.Hour)
	return store.KeyRef{Fingerprint: fp, NotBefore: nb, NotAfter: nb.Add(365 * 24 * time.Hour)}
}

func state(id string, ago time.Duration, keys ...store.KeyRef) store.AgentState {
	return store.AgentState{
		AgentID:      id,
		LastCheckIn:  now.Add(-ago),
		KeysComplete: true,
		Controller:   protocol.Controller{KeyOrderPriority: "CertNotBefore"},
		Keys:         keys,
	}
}

func agent(t *testing.T, f Fleet, id string) Agent {
	t.Helper()
	for _, a := range f.Agents {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("agent %s not in fleet", id)
	return Agent{}
}

func TestCompute_EnvKeyIsNewestKeyHeldEverywhere(t *testing.T) {
	reg := testRegistry(t, "a", "b", "c")
	old, mid, fresh := key("SHA256:old", 60), key("SHA256:mid", 30), key("SHA256:fresh", 1)
	f := Compute("dev", reg, map[string]store.AgentState{
		// c just generated "fresh"; it has not reached a or b yet
		"a": state("a", 5*time.Second, old, mid),
		"b": state("b", 5*time.Second, old, mid),
		"c": state("c", 5*time.Second, old, mid, fresh),
	}, Keys{}, now)

	if !f.KeysInSync || f.EnvKey == nil || f.EnvKey.Fingerprint != "SHA256:mid" {
		t.Fatalf("env key = %+v, want SHA256:mid", f.EnvKey)
	}
	if got := agent(t, f, "a").MissingKeys; len(got) != 1 || got[0] != "SHA256:fresh" {
		t.Errorf("a missing = %v, want [SHA256:fresh]", got)
	}
	if got := agent(t, f, "c").MissingKeys; len(got) != 0 {
		t.Errorf("c missing = %v, want none", got)
	}
}

func TestCompute_OutOfSyncWhenNoKeyIsShared(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	f := Compute("dev", reg, map[string]store.AgentState{
		"a": state("a", time.Second, key("SHA256:a", 1)),
		"b": state("b", time.Second, key("SHA256:b", 1)),
	}, Keys{}, now)
	if f.KeysInSync || f.EnvKey != nil || f.NoUsableKey {
		t.Fatalf("expected no env key, got %+v (no usable key %v)", f.EnvKey, f.NoUsableKey)
	}
	if got := agent(t, f, "a").MissingKeys; len(got) != 1 || got[0] != "SHA256:b" {
		t.Errorf("a missing = %v", got)
	}
}

func TestCompute_DownClusterStaysInScope(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	f := Compute("dev", reg, map[string]store.AgentState{
		"a": state("a", time.Second, key("SHA256:old", 30), key("SHA256:new", 1)),
		// b is down; it must still be able to decrypt, so "new" is not usable yet
		"b": state("b", 10*time.Minute, key("SHA256:old", 30)),
	}, Keys{}, now)
	b := agent(t, f, "b")
	if b.Healthy || !b.InScope {
		t.Fatalf("b healthy=%v inScope=%v, want unhealthy and in scope", b.Healthy, b.InScope)
	}
	if f.EnvKey == nil || f.EnvKey.Fingerprint != "SHA256:old" {
		t.Fatalf("env key = %+v, want SHA256:old", f.EnvKey)
	}
}

func TestCompute_NeverCheckedInAndWrongKeyOrderAreExcluded(t *testing.T) {
	reg := testRegistry(t, "a", "b", "c")
	wrongOrder := state("c", time.Second, key("SHA256:other", 1))
	wrongOrder.Controller.KeyOrderPriority = "SecretCreationTimestamp"
	f := Compute("dev", reg, map[string]store.AgentState{
		"a": state("a", time.Second, key("SHA256:k", 5)),
		"c": wrongOrder,
	}, Keys{}, now)

	if f.EnvKey == nil || f.EnvKey.Fingerprint != "SHA256:k" {
		t.Fatalf("env key = %+v, want SHA256:k", f.EnvKey)
	}
	if b := agent(t, f, "b"); b.CheckedIn || b.InScope || !strings.Contains(strings.Join(b.Issues, ";"), "never checked in") {
		t.Errorf("b = %+v", b)
	}
	if c := agent(t, f, "c"); c.InScope || !strings.Contains(strings.Join(c.Issues, ";"), "SecretCreationTimestamp") {
		t.Errorf("c = %+v", c)
	}
}

func TestCompute_NoCheckIns(t *testing.T) {
	f := Compute("dev", testRegistry(t, "a"), nil, Keys{}, now)
	if f.KeysInSync || f.EnvKey != nil || f.NoUsableKey || len(f.Agents) != 1 {
		t.Fatalf("fleet = %+v", f)
	}
}

func TestCompute_EnvKeyTieGoesToGreaterFingerprint(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	// keys made in the same second, reported in different orders
	k1, k2, k3 := key("SHA256:aaa", 1), key("SHA256:ccc", 1), key("SHA256:bbb", 1)
	for range 20 {
		f := Compute("dev", reg, map[string]store.AgentState{
			"a": state("a", time.Second, k1, k2, k3),
			"b": state("b", time.Second, k3, k2, k1),
		}, Keys{}, now)
		if f.EnvKey == nil || f.EnvKey.Fingerprint != "SHA256:ccc" {
			t.Fatalf("env key = %+v, want SHA256:ccc", f.EnvKey)
		}
	}
}

// An agent is healthy for three of its own check-in intervals; one that does
// not report its interval for three of the default.
func TestCompute_HealthFollowsEachAgentsInterval(t *testing.T) {
	reg := testRegistry(t, "default", "slow", "slower", "fast")
	k := key("SHA256:k", 1)
	withInterval := func(s store.AgentState, seconds int) store.AgentState {
		s.CheckInIntervalSeconds = seconds
		return s
	}
	f := Compute("dev", reg, map[string]store.AgentState{
		"default": state("default", 50*time.Second, k),
		"slow":    withInterval(state("slow", 150*time.Second, k), 60),
		"slower":  withInterval(state("slower", 200*time.Second, k), 60),
		// a short interval still gets the 45-second floor
		"fast": withInterval(state("fast", 40*time.Second, k), 5),
	}, Keys{}, now)
	for id, want := range map[string]bool{"default": false, "slow": true, "slower": false, "fast": true} {
		if got := agent(t, f, id).Healthy; got != want {
			t.Errorf("%s healthy = %v, want %v", id, got, want)
		}
	}
}

// restorer is a state of an agent that can restore keys, which joined the
// env joined ago.
func restorer(s store.AgentState, joined time.Duration) store.AgentState {
	s.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityKeys}
	s.Commands = []string{protocol.CommandSeal, protocol.CommandKeysRestore}
	at := now.Add(-joined)
	s.JoinedAt = &at
	return s
}

func issues(a Agent) string { return strings.Join(a.Issues, "; ") }

func listed(t *testing.T, f Fleet, fp string) Key {
	t.Helper()
	for _, k := range f.Keys {
		if k.Fingerprint == fp {
			return k
		}
	}
	t.Fatalf("key %s not listed in %+v", fp, f.Keys)
	return Key{}
}

func TestCompute_RevokedKeyIsNeitherEnvKeyNorHeldNorMissing(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	old, revoked := key("SHA256:old", 30), key("SHA256:revoked", 1)
	gone := key("SHA256:gone", 90)
	at := now.Add(-time.Minute)
	keys := Keys{Revoked: map[string]store.RevokedKey{
		revoked.Fingerprint: {Fingerprint: revoked.Fingerprint, NotBefore: revoked.NotBefore, By: "alice", At: at},
		// revoked, and reported by no cluster any more
		gone.Fingerprint: {Fingerprint: gone.Fingerprint, NotBefore: gone.NotBefore, NotAfter: gone.NotAfter, By: "bob", At: at},
	}}
	f := Compute("dev", reg, map[string]store.AgentState{
		// both hold the revoked key, which is the newest; b also lacks
		// nothing else, a lacks nothing
		"a": state("a", time.Second, old, revoked),
		"b": state("b", time.Second, old),
	}, keys, now)

	if f.EnvKey == nil || f.EnvKey.Fingerprint != "SHA256:old" {
		t.Fatalf("env key = %+v, want SHA256:old", f.EnvKey)
	}
	if got := agent(t, f, "b").MissingKeys; len(got) != 0 {
		t.Errorf("b missing = %v; a revoked key is never missing", got)
	}
	k := listed(t, f, revoked.Fingerprint)
	if k.Status != store.KeyRevoked || k.RevokedBy != "alice" || k.RevokedAt == nil || k.EnvKey || len(k.Holders) != 1 {
		t.Errorf("revoked key = %+v", k)
	}
	if k := listed(t, f, gone.Fingerprint); k.Status != store.KeyRevoked || len(k.Holders) != 0 || !k.NotAfter.Equal(gone.NotAfter) {
		t.Errorf("revoked key no cluster reports = %+v", k)
	}
	if k := listed(t, f, old.Fingerprint); !k.EnvKey || k.Status != store.KeyActive || len(k.Holders) != 2 {
		t.Errorf("env key = %+v", k)
	}
	if f.Keys[0].Fingerprint != revoked.Fingerprint || f.Keys[len(f.Keys)-1].Fingerprint != gone.Fingerprint {
		t.Errorf("keys are not newest first: %+v", f.Keys)
	}

	// revoking every shared key leaves no env key, and no cluster missing
	// one: sealing needs a new key, and says so
	keys.Revoked[old.Fingerprint] = store.RevokedKey{Fingerprint: old.Fingerprint}
	f = Compute("dev", reg, map[string]store.AgentState{
		"a": state("a", time.Second, old, revoked),
		"b": state("b", time.Second, old),
	}, keys, now)
	if f.EnvKey != nil || f.KeysInSync || !f.NoUsableKey {
		t.Errorf("env key = %+v, no usable key %v; want none, and a new key needed", f.EnvKey, f.NoUsableKey)
	}
	if _, err := ChooseSealer(f, nil, nil); !errors.Is(err, ErrNoUsableKey) {
		t.Errorf("ChooseSealer: %v, want ErrNoUsableKey", err)
	}
}

func TestCompute_FutureDatedKeyIsNotUsedUntilItsTime(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	current := key("SHA256:current", 10)
	planted := store.KeyRef{Fingerprint: "SHA256:planted", NotBefore: now.Add(FutureSkew + time.Minute), NotAfter: now.AddDate(80, 0, 0)}
	// within the skew: a clock a little ahead is fine
	skewed := store.KeyRef{Fingerprint: "SHA256:skewed", NotBefore: now.Add(FutureSkew - time.Minute), NotAfter: now.AddDate(1, 0, 0)}
	states := map[string]store.AgentState{
		"a": state("a", time.Second, current, skewed, planted),
		"b": state("b", time.Second, current, skewed, planted),
	}
	f := Compute("dev", reg, states, Keys{}, now)
	if f.EnvKey == nil || f.EnvKey.Fingerprint != skewed.Fingerprint {
		t.Fatalf("env key = %+v, want the skewed key", f.EnvKey)
	}
	// a future-dated key alone is no env key: a new key is needed
	only := map[string]store.AgentState{"a": state("a", time.Second, planted), "b": state("b", time.Second, planted)}
	if f := Compute("dev", reg, only, Keys{}, now); f.EnvKey != nil || !f.NoUsableKey {
		t.Errorf("with only a future-dated key: env key %+v, no usable key %v", f.EnvKey, f.NoUsableKey)
	}
	if k := listed(t, f, planted.Fingerprint); !k.FutureDated || k.EnvKey {
		t.Errorf("planted key = %+v", k)
	}
	if !strings.Contains(issues(agent(t, f, "a")), "SHA256:planted valid only from") {
		t.Errorf("a issues = %v", agent(t, f, "a").Issues)
	}

	// held by one cluster only, it is not missing anywhere, so never restored
	states["b"] = state("b", time.Second, current, skewed)
	f = Compute("dev", reg, states, Keys{}, now)
	if got := agent(t, f, "b").MissingKeys; len(got) != 0 {
		t.Errorf("b missing = %v", got)
	}
	// once its time comes, it is a key like any other
	later := planted.NotBefore.Add(time.Second)
	if f := Compute("dev", reg, states, Keys{}, later); len(agent(t, f, "b").MissingKeys) != 1 {
		t.Errorf("b missing after the key's NotBefore = %v", agent(t, f, "b").MissingKeys)
	}
}

func TestCompute_JoiningClusterIsLeftOutOfTheEnvKey(t *testing.T) {
	reg := testRegistry(t, "a", "b", "new")
	shared, fresh := key("SHA256:shared", 30), key("SHA256:fresh", 0)
	escrowed := Keys{Escrow: map[string][]string{shared.Fingerprint: {"a"}}}
	states := map[string]store.AgentState{
		"a": restorer(state("a", time.Second, shared), 48*time.Hour),
		"b": state("b", time.Second, shared),
		// a new cluster reports only the key its controller just made
		"new": restorer(state("new", time.Second, fresh), 5*time.Minute),
	}

	f := Compute("dev", reg, states, escrowed, now)
	n := agent(t, f, "new")
	if !n.Joining || !strings.Contains(issues(n), "joined 5 minutes ago; left out of the env key") {
		t.Fatalf("new = joining %v, issues %v", n.Joining, n.Issues)
	}
	if f.EnvKey == nil || f.EnvKey.Fingerprint != shared.Fingerprint {
		t.Fatalf("env key = %+v, want the shared key", f.EnvKey)
	}
	// the new cluster is still sent the shared key, and its key the others
	if got := n.MissingKeys; len(got) != 1 || got[0] != shared.Fingerprint {
		t.Errorf("new missing = %v", got)
	}
	if got := agent(t, f, "a").MissingKeys; len(got) != 1 || got[0] != fresh.Fingerprint {
		t.Errorf("a missing = %v", got)
	}
	// it cannot seal: it does not hold the env key
	if _, err := ChooseSealer(f, nil, nil); err != nil {
		t.Errorf("ChooseSealer: %v", err)
	}
	for _, a := range f.Agents {
		if a.ID == "new" && canSeal(a, f.EnvKey.Fingerprint) {
			t.Error("a joining cluster may seal")
		}
	}

	t.Run("not escrowed", func(t *testing.T) {
		f := Compute("dev", reg, states, Keys{}, now)
		if n := agent(t, f, "new"); n.Joining || !strings.Contains(issues(n), "no escrowed copy yet") {
			t.Errorf("new = joining %v, issues %v", n.Joining, n.Issues)
		}
		if f.EnvKey != nil {
			t.Errorf("env key = %+v; restore cannot catch the cluster up", f.EnvKey)
		}
	})
	t.Run("cannot restore", func(t *testing.T) {
		s := maps.Clone(states)
		sealOnly := state("new", time.Second, fresh)
		sealOnly.JoinedAt = s["new"].JoinedAt
		s["new"] = sealOnly
		f := Compute("dev", reg, s, escrowed, now)
		if n := agent(t, f, "new"); n.Joining || !strings.Contains(issues(n), "needs the keys capability") {
			t.Errorf("new = joining %v, issues %v", n.Joining, n.Issues)
		}
	})
	t.Run("key order unknown", func(t *testing.T) {
		// the agent refuses to restore when it cannot tell its controller's
		// key order, so the cluster is not given the grace either
		s := maps.Clone(states)
		unknown := s["new"]
		unknown.Controller.KeyOrderPriority = ""
		s["new"] = unknown
		f := Compute("dev", reg, s, escrowed, now)
		n := agent(t, f, "new")
		if n.Joining || n.CanRestore() || !n.InScope {
			t.Errorf("new = joining %v, can restore %v, in scope %v", n.Joining, n.CanRestore(), n.InScope)
		}
		if !strings.Contains(issues(n), "key order unknown") || !strings.Contains(issues(n), "its key order is unknown") {
			t.Errorf("new issues = %v", n.Issues)
		}
		// an agent that cannot restore anyway is not told about it
		if b := agent(t, f, "b"); strings.Contains(issues(b), "key order") {
			t.Errorf("b issues = %v", b.Issues)
		}
	})
	t.Run("after the window", func(t *testing.T) {
		later := now.Add(JoinWindow)
		s := maps.Clone(states)
		for id, st := range s {
			st.LastCheckIn = later
			s[id] = st
		}
		f := Compute("dev", reg, s, escrowed, later)
		if n := agent(t, f, "new"); n.Joining || !strings.Contains(issues(n), "still lacks the key every other cluster holds") {
			t.Errorf("new = joining %v, issues %v", n.Joining, n.Issues)
		}
		if f.EnvKey != nil {
			t.Errorf("env key = %+v, want none once the cluster counts again", f.EnvKey)
		}
	})
	t.Run("first clusters of an env", func(t *testing.T) {
		s := map[string]store.AgentState{
			"a": restorer(state("a", time.Second, shared), time.Minute),
			"b": restorer(state("b", time.Second, fresh), time.Minute),
		}
		f := Compute("dev", testRegistry(t, "a", "b"), s, Keys{Escrow: map[string][]string{shared.Fingerprint: {"a"}, fresh.Fingerprint: {"b"}}}, now)
		if agent(t, f, "a").Joining || agent(t, f, "b").Joining {
			t.Error("the first clusters of an env have no one to catch up with")
		}
	})
	t.Run("holding the env key", func(t *testing.T) {
		s := maps.Clone(states)
		s["new"] = restorer(state("new", time.Second, shared, fresh), 5*time.Minute)
		f := Compute("dev", reg, s, escrowed, now)
		if agent(t, f, "new").Joining {
			t.Error("a cluster holding the env key is not joining")
		}
		if f.EnvKey == nil || f.EnvKey.Fingerprint != shared.Fingerprint {
			t.Errorf("env key = %+v", f.EnvKey)
		}
	})
}

// keySet returns n keys made a day apart, the newest ageDays old, oldest
// first, as agents report them.
func keySet(prefix string, n, ageDays int) []store.KeyRef {
	out := make([]store.KeyRef, n)
	for i := range n {
		out[i] = key(fmt.Sprintf("SHA256:%s-%03d", prefix, i), ageDays+n-1-i)
	}
	return out
}

func TestCompute_KeyLimit(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	fresh := key("SHA256:fresh", 1)
	// b holds old keys a reported but were left out over the limit, and
	// one a never had
	shared := keySet("shared", protocol.MaxKeys+20, 2)
	never := key("SHA256:never", 1000)
	a := state("a", time.Second, append(slices.Clone(shared[20:]), fresh)...)
	a.KeysReported = len(shared) + 1
	upTo := shared[19].NotBefore
	a.DroppedUpTo = &upTo
	b := state("b", time.Second, append(slices.Clone(shared[len(shared)-199:]), fresh)...)
	f := Compute("dev", reg, map[string]store.AgentState{"a": a, "b": b}, Keys{}, now)

	// a may hold the keys left out of its report, so it is not sent them
	if got := agent(t, f, "a").MissingKeys; len(got) != 0 {
		t.Errorf("a missing = %v, want none", got)
	}
	if ga := agent(t, f, "a"); ga.KeysReported != protocol.MaxKeys+21 || ga.KeysDropped != 20 ||
		!strings.Contains(issues(ga), "the 20 oldest are left out") {
		t.Errorf("a = reported %d, dropped %d, issues %v", ga.KeysReported, ga.KeysDropped, ga.Issues)
	}
	if !strings.Contains(issues(agent(t, f, "b")), "200 keys, 80% of the 250 kept") {
		t.Errorf("b issues = %v", agent(t, f, "b").Issues)
	}
	if f.KeyLimit != protocol.MaxKeys || f.EnvKey == nil || f.EnvKey.Fingerprint != fresh.Fingerprint {
		t.Errorf("limit %d, env key %+v", f.KeyLimit, f.EnvKey)
	}

	// a key newer than those left out is missing as usual
	b.Keys = append(b.Keys, key("SHA256:newer", 0))
	f = Compute("dev", reg, map[string]store.AgentState{"a": a, "b": b}, Keys{}, now)
	if got := agent(t, f, "a").MissingKeys; !slices.Equal(got, []string{"SHA256:newer"}) {
		t.Errorf("a missing = %v, want [SHA256:newer]", got)
	}
	// but not one older than all of them
	b.Keys = append(b.Keys[:len(b.Keys)-1], never)
	f = Compute("dev", reg, map[string]store.AgentState{"a": a, "b": b}, Keys{}, now)
	if got := agent(t, f, "a").MissingKeys; len(got) != 0 {
		t.Errorf("a missing = %v, want none", got)
	}

	b = state("b", time.Second, keySet("half", protocol.MaxKeys/2, 1)...)
	f = Compute("dev", testRegistry(t, "b"), map[string]store.AgentState{"b": b}, Keys{}, now)
	if !strings.Contains(issues(agent(t, f, "b")), "125 keys, over half of the 250") {
		t.Errorf("b issues = %v", agent(t, f, "b").Issues)
	}
}

// cleanupRegistry registers a and b with cleanup, c without.
func cleanupRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	y := "issuers: [{name: local, url: \"https://k8s.example.com\", jwksFile: k.json}]\nagents:\n"
	for _, a := range []struct{ id, caps string }{{"a", "seal, keys, cleanup"}, {"b", "seal, keys, cleanup"}, {"c", "seal, keys"}} {
		y += "  - {id: " + a.id + ", cluster: " + a.id + ", region: use1, capabilities: [" + a.caps + "], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:" + a.id + ":agent\"}}}\n"
	}
	r, err := registry.Parse([]byte(y), "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func counting(id string, keys ...store.KeyRef) store.AgentState {
	s := state(id, time.Second, keys...)
	s.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityKeys, protocol.CapabilityCleanup}
	return s
}

func TestCompute_KeyReferences(t *testing.T) {
	reg := cleanupRegistry(t)
	used, unused := key("SHA256:used", 30), key("SHA256:unused", 60)
	counted := now.Add(-time.Minute)
	f := Compute("dev", reg, map[string]store.AgentState{
		"a": counting("a", unused, used),
		"b": counting("b", unused, used),
		"c": state("c", time.Second, unused, used),
	}, Keys{Usage: map[string]store.KeyUsage{
		"a": {AgentID: "a", CountedAt: counted, Namespaces: []string{"apps", "sealed-secrets"}, SealedSecrets: 3, Values: 5, Unmatched: 2,
			Keys: map[string]store.KeyUse{used.Fingerprint: {Values: 3, SealedSecrets: 2}}},
		"b": {AgentID: "b", CountedAt: counted, SealedSecrets: 1, Values: 1,
			Keys: map[string]store.KeyUse{used.Fingerprint: {Values: 1, SealedSecrets: 1}}},
	}}, now)

	refs := listed(t, f, used.Fingerprint).References
	if refs.Values != 4 || refs.SealedSecrets != 3 || len(refs.Clusters) != 2 || !slices.Equal(refs.Uncounted, []string{"c"}) {
		t.Fatalf("references of the used key = %+v", refs)
	}
	if c := refs.Clusters[0]; c.Agent != "a" || c.Cluster != "a" || c.Values != 3 || c.SealedSecrets != 2 || !c.CountedAt.Equal(counted) {
		t.Errorf("a's references = %+v", c)
	}
	// clusters that counted none are listed too
	if refs := listed(t, f, unused.Fingerprint).References; refs.Values != 0 || len(refs.Clusters) != 2 || refs.Clusters[1].Values != 0 {
		t.Errorf("references of the unused key = %+v", refs)
	}
	// active keys are not offered for deletion
	if k := listed(t, f, unused.Fingerprint); k.Deletable || k.DeleteBlocked != BlockedActive {
		t.Errorf("active key: deletable %v, blocked %q", k.Deletable, k.DeleteBlocked)
	}

	a := agent(t, f, "a")
	if u := a.KeyUsage; u == nil || !u.CountedAt.Equal(counted) || u.Values != 5 || u.Unmatched != 2 || !slices.Equal(u.Namespaces, []string{"apps", "sealed-secrets"}) {
		t.Errorf("a's usage = %+v", a.KeyUsage)
	}
	if !slices.ContainsFunc(a.Issues, func(s string) bool {
		return s == "2 values in this cluster's SealedSecrets match none of its keys: the controller cannot decrypt them"
	}) {
		t.Errorf("a's issues = %q", a.Issues)
	}
	// every namespace is null, not an empty list
	if u := agent(t, f, "b").KeyUsage; u == nil || u.Namespaces != nil {
		t.Errorf("b's usage = %+v", u)
	}
	if u := agent(t, f, "c").KeyUsage; u != nil {
		t.Errorf("c never counted, usage = %+v", u)
	}
	b, err := json.Marshal(agent(t, f, "b").KeyUsage)
	if err != nil || !strings.Contains(string(b), `"namespaces":null`) {
		t.Errorf("b's usage as JSON = %s, %v", b, err)
	}
}

func TestCompute_DeleteGate(t *testing.T) {
	reg := cleanupRegistry(t)
	k := key("SHA256:k", 60)
	revokedAt := now.Add(-30 * time.Minute)
	after, before, stale := now.Add(-time.Minute), revokedAt.Add(-time.Minute), now.Add(-UsageFresh-time.Second)
	usage := func(at time.Time, values int, err string) store.KeyUsage {
		u := store.KeyUsage{CountedAt: at, Error: err}
		if values > 0 {
			u.Values, u.SealedSecrets = values, 1
			u.Keys = map[string]store.KeyUse{k.Fingerprint: {Values: values, SealedSecrets: 1}}
		}
		return u
	}
	states := func(withC bool) map[string]store.AgentState {
		out := map[string]store.AgentState{"a": counting("a", k), "b": counting("b", k)}
		if withC {
			out["c"] = state("c", time.Second, k)
		}
		return out
	}
	cases := map[string]struct {
		states  map[string]store.AgentState
		usage   map[string]store.KeyUsage
		blocked string
	}{
		"every cluster counted none since it was revoked": {
			states: states(false), usage: map[string]store.KeyUsage{"a": usage(after, 0, ""), "b": usage(after, 0, "")},
		},
		// a cluster down, but its count recent, still counts
		"a cluster down with a recent count": {
			states: map[string]store.AgentState{"a": counting("a", k), "b": func() store.AgentState {
				s := counting("b", k)
				s.LastCheckIn = now.Add(-20 * time.Minute)
				return s
			}()},
			usage: map[string]store.KeyUsage{"a": usage(after, 0, ""), "b": usage(after, 0, "")},
		},
		"values sealed with it": {
			states: states(false), usage: map[string]store.KeyUsage{"a": usage(after, 3, ""), "b": usage(after, 0, "")},
			blocked: "3 values in 1 SealedSecret use it (a).",
		},
		"one value": {
			states: states(false), usage: map[string]store.KeyUsage{"a": usage(after, 1, ""), "b": usage(stale, 0, "")},
			blocked: "1 value in 1 SealedSecret uses it (a).",
		},
		// references block whatever else holds
		"values in two clusters, and a cluster without cleanup": {
			states:  states(true),
			usage:   map[string]store.KeyUsage{"a": usage(after, 12, ""), "b": usage(before, 2, "")},
			blocked: "14 values in 2 SealedSecrets use it (a, b).",
		},
		"a cluster without cleanup": {
			states: states(true), usage: map[string]store.KeyUsage{"a": usage(after, 0, ""), "b": usage(after, 0, "")},
			blocked: "c cannot count the values sealed with it: it needs the cleanup capability.",
		},
		"a failed count": {
			states: states(false), usage: map[string]store.KeyUsage{"a": usage(after, 0, "forbidden"), "b": usage(after, 0, "")},
			blocked: "The last count of the values sealed with it failed in a.",
		},
		"a count from before the revocation": {
			states: states(false), usage: map[string]store.KeyUsage{"a": usage(before, 0, ""), "b": usage(after, 0, "")},
			blocked: "Waiting for a to count the values sealed with it since it was revoked; clusters count every few minutes.",
		},
		"a count over an hour old, and one never made": {
			states: states(false), usage: map[string]store.KeyUsage{"a": usage(stale, 0, "")},
			blocked: "Waiting for a and b to count the values sealed with it since it was revoked; clusters count every few minutes.",
		},
		"no cluster checked in": {
			states:  map[string]store.AgentState{},
			blocked: "No cluster has checked in, so none has counted the values sealed with it.",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := Compute("dev", reg, tc.states, Keys{
				Revoked: map[string]store.RevokedKey{k.Fingerprint: {Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, By: "alice", At: revokedAt}},
				Usage:   tc.usage,
			}, now)
			got := listed(t, f, k.Fingerprint)
			if got.DeleteBlocked != tc.blocked || got.Deletable != (tc.blocked == "") {
				t.Fatalf("deletable %v, blocked %q; want %q", got.Deletable, got.DeleteBlocked, tc.blocked)
			}
		})
	}
}

// A deleted key is a revoked key for everything else; it is listed with
// who deleted it while a cluster still reports it or it can be reinstated.
func TestCompute_DeletedKey(t *testing.T) {
	reg := cleanupRegistry(t)
	old, deleted, gone := key("SHA256:old", 60), key("SHA256:deleted", 1), key("SHA256:gone", 90)
	deletedAt, purgeAt := now.Add(-time.Hour), now.Add(29*24*time.Hour)
	past := now.Add(-time.Second)
	record := func(k store.KeyRef, purge *time.Time) store.RevokedKey {
		return store.RevokedKey{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, By: "alice", At: deletedAt.Add(-time.Hour),
			Status: store.KeyDeleted, DeletedBy: "bob", DeletedAt: &deletedAt, PurgeAt: purge}
	}
	keys := Keys{Revoked: map[string]store.RevokedKey{
		deleted.Fingerprint: record(deleted, &purgeAt),
		gone.Fingerprint:    record(gone, &past),
		old.Fingerprint:     record(old, &past),
	}}
	f := Compute("dev", reg, map[string]store.AgentState{
		"a": counting("a", old, deleted),
		"b": counting("b", key("SHA256:mid", 30)),
	}, keys, now)

	if f.EnvKey != nil || slices.Contains(agent(t, f, "b").MissingKeys, deleted.Fingerprint) {
		t.Fatalf("env key %+v, b missing %v", f.EnvKey, agent(t, f, "b").MissingKeys)
	}
	k := listed(t, f, deleted.Fingerprint)
	if k.Status != store.KeyDeleted || k.RevokedBy != "alice" || k.DeletedBy != "bob" || k.DeletedAt == nil || k.PurgeAt == nil || k.Purged || k.Deletable || k.DeleteBlocked != BlockedDeleted {
		t.Errorf("deleted key = %+v", k)
	}
	// purged but still in a cluster: listed, so its removal shows
	if k := listed(t, f, old.Fingerprint); k.Status != store.KeyDeleted || !k.Purged || len(k.Holders) != 1 {
		t.Errorf("purged key a cluster holds = %+v", k)
	}
	// purged and in no cluster: left out
	if _, ok := f.Key(gone.Fingerprint); ok {
		t.Error("a purged key no cluster holds is listed")
	}
}

// A reinstated key may be in no cluster any more: every in-scope cluster
// lacks it, so restore brings it back, and it is listed meanwhile.
func TestCompute_ReinstatedKeyIsMissingWhereNotHeld(t *testing.T) {
	reg := testRegistry(t, "a", "b")
	env, back := key("SHA256:env", 1), key("SHA256:back", 30)
	keys := Keys{Reinstated: map[string]store.ReinstatedKey{
		back.Fingerprint: {Fingerprint: back.Fingerprint, NotBefore: back.NotBefore, NotAfter: back.NotAfter, By: "alice", At: now},
	}}
	f := Compute("dev", reg, map[string]store.AgentState{
		"a": state("a", time.Second, env),
		"b": state("b", time.Second, back, env),
	}, keys, now)
	if got := agent(t, f, "a").MissingKeys; !slices.Equal(got, []string{back.Fingerprint}) {
		t.Errorf("a missing = %v", got)
	}
	if got := agent(t, f, "b").MissingKeys; len(got) != 0 {
		t.Errorf("b missing = %v", got)
	}
	f = Compute("dev", reg, map[string]store.AgentState{
		"a": state("a", time.Second, env),
		"b": state("b", time.Second, env),
	}, keys, now)
	if k := listed(t, f, back.Fingerprint); k.Status != store.KeyActive || len(k.Holders) != 0 || k.EnvKey {
		t.Errorf("reinstated key held by none = %+v", k)
	}
	if f.EnvKey == nil || f.EnvKey.Fingerprint != env.Fingerprint || len(agent(t, f, "b").MissingKeys) != 1 {
		t.Errorf("env key %+v, b missing %v", f.EnvKey, agent(t, f, "b").MissingKeys)
	}
}
