package fleet

import (
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
		y += "  - {id: " + id + ", cluster: " + id + ", region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:" + id + ":agent\"}}}\n"
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
	}, now)

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
	}, now)
	if f.KeysInSync || f.EnvKey != nil {
		t.Fatalf("expected no env key, got %+v", f.EnvKey)
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
	}, now)
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
	}, now)

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
	f := Compute("dev", testRegistry(t, "a"), nil, now)
	if f.KeysInSync || f.EnvKey != nil || len(f.Agents) != 1 {
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
		}, now)
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
	}, now)
	for id, want := range map[string]bool{"default": false, "slow": true, "slower": false, "fast": true} {
		if got := agent(t, f, id).Healthy; got != want {
			t.Errorf("%s healthy = %v, want %v", id, got, want)
		}
	}
}
