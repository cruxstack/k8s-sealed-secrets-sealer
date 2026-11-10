package controlplane

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

func TestLimitKeys(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	refs := func(n int) []store.KeyRef {
		out := make([]store.KeyRef, n)
		for i := range n {
			out[i] = store.KeyRef{Fingerprint: fmt.Sprintf("SHA256:%02d", i), NotBefore: base.Add(time.Duration(i) * time.Hour)}
		}
		return out
	}
	fps := func(ks []store.KeyRef) []string {
		var out []string
		for _, k := range ks {
			out = append(out, k.Fingerprint)
		}
		return out
	}

	if kept, upTo := limitKeys(refs(3), nil, 3); len(kept) != 3 || upTo != nil {
		t.Errorf("at the limit: kept %v, up to %v", fps(kept), upTo)
	}
	// reported newest first: the newest are kept, oldest first
	reported := refs(5)
	slices.Reverse(reported)
	kept, upTo := limitKeys(reported, nil, 3)
	if !slices.Equal(fps(kept), []string{"SHA256:02", "SHA256:03", "SHA256:04"}) || upTo == nil || !upTo.Equal(base.Add(time.Hour)) {
		t.Errorf("over the limit: kept %v, up to %v", fps(kept), upTo)
	}
	// revoked keys are left out first, and do not move the cutoff
	revoked := map[string]store.RevokedKey{"SHA256:04": {}, "SHA256:00": {}}
	kept, upTo = limitKeys(refs(5), revoked, 3)
	if !slices.Equal(fps(kept), []string{"SHA256:01", "SHA256:02", "SHA256:03"}) || upTo != nil {
		t.Errorf("with revoked keys: kept %v, up to %v", fps(kept), upTo)
	}
	// keys made in the same second keep the greater fingerprint
	tied := []store.KeyRef{{Fingerprint: "SHA256:a", NotBefore: base}, {Fingerprint: "SHA256:c", NotBefore: base}, {Fingerprint: "SHA256:b", NotBefore: base}}
	if kept, _ := limitKeys(tied, nil, 2); !slices.Equal(fps(kept), []string{"SHA256:c", "SHA256:b"}) {
		t.Errorf("tied: kept %v", fps(kept))
	}
}

func TestJoinedAt(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	earlier := now.Add(-48 * time.Hour)
	ka, kb := store.KeyRef{Fingerprint: "SHA256:a"}, store.KeyRef{Fingerprint: "SHA256:b"}
	prev := store.AgentState{Keys: []store.KeyRef{ka}, KeysComplete: true, JoinedAt: &earlier}
	report := func(complete bool, ks ...store.KeyRef) store.AgentState {
		return store.AgentState{Keys: ks, KeysComplete: complete}
	}
	cases := map[string]struct {
		prev  store.AgentState
		seen  bool
		state store.AgentState
		want  *time.Time
	}{
		"first check-in":       {store.AgentState{}, false, report(true, kb), &now},
		"same cluster":         {prev, true, report(true, ka, kb), &earlier},
		"rebuilt cluster":      {prev, true, report(true, kb), &now},
		"seen before recorded": {store.AgentState{Keys: []store.KeyRef{ka}, KeysComplete: true}, true, report(true, ka), nil},
		// without the keys capability an agent reports only its active
		// key, which changes when the controller renews
		"active key only": {store.AgentState{Keys: []store.KeyRef{ka}, JoinedAt: &earlier}, true, report(false, kb), &earlier},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := joinedAt(tc.prev, tc.seen, tc.state, now)
			if (got == nil) != (tc.want == nil) || (got != nil && !got.Equal(*tc.want)) {
				t.Fatalf("joinedAt = %v, want %v", got, tc.want)
			}
		})
	}
}
