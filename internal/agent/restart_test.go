package agent

import (
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

func TestRestoreState(t *testing.T) {
	base := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	cert := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), base.Add(-time.Hour))
	k, _, err := keys.ParseCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	restored := *restoredSecret("restored", cert, base)
	own := *keySecret("own", cert, true)
	terminating := *controllerPod("terminating", base.Add(-time.Hour), true)
	terminating.DeletionTimestamp = &metav1.Time{Time: base}
	pod := func(name string, created time.Duration, ready bool) corev1.Pod {
		return *controllerPod(name, base.Add(created), ready)
	}

	cases := map[string]struct {
		secrets []corev1.Secret
		pods    []corev1.Pod
		active  string
		pending bool
		stale   []string
		// unsure: no pod is ready, so what is loaded cannot be told
		unsure bool
	}{
		"pod from before the key": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("old", -time.Minute, true)},
			pending: true, stale: []string{"old"},
		},
		// creation times are whole seconds: the same second may be before
		"pod from the same second": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("same", 0, true)},
			pending: true, stale: []string{"same"},
		},
		"pod from a later second": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("new", time.Second, true)},
		},
		"new pod not ready yet": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("new", time.Second, false)},
			pending: true, unsure: true,
		},
		// a restart: the old pod is going away, the new one not ready yet
		"old pod terminating, new pod not ready": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{terminating, pod("new", time.Second, false)},
			pending: true, unsure: true,
		},
		"an old pod still running beside a new one": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("new", time.Second, true), pod("old", -time.Minute, true)},
			pending: true, stale: []string{"old"},
		},
		"a terminating pod is going away": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("new", time.Second, true), terminating},
		},
		"no pods": {
			secrets: []corev1.Secret{restored},
			pending: true, unsure: true,
		},
		// the controller seals with it, so it has loaded it
		"the active key": {
			secrets: []corev1.Secret{restored}, pods: []corev1.Pod{pod("old", -time.Minute, true)}, active: k.Fingerprint,
		},
		// keys the agent did not restore are not its to track
		"not restored by the agent": {
			secrets: []corev1.Secret{own}, pods: []corev1.Pod{pod("old", -time.Minute, true)},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st := restoreState(tc.secrets, tc.pods, tc.active)
			if got := len(st.pending) > 0; got != tc.pending {
				t.Errorf("pending = %v, want %v", st.fingerprints(), tc.pending)
			}
			if st.unsure != tc.unsure {
				t.Errorf("unsure = %v, want %v", st.unsure, tc.unsure)
			}
			var stale []string
			for _, p := range st.stale {
				stale = append(stale, p.Name)
			}
			if !slices.Equal(stale, tc.stale) {
				t.Errorf("stale = %v, want %v", stale, tc.stale)
			}
		})
	}
}
