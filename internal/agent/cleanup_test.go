package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// cleanupCluster is a cluster whose agent has keys and cleanup, with its
// controller (one pod, an hour old) watching its own namespace and "apps".
type cleanupCluster struct {
	*cluster
	sealedSecrets *dynamicfake.FakeDynamicClient
	cleanup       *Cleanup
}

func newCleanupCluster(t *testing.T, active []byte, secrets []runtime.Object, sealed ...runtime.Object) *cleanupCluster {
	t.Helper()
	c := newCluster(t, envelope.NewFakeKMS("escrow"), nil, "dev", append(secrets, controllerDeployment(appsOnly...))...)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{sealedSecretsResource: "SealedSecretList"}, sealed...)
	usage := NewUsage(UsageOptions{Kube: c.kube, SealedSecrets: dyn, Namespace: ns, Deployment: "sealed-secrets-controller", Interval: time.Minute})
	return &cleanupCluster{cluster: c, sealedSecrets: dyn, cleanup: NewCleanup(c.sync, usage, staticCerts{pem: active}, nil)}
}

func deletePayload(fps ...string) json.RawMessage {
	b, _ := json.Marshal(protocol.KeysDeletePayload{Fingerprints: fps})
	return b
}

func (c *cleanupCluster) delete(t *testing.T, fps ...string) (protocol.KeysDeleteResult, error) {
	t.Helper()
	out, err := c.cleanup.Delete(context.Background(), protocol.Command{Payload: deletePayload(fps...)})
	res, ok := out.(protocol.KeysDeleteResult)
	if !ok {
		t.Fatalf("result = %#v, err = %v", out, err)
	}
	return res, err
}

// secretNames lists the Secrets in the controller's namespace.
func (c *cleanupCluster) secretNames(t *testing.T) []string {
	t.Helper()
	list, err := c.kube.CoreV1().Secrets(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range list.Items {
		out = append(out, s.Name)
	}
	slices.Sort(out)
	return out
}

func outcome(res protocol.KeysDeleteResult, fp string) protocol.KeyDeletion {
	for _, k := range res.Keys {
		if k.Fingerprint == fp {
			return k
		}
	}
	return protocol.KeyDeletion{}
}

func TestCleanup_RemovesOnlyKeysNoValueUses(t *testing.T) {
	used := newPair(t, time.Now().Add(-72*time.Hour))
	unused := newPair(t, time.Now().Add(-48*time.Hour))
	active := newPair(t, time.Now().Add(-time.Hour))
	gone := newPair(t, time.Now().Add(-24*time.Hour))
	// a second Secret of the unused key, relabeled: it goes too
	relabeled := unused.secret("unused-old")
	relabeled.Labels[keyLabel] = "compromised"
	c := newCleanupCluster(t, active.cert,
		[]runtime.Object{used.secret("used"), unused.secret("unused"), relabeled, active.secret("active")},
		sealedSecret("apps", "s", nil, map[string]string{"a": seal(t, used, "apps", "s", ssv1alpha1.StrictScope)}))

	res, err := c.delete(t, used.fp, unused.fp, gone.fp, unused.fp)
	if err == nil || !strings.Contains(err.Error(), "refused to remove 1 of 3 keys") {
		t.Fatalf("err = %v", err)
	}
	if len(res.Keys) != 3 || !res.ControllerRestarted {
		t.Fatalf("result = %+v", res)
	}
	if k := outcome(res, used.fp); k.Outcome != protocol.KeyRefused || k.Values != 1 || k.SealedSecrets != 1 || k.Reason != "1 value in 1 SealedSecret uses it" {
		t.Errorf("used key = %+v", k)
	}
	if k := outcome(res, unused.fp); k.Outcome != protocol.KeyRemoved {
		t.Errorf("unused key = %+v", k)
	}
	if k := outcome(res, gone.fp); k.Outcome != protocol.KeyAbsent {
		t.Errorf("absent key = %+v", k)
	}
	if got := c.secretNames(t); !slices.Equal(got, []string{"active", "used"}) {
		t.Fatalf("secrets left = %v", got)
	}
	// the controller held the key in memory: its pod is restarted
	if !c.restarted(t) || c.sync.DeletedLoaded() {
		t.Fatalf("restarted = %v, deleted keys still loaded = %v", c.restarted(t), c.sync.DeletedLoaded())
	}

	// once its value is sealed with another key, the used key goes too
	if err := c.sealedSecrets.Resource(sealedSecretsResource).Namespace("apps").Delete(context.Background(), "s", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err = c.delete(t, used.fp)
	if err != nil || outcome(res, used.fp).Outcome != protocol.KeyRemoved {
		t.Fatalf("second removal = %+v, %v", res, err)
	}
}

// The removal counts again: a value applied since the last count stops it.
func TestCleanup_CountsAgainBeforeRemoving(t *testing.T) {
	old := newPair(t, time.Now().Add(-48*time.Hour))
	active := newPair(t, time.Now().Add(-time.Hour))
	c := newCleanupCluster(t, active.cert, []runtime.Object{old.secret("old"), active.secret("active")})
	if r, err := c.cleanup.usage.Count(context.Background()); err != nil || len(r.Keys) != 0 {
		t.Fatalf("count = %+v, %v", r, err)
	}
	if _, err := c.sealedSecrets.Resource(sealedSecretsResource).Namespace("apps").Create(context.Background(),
		sealedSecret("apps", "new", nil, map[string]string{"a": seal(t, old, "apps", "new", ssv1alpha1.StrictScope)}), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := c.delete(t, old.fp)
	if err == nil || outcome(res, old.fp).Outcome != protocol.KeyRefused || res.ControllerRestarted {
		t.Fatalf("removal = %+v, %v", res, err)
	}
	if got := c.secretNames(t); !slices.Equal(got, []string{"active", "old"}) || c.restarted(t) {
		t.Fatalf("secrets left = %v, restarted %v", got, c.restarted(t))
	}
}

func TestCleanup_Refuses(t *testing.T) {
	old := newPair(t, time.Now().Add(-48*time.Hour))
	active := newPair(t, time.Now().Add(-time.Hour))
	unloadable := old.secret("old")
	unloadable.Data["tls.key"] = []byte("not a key")
	cases := map[string]struct {
		secrets []runtime.Object
		setup   func(c *cleanupCluster)
		reason  string
	}{
		"the count fails": {
			secrets: []runtime.Object{old.secret("old")},
			setup: func(c *cleanupCluster) {
				c.sealedSecrets.PrependReactor("list", "sealedsecrets", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("forbidden")
				})
			},
			reason: "could not count the values sealed with it: failed to list SealedSecrets in apps: forbidden",
		},
		"its Secret does not load, so it cannot be counted": {
			secrets: []runtime.Object{unloadable},
			reason:  "key Secret old does not load",
		},
		"its Secret changed while it was deleted": {
			secrets: []runtime.Object{old.secret("old")},
			setup: func(c *cleanupCluster) {
				c.kube.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewConflict(corev1.Resource("secrets"), "old", errors.New("precondition failed"))
				})
			},
			reason: "key secret old changed while it was being deleted",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := newCleanupCluster(t, active.cert, append(tc.secrets, active.secret("active")))
			if tc.setup != nil {
				tc.setup(c)
			}
			res, err := c.delete(t, old.fp)
			if err == nil || len(res.Keys) != 1 || res.Keys[0].Outcome != protocol.KeyRefused || !strings.Contains(res.Keys[0].Reason, tc.reason) {
				t.Fatalf("removal = %+v, %v", res, err)
			}
			if c.restarted(t) {
				t.Fatal("the controller was restarted although nothing was removed")
			}
		})
	}
}

func TestCleanup_RefusesInvalidPayloads(t *testing.T) {
	active := newPair(t, time.Now().Add(-time.Hour))
	c := newCleanupCluster(t, active.cert, []runtime.Object{active.secret("active")})
	many := make([]string, protocol.MaxRestoreKeys+1)
	for i := range many {
		many[i] = fmt.Sprintf("SHA256:k%d", i)
	}
	for name, payload := range map[string]json.RawMessage{
		"unknown field":   json.RawMessage(`{"fingerprints":["SHA256:a"],"force":true}`),
		"no fingerprints": deletePayload(),
		"too many":        deletePayload(many...),
		"not fingerprint": deletePayload("md5:abc"),
	} {
		if _, err := c.cleanup.Delete(context.Background(), protocol.Command{Payload: payload}); err == nil || !strings.Contains(err.Error(), "invalid payload") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if got := c.secretNames(t); !slices.Equal(got, []string{"active"}) {
		t.Fatalf("secrets = %v", got)
	}
}

// A key no Secret holds that the controller still seals with is held only
// by pods that started before it was deleted: they are restarted.
func TestCleanup_RestartsAControllerStillServingAnAbsentKey(t *testing.T) {
	deleted := newPair(t, time.Now().Add(-time.Hour))
	other := newPair(t, time.Now().Add(-48*time.Hour))
	c := newCleanupCluster(t, deleted.cert, []runtime.Object{other.secret("other")})
	res, err := c.delete(t, deleted.fp)
	if err != nil || outcome(res, deleted.fp).Outcome != protocol.KeyAbsent || !res.ControllerRestarted || !c.restarted(t) {
		t.Fatalf("removal = %+v, %v; restarted %v", res, err, c.restarted(t))
	}
}

// A restart that fails is retried by the check-in loop until the pods that
// held the deleted key are gone.
func TestCleanup_RetriesAFailedRestart(t *testing.T) {
	old := newPair(t, time.Now().Add(-48*time.Hour))
	active := newPair(t, time.Now().Add(-time.Hour))
	c := newCleanupCluster(t, active.cert, []runtime.Object{old.secret("old"), active.secret("active")})
	var failDeletes atomic.Bool
	failDeletes.Store(true)
	c.kube.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failDeletes.Load() {
			return true, nil, errors.New("api server unavailable")
		}
		return false, nil, nil
	})
	res, err := c.delete(t, old.fp)
	if err == nil || outcome(res, old.fp).Outcome != protocol.KeyRemoved || res.ControllerRestarted || !c.sync.DeletedLoaded() {
		t.Fatalf("removal with a failing restart = %+v, %v", res, err)
	}
	failDeletes.Store(false)
	// past the backoff
	now := time.Now().Add(time.Hour)
	c.sync.now = func() time.Time { return now }
	c.sync.LoadRestored(context.Background(), "")
	if !c.restarted(t) || c.sync.DeletedLoaded() {
		t.Fatalf("after the retry: restarted %v, deleted keys still loaded %v", c.restarted(t), c.sync.DeletedLoaded())
	}
}

// A Secret with one key's certificate and another key's private key holds,
// for the controller, the key of its private key. Neither key is removed
// on its word: the count could have taken values sealed with one for the
// other's.
func TestCleanup_RefusesASecretWhoseCertificateIsAnotherKey(t *testing.T) {
	x := newPair(t, time.Now().Add(-72*time.Hour))
	y := newPair(t, time.Now().Add(-48*time.Hour))
	active := newPair(t, time.Now().Add(-time.Hour))
	shadow := x.secret("a-shadow")
	shadow.Data[corev1.TLSPrivateKeyKey] = y.key
	shadow.Labels[keyLabel] = "compromised"
	c := newCleanupCluster(t, active.cert,
		[]runtime.Object{shadow, x.secret("b-real"), active.secret("z-active")},
		sealedSecret("apps", "s", nil, map[string]string{"a": seal(t, x, "apps", "s", ssv1alpha1.StrictScope)}))

	res, err := c.delete(t, x.fp, y.fp)
	if err == nil {
		t.Fatal("removal succeeded")
	}
	if k := outcome(res, x.fp); k.Outcome != protocol.KeyRefused || k.Values != 1 {
		t.Errorf("x = %+v; a value is sealed with it", k)
	}
	if k := outcome(res, y.fp); k.Outcome != protocol.KeyRefused || !strings.Contains(k.Reason, "a-shadow holds the certificate of one key and the private key of another") {
		t.Errorf("y = %+v", k)
	}
	if got := c.secretNames(t); !slices.Equal(got, []string{"a-shadow", "b-real", "z-active"}) {
		t.Fatalf("secrets left = %v", got)
	}
}

// A removal waits for a count already running only as long as its command
// may: the agent's command loop is not held up past it.
func TestCleanup_GivesUpWaitingForARunningCount(t *testing.T) {
	x := newPair(t, time.Now().Add(-72*time.Hour))
	active := newPair(t, time.Now().Add(-time.Hour))
	c := newCleanupCluster(t, active.cert, []runtime.Object{x.secret("x"), active.secret("active")})
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	c.sealedSecrets.PrependReactor("list", "sealedsecrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		select {
		case entered <- struct{}{}:
			<-release // the background count is slow
		default:
		}
		return false, nil, nil
	})
	counted := make(chan struct{})
	go func() {
		defer close(counted)
		_, _ = c.cleanup.usage.Count(context.Background())
	}()
	<-entered
	defer func() { close(release); <-counted }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := c.cleanup.Delete(ctx, protocol.Command{Payload: deletePayload(x.fp)})
	if took := time.Since(start); took > 2*time.Second || err == nil {
		t.Fatalf("Delete returned after %v: %v", took, err)
	}
	if res := out.(protocol.KeysDeleteResult); outcome(res, x.fp).Outcome != protocol.KeyRefused {
		t.Fatalf("result = %+v", res)
	}
	if got := c.secretNames(t); !slices.Contains(got, "x") {
		t.Fatalf("secrets left = %v", got)
	}
}
