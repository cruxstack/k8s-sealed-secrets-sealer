package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// seal seals a value with a key's certificate as kubeseal and the agent's
// seal.v1 do, for a SealedSecret namespace/name of the given scope, and
// returns it as it goes in spec.encryptedData.
func seal(t *testing.T, p pair, namespace, name string, scope ssv1alpha1.SealingScope) string {
	t.Helper()
	_, pub, err := keys.ParseCert(p.cert)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sscrypto.HybridEncrypt(rand.Reader, pub, []byte("value"), ssv1alpha1.EncryptionLabel(namespace, name, scope))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// sealedSecret is a SealedSecret with the given encrypted data, scope
// annotations on its own metadata and a template.
func sealedSecret(namespace, name string, annotations map[string]string, data map[string]string) *unstructured.Unstructured {
	encrypted := map[string]any{}
	for k, v := range data {
		encrypted[k] = v
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "bitnami.com/v1alpha1",
		"kind":       "SealedSecret",
		"metadata":   map[string]any{"namespace": namespace, "name": name},
		"spec": map[string]any{
			"encryptedData": encrypted,
			"template":      map[string]any{"metadata": map[string]any{"name": name}},
		},
	}}
	obj.SetAnnotations(annotations)
	obj.SetUID(types.UID(namespace + "-" + name))
	obj.SetResourceVersion("1")
	return obj
}

// usageCluster is a fake cluster whose controller, in ns, watches its own
// namespace and "apps".
type usageCluster struct {
	kube          *fake.Clientset
	sealedSecrets *dynamicfake.FakeDynamicClient
	usage         *Usage
}

func newUsageCluster(t *testing.T, controllerArgs []string, secrets []runtime.Object, sealed ...runtime.Object) *usageCluster {
	t.Helper()
	objs := append([]runtime.Object{controllerDeployment(controllerArgs...)}, secrets...)
	kube := fake.NewClientset(objs...)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{sealedSecretsResource: "SealedSecretList"}, sealed...)
	return &usageCluster{kube: kube, sealedSecrets: dyn, usage: NewUsage(UsageOptions{
		Kube: kube, SealedSecrets: dyn, Namespace: ns, Deployment: "sealed-secrets-controller", Interval: time.Minute,
	})}
}

var appsOnly = []string{"--all-namespaces=false", "--additional-namespaces", "apps"}

func (c *usageCluster) count(t *testing.T) protocol.KeyUsage {
	t.Helper()
	r, err := c.usage.Count(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return r
}

func (c *usageCluster) put(t *testing.T, obj *unstructured.Unstructured) {
	t.Helper()
	ctx := context.Background()
	res := c.sealedSecrets.Resource(sealedSecretsResource).Namespace(obj.GetNamespace())
	if _, err := res.Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
		if _, err := res.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUsage_CountsValuesByTheKeyThatSealedThem(t *testing.T) {
	k1 := newPair(t, time.Now().Add(-48*time.Hour))
	k2 := newPair(t, time.Now().Add(-time.Hour))
	stranger := newPair(t, time.Now().Add(-time.Hour))
	// a key relabeled as compromised still decrypts: deleting it would
	// break what it sealed
	relabeled := k2.secret("k2")
	relabeled.Labels[keyLabel] = "compromised"
	nsWide := map[string]string{ssv1alpha1.SealedSecretNamespaceWideAnnotation: "true"}
	legacy := sealedSecret("apps", "legacy", nil, nil)
	legacy.Object["spec"].(map[string]any)["data"] = seal(t, k1, "apps", "legacy", ssv1alpha1.StrictScope)
	c := newUsageCluster(t, appsOnly, []runtime.Object{k1.secret("k1"), relabeled},
		sealedSecret("apps", "two", nil, map[string]string{
			"a": seal(t, k1, "apps", "two", ssv1alpha1.StrictScope),
			"b": seal(t, k1, "apps", "two", ssv1alpha1.StrictScope),
		}),
		// the scope comes from the SealedSecret's own annotations
		sealedSecret("apps", "wide", nsWide, map[string]string{"a": seal(t, k2, "apps", "wide", ssv1alpha1.NamespaceWideScope)}),
		// sealed under another scope than annotated: the controller cannot
		// decrypt it, but the key is still its reference
		sealedSecret("apps", "mislabeled", nil, map[string]string{"a": seal(t, k1, "apps", "mislabeled", ssv1alpha1.ClusterWideScope)}),
		sealedSecret(ns, "unmatched", nil, map[string]string{
			"a": seal(t, stranger, ns, "unmatched", ssv1alpha1.StrictScope),
			"b": "not base64!",
		}),
		legacy,
		// not a namespace the controller watches
		sealedSecret("other", "elsewhere", nil, map[string]string{"a": seal(t, k1, "other", "elsewhere", ssv1alpha1.StrictScope)}),
	)

	r := c.count(t)
	if r.Error != "" || r.ScannedAt.IsZero() || !slices.Equal(r.Namespaces, []string{"apps", ns}) {
		t.Fatalf("count = %+v", r)
	}
	if r.SealedSecrets != 5 || r.Values != 7 || r.Unmatched != 2 {
		t.Fatalf("counted %d SealedSecrets, %d values, %d unmatched; want 5, 7, 2", r.SealedSecrets, r.Values, r.Unmatched)
	}
	want := map[string]protocol.KeyUse{k1.fp: {Values: 4, SealedSecrets: 3}, k2.fp: {Values: 1, SealedSecrets: 1}}
	if !maps.Equal(r.Keys, want) {
		t.Fatalf("keys = %+v, want %+v", r.Keys, want)
	}
	if got := c.usage.Latest(); got == nil || got.Values != 7 || !got.ScannedAt.Equal(r.ScannedAt) {
		t.Fatalf("latest = %+v", got)
	}
}

// A count decrypts only what changed: an unchanged SealedSecret keeps what
// it matched, an unmatched value is tried again when a key is added, and a
// value whose key left the cluster counts as unmatched.
func TestUsage_CachesUntilASealedSecretChanges(t *testing.T) {
	k1 := newPair(t, time.Now().Add(-48*time.Hour))
	k2 := newPair(t, time.Now().Add(-time.Hour))
	s := sealedSecret("apps", "s", nil, map[string]string{"a": seal(t, k1, "apps", "s", ssv1alpha1.StrictScope)})
	later := sealedSecret("apps", "later", nil, map[string]string{"a": seal(t, k2, "apps", "later", ssv1alpha1.StrictScope)})
	c := newUsageCluster(t, appsOnly, []runtime.Object{k1.secret("k1")}, s, later)
	ctx := context.Background()

	if r := c.count(t); r.Keys[k1.fp].Values != 1 || r.Unmatched != 1 {
		t.Fatalf("first count = %+v", r)
	}
	// the same object, its value replaced without a new resourceVersion:
	// the cached match stands, so it was not decrypted again
	s.Object["spec"].(map[string]any)["encryptedData"] = map[string]any{"a": "garbage"}
	c.put(t, s)
	if r := c.count(t); r.Keys[k1.fp].Values != 1 {
		t.Fatalf("count of an unchanged object = %+v", r)
	}
	// a new resourceVersion is decrypted again
	s.SetResourceVersion("2")
	c.put(t, s)
	if r := c.count(t); r.Keys[k1.fp].Values != 0 || r.Unmatched != 2 {
		t.Fatalf("count after a change = %+v", r)
	}

	// k2 arrives (restored, say): the value no key matched is tried again
	if _, err := c.kube.CoreV1().Secrets(ns).Create(ctx, k2.secret("k2"), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if r := c.count(t); r.Keys[k2.fp].Values != 1 || r.Unmatched != 1 {
		t.Fatalf("count after a key was added = %+v", r)
	}
	// k2 leaves: its value has no key in the cluster
	if err := c.kube.CoreV1().Secrets(ns).Delete(ctx, "k2", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if r := c.count(t); len(r.Keys) != 0 || r.Unmatched != 2 {
		t.Fatalf("count after a key left = %+v", r)
	}
	// a SealedSecret deleted is forgotten
	if err := c.sealedSecrets.Resource(sealedSecretsResource).Namespace("apps").Delete(ctx, "later", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if r := c.count(t); r.SealedSecrets != 1 || len(c.usage.cached) != 1 {
		t.Fatalf("count after a SealedSecret was deleted = %+v, cached %d", r, len(c.usage.cached))
	}
}

// A controller watching every namespace is counted everywhere, a page at
// a time.
func TestUsage_EveryNamespaceInPages(t *testing.T) {
	k1 := newPair(t, time.Now().Add(-time.Hour))
	var sealed []runtime.Object
	for i := range 3 {
		name := fmt.Sprintf("s%d", i)
		sealed = append(sealed, sealedSecret(fmt.Sprintf("team-%d", i), name, nil, map[string]string{"a": seal(t, k1, fmt.Sprintf("team-%d", i), name, ssv1alpha1.StrictScope)}))
	}
	c := newUsageCluster(t, nil, []runtime.Object{k1.secret("k1")})
	// the fake API server does not page; this one serves a page per call
	paged := &pagedSealedSecrets{pages: sealed}
	c.usage.sealedSecrets = paged
	r := c.count(t)
	if r.Namespaces != nil || r.SealedSecrets != 3 || r.Keys[k1.fp].Values != 3 {
		t.Fatalf("count = %+v", r)
	}
	calls := paged.calls
	if len(calls) != 3 || calls[0].Limit != usagePageSize || calls[0].Continue != "" || calls[2].Continue != "2" || paged.namespace != "" {
		t.Fatalf("list calls = %+v in %q", calls, paged.namespace)
	}
}

// pagedSealedSecrets serves one SealedSecret per page, and records how it
// was asked.
type pagedSealedSecrets struct {
	dynamic.Interface
	dynamic.NamespaceableResourceInterface
	pages     []runtime.Object
	calls     []metav1.ListOptions
	namespace string
}

func (p *pagedSealedSecrets) Resource(schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return p
}

func (p *pagedSealedSecrets) Namespace(ns string) dynamic.ResourceInterface {
	p.namespace = ns
	return p
}

func (p *pagedSealedSecrets) List(_ context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	p.calls = append(p.calls, opts)
	page := 0
	if opts.Continue != "" {
		page, _ = strconv.Atoi(opts.Continue)
	}
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*p.pages[page].(*unstructured.Unstructured)}}
	if page < len(p.pages)-1 {
		list.SetContinue(strconv.Itoa(page + 1))
	}
	return list, nil
}

// A controller with a label selector is counted with it.
func TestUsage_LabelSelector(t *testing.T) {
	k1 := newPair(t, time.Now().Add(-time.Hour))
	mine := sealedSecret("apps", "mine", nil, map[string]string{"a": seal(t, k1, "apps", "mine", ssv1alpha1.StrictScope)})
	mine.SetLabels(map[string]string{"team": "a"})
	theirs := sealedSecret("apps", "theirs", nil, map[string]string{"a": seal(t, k1, "apps", "theirs", ssv1alpha1.StrictScope)})
	c := newUsageCluster(t, append(slices.Clone(appsOnly), "--label-selector=team=a"), []runtime.Object{k1.secret("k1")}, mine, theirs)
	if r := c.count(t); r.SealedSecrets != 1 {
		t.Fatalf("count = %+v", r)
	}
}

// A count that fails says why, has no counts, and is the latest.
func TestUsage_Failures(t *testing.T) {
	k1 := newPair(t, time.Now().Add(-time.Hour))
	cases := map[string]struct {
		setup func(c *usageCluster)
		want  string
	}{
		"the deployment cannot be read": {
			setup: func(c *usageCluster) {
				_ = c.kube.AppsV1().Deployments(ns).Delete(context.Background(), "sealed-secrets-controller", metav1.DeleteOptions{})
			},
			want: "failed to read the controller's deployment",
		},
		"the namespaces are set where the agent cannot read them": {
			setup: func(c *usageCluster) {
				d, _ := c.kube.AppsV1().Deployments(ns).Get(context.Background(), "sealed-secrets-controller", metav1.GetOptions{})
				d.Spec.Template.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{}}}
				_, _ = c.kube.AppsV1().Deployments(ns).Update(context.Background(), d, metav1.UpdateOptions{})
			},
			want: "cannot tell which SealedSecrets the controller watches",
		},
		"SealedSecrets cannot be listed": {
			setup: func(c *usageCluster) {
				c.sealedSecrets.PrependReactor("list", "sealedsecrets", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("forbidden")
				})
			},
			want: "failed to list SealedSecrets in apps: forbidden",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := newUsageCluster(t, appsOnly, []runtime.Object{k1.secret("k1")})
			tc.setup(c)
			r, err := c.usage.Count(context.Background())
			if err == nil || !strings.Contains(r.Error, tc.want) || r.ScannedAt.IsZero() || r.Values != 0 || r.Keys != nil {
				t.Fatalf("count = %+v, %v", r, err)
			}
			if got := c.usage.Latest(); got == nil || got.Error != r.Error {
				t.Fatalf("latest = %+v", got)
			}
		})
	}
}

// Run counts at once and then every interval; a count cut short by
// shutdown is not kept.
func TestUsage_Run(t *testing.T) {
	k1 := newPair(t, time.Now().Add(-time.Hour))
	c := newUsageCluster(t, appsOnly, []runtime.Object{k1.secret("k1")})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.usage.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for c.usage.Latest() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.usage.Latest() == nil {
		t.Fatal("no count after Run started")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// A count cut short keeps what it matched, so the next goes on from there
// instead of decrypting it all again.
func TestUsage_KeepsProgressWhenACountIsCutShort(t *testing.T) {
	x := newPair(t, time.Now().Add(-72*time.Hour))
	c := newUsageCluster(t, appsOnly, []runtime.Object{x.secret("x")},
		sealedSecret("apps", "s", nil, map[string]string{"a": seal(t, x, "apps", "s", ssv1alpha1.StrictScope)}),
		sealedSecret("apps", "t", nil, map[string]string{"a": seal(t, x, "apps", "t", ssv1alpha1.StrictScope)}))
	c.usage.workers = 1
	// the count's time runs out once it matched one SealedSecret
	ctx, cancel := context.WithCancel(context.Background())
	var matched []string
	c.usage.onMatched = func(id string) {
		matched = append(matched, id)
		cancel()
	}
	if _, err := c.usage.Count(ctx); err == nil || !strings.Contains(err.Error(), "the next count goes on from there") {
		t.Fatalf("count cut short: %v", err)
	}
	if len(matched) != 1 || len(c.usage.cached) != 1 || c.usage.cached[matched[0]] == nil {
		t.Fatalf("matched %v, cached %d", matched, len(c.usage.cached))
	}
	// the next count decrypts only the other
	first := matched[0]
	matched = nil
	c.usage.onMatched = func(id string) { matched = append(matched, id) }
	r := c.count(t)
	if len(matched) != 1 || matched[0] == first || r.Keys[x.fp].Values != 2 {
		t.Fatalf("second count matched %v (first %s), keys %+v", matched, first, r.Keys)
	}
}

// A count whose list fails decrypts nothing and keeps what earlier counts
// matched: a list call never waits on decryption, so its continue token
// does not expire meanwhile.
func TestUsage_AFailedListKeepsTheCache(t *testing.T) {
	x := newPair(t, time.Now().Add(-72*time.Hour))
	c := newUsageCluster(t, appsOnly, []runtime.Object{x.secret("x")},
		sealedSecret("apps", "s", nil, map[string]string{"a": seal(t, x, "apps", "s", ssv1alpha1.StrictScope)}))
	c.count(t)
	c.sealedSecrets.PrependReactor("list", "sealedsecrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == ns {
			return true, nil, errors.New("the provided continue parameter is too old")
		}
		return false, nil, nil
	})
	if _, err := c.usage.Count(context.Background()); err == nil {
		t.Fatal("count succeeded")
	}
	if s := c.usage.cached["apps/s"]; s == nil || s.values[0] != x.fp {
		t.Fatalf("cached after a failed list = %+v", s)
	}
}

// A count decrypts at most maxPending values afresh, and reports itself
// incomplete; the next goes on from there until it is complete.
func TestUsage_CountsALargeClusterOverSeveralCounts(t *testing.T) {
	x := newPair(t, time.Now().Add(-72*time.Hour))
	var sealed []runtime.Object
	for i := range 5 {
		name := fmt.Sprintf("s%d", i)
		sealed = append(sealed, sealedSecret("apps", name, nil, map[string]string{
			"a": seal(t, x, "apps", name, ssv1alpha1.StrictScope), "b": seal(t, x, "apps", name, ssv1alpha1.StrictScope),
		}))
	}
	c := newUsageCluster(t, appsOnly, []runtime.Object{x.secret("x")}, sealed...)
	c.usage.maxPending = 4
	var errs []error
	for range 3 {
		_, err := c.usage.Count(context.Background())
		errs = append(errs, err)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "wait for the next count") {
			t.Fatalf("err = %v", err)
		}
	}
	if len(errs) != 3 || errs[2] != nil {
		t.Fatalf("counts = %v, want two incomplete and then a complete one", errs)
	}
	if r := c.usage.Latest(); r.Error != "" || r.SealedSecrets != 5 || r.Keys[x.fp].Values != 10 {
		t.Fatalf("latest = %+v", r)
	}
}

// After a count that failed or overran its interval, Run waits the whole
// interval.
func TestUsage_Pause(t *testing.T) {
	u := NewUsage(UsageOptions{Interval: time.Minute})
	for _, tc := range []struct {
		elapsed time.Duration
		failed  bool
		want    time.Duration
	}{
		{10 * time.Second, false, 50 * time.Second},
		{10 * time.Second, true, time.Minute},
		{2 * time.Minute, false, time.Minute},
	} {
		if got := u.pause(tc.elapsed, tc.failed); got != tc.want {
			t.Errorf("pause(%s, %v) = %s, want %s", tc.elapsed, tc.failed, got, tc.want)
		}
	}
}

// Only the head of a value is decoded: its length and RSA part.
func TestRSAPart(t *testing.T) {
	x := newPair(t, time.Now().Add(-time.Hour))
	ct, err := base64.StdEncoding.DecodeString(seal(t, x, "apps", "s", ssv1alpha1.StrictScope))
	if err != nil {
		t.Fatal(err)
	}
	n := int(ct[0])<<8 | int(ct[1])
	if got := rsaPart(base64.StdEncoding.EncodeToString(ct)); !bytes.Equal(got, ct[2:2+n]) {
		t.Fatalf("rsaPart = %d bytes, want %d", len(got), n)
	}
	for _, bad := range []string{"", "AA", "!!!!", base64.StdEncoding.EncodeToString(ct[:n/2])} {
		if got := rsaPart(bad); got != nil {
			t.Errorf("rsaPart(%.12q...) = %d bytes", bad, len(got))
		}
	}
}

// Errors are cut at a rune boundary, never past the limit.
func TestTruncate(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{{"abc", 5, "abc"}, {"abcdef", 3, "abc"}, {"aé", 2, "a"}, {"日本", 4, "日"}} {
		if got := truncate(tc.in, tc.n); got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
