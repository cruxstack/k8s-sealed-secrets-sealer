package agent

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// A sealed value does not say which key sealed it; only the private keys can
// tell. Usage counts, for each key in the cluster, the values its
// controller's SealedSecrets hold that the key sealed. For each value it
// decrypts only the RSA-OAEP part at the head of the ciphertext (a 2-byte
// big-endian length, then that many bytes; sealed-secrets' HybridEncrypt),
// which yields the value's one-time AES key, and drops that key at once: it
// never decrypts, keeps or reports a value. It reports counts by
// fingerprint, never which SealedSecret holds what.

// sealedSecretsResource is the SealedSecrets API. They are read with the
// dynamic client: the agent needs a few of their fields, not the
// controller's types.
var sealedSecretsResource = schema.GroupVersionResource{Group: "bitnami.com", Version: "v1alpha1", Resource: "sealedsecrets"}

// Counting.
const (
	// usagePageSize is how many SealedSecrets one list call returns.
	usagePageSize = 500
	// usageScanTimeout bounds one count, so a stuck call does not stop
	// the counts after it.
	usageScanTimeout = 10 * time.Minute
)

// Usage counts the values the controller's SealedSecrets hold by the key
// that sealed them. It runs on its own, every interval, never in the way of
// check-ins or commands; a removal counts again before it removes a key.
// It needs the cleanup capability's RBAC (list SealedSecrets) and keys'
// (list Secrets).
type Usage struct {
	kube          kubernetes.Interface
	sealedSecrets dynamic.Interface
	namespace     string
	deployment    string
	interval      time.Duration
	logger        *slog.Logger
	now           func() time.Time

	// mu runs one count at a time and guards what counts keep: cached
	// holds what each SealedSecret's values matched, until the object
	// changes (namespace/name, then UID and resourceVersion); gen counts
	// the counts whose key set gained a key, and added holds the gen each
	// key in the set was added at, so an unmatched value is tried again
	// with keys added since; matched is how many values each key matched
	// last, so the likeliest key is tried first.
	mu      sync.Mutex
	cached  map[string]*sealedUsage
	gen     int
	added   map[string]int
	matched map[string]int

	latestMu sync.Mutex
	latest   *protocol.KeyUsage
}

// sealedUsage is what a count found in one SealedSecret. It holds no
// ciphertext, only the fingerprint of the key each value matched.
type sealedUsage struct {
	uid             types.UID
	resourceVersion string
	// values holds each value's key fingerprint, "" for a value none of
	// the keys tried decrypts
	values []string
	// tried is the gen the unmatched values were last tried at
	tried int
}

// UsageOptions configures a Usage.
type UsageOptions struct {
	Kube          kubernetes.Interface
	SealedSecrets dynamic.Interface
	// Namespace and Deployment are the controller's: its key Secrets and
	// the flags that say which SealedSecrets it watches.
	Namespace  string
	Deployment string
	// Interval is the least time between the starts of two counts.
	Interval time.Duration
	Logger   *slog.Logger
	Now      func() time.Time
}

// NewUsage returns a Usage. It makes no network calls.
func NewUsage(opts UsageOptions) *Usage {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Usage{
		kube:          opts.Kube,
		sealedSecrets: opts.SealedSecrets,
		namespace:     opts.Namespace,
		deployment:    opts.Deployment,
		interval:      opts.Interval,
		logger:        logger,
		now:           now,
		cached:        map[string]*sealedUsage{},
		added:         map[string]int{},
		matched:       map[string]int{},
	}
}

// Run counts now, then at most every interval, until ctx ends.
func (u *Usage) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		started := time.Now()
		scanCtx, cancel := context.WithTimeout(ctx, usageScanTimeout)
		_, err := u.Count(scanCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			u.logger.WarnContext(ctx, "failed to count the values sealed with each key",
				"event", "key.count_failed", "error", err)
		}
		sleep(ctx, u.interval-time.Since(started))
	}
	return nil
}

// Latest returns the latest finished count, nil before the first.
func (u *Usage) Latest() *protocol.KeyUsage {
	u.latestMu.Lock()
	defer u.latestMu.Unlock()
	if u.latest == nil {
		return nil
	}
	r := *u.latest
	r.Keys = maps.Clone(r.Keys)
	return &r
}

// Count counts now, reusing what earlier counts found in SealedSecrets that
// have not changed, and makes it the latest. A failed count is the latest
// too, with its error and no counts; it returns the error as well. A count
// cut short by ctx is not kept.
func (u *Usage) Count(ctx context.Context) (protocol.KeyUsage, error) {
	r, _, err := u.count(ctx)
	return r, err
}

// count is Count, which also returns the fingerprints of the keys it
// counted with: a key Secret that did not load is not among them.
func (u *Usage) count(ctx context.Context) (protocol.KeyUsage, map[string]bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	r, ring, err := u.scan(ctx)
	if err != nil {
		r = protocol.KeyUsage{Error: truncate(err.Error(), protocol.MaxUsageError)}
	}
	r.ScannedAt = u.now().UTC()
	if ctx.Err() == nil {
		u.latestMu.Lock()
		u.latest = &r
		u.latestMu.Unlock()
	}
	return r, ring, err
}

// sealingKey is a key the cluster holds, with its private half, for one
// count only.
type sealingKey struct {
	fingerprint string
	notBefore   time.Time
	priv        *rsa.PrivateKey
}

// scan counts once. The caller holds mu.
func (u *Usage) scan(ctx context.Context) (protocol.KeyUsage, map[string]bool, error) {
	d, err := u.kube.AppsV1().Deployments(u.namespace).Get(ctx, u.deployment, metav1.GetOptions{})
	if err != nil {
		return protocol.KeyUsage{}, nil, fmt.Errorf("failed to read the controller's deployment %s/%s: %w", u.namespace, u.deployment, err)
	}
	scope, err := readWatchScope(d)
	if err != nil {
		return protocol.KeyUsage{}, nil, err
	}
	if len(scope.namespaces) > protocol.MaxUsageNamespaces {
		return protocol.KeyUsage{}, nil, fmt.Errorf("the controller watches %d namespaces, more than the %d a count can name", len(scope.namespaces), protocol.MaxUsageNamespaces)
	}
	ring, err := u.keyRing(ctx)
	if err != nil {
		return protocol.KeyUsage{}, nil, err
	}
	inRing := make(map[string]bool, len(ring))
	for _, k := range ring {
		inRing[k.fingerprint] = true
	}
	u.noteKeys(inRing)
	// the likeliest key first: the one most values matched, then the newest
	sort.SliceStable(ring, func(i, j int) bool {
		a, b := ring[i], ring[j]
		if u.matched[a.fingerprint] != u.matched[b.fingerprint] {
			return u.matched[a.fingerprint] > u.matched[b.fingerprint]
		}
		if !a.notBefore.Equal(b.notBefore) {
			return a.notBefore.After(b.notBefore)
		}
		return a.fingerprint > b.fingerprint
	})

	seen := map[string]*sealedUsage{}
	namespaces := scope.namespaces
	if namespaces == nil {
		namespaces = []string{metav1.NamespaceAll}
	}
	for _, ns := range namespaces {
		err := u.list(ctx, ns, scope.labelSelector, func(obj *unstructured.Unstructured) {
			id := obj.GetNamespace() + "/" + obj.GetName()
			seen[id] = u.match(obj, u.cached[id], ring)
		})
		if err != nil {
			return protocol.KeyUsage{}, nil, err
		}
	}
	// SealedSecrets gone since are forgotten
	u.cached = seen

	r := protocol.KeyUsage{Namespaces: scope.namespaces, Keys: map[string]protocol.KeyUse{}}
	matched := map[string]int{}
	for _, s := range seen {
		r.SealedSecrets++
		here := map[string]bool{}
		for _, fp := range s.values {
			r.Values++
			if fp == "" || !inRing[fp] {
				// none of the keys decrypts it, or its key has left the
				// cluster since
				r.Unmatched++
				continue
			}
			use := r.Keys[fp]
			use.Values++
			if !here[fp] {
				here[fp] = true
				use.SealedSecrets++
			}
			r.Keys[fp] = use
			matched[fp]++
		}
	}
	u.matched = matched
	if len(r.Keys) > protocol.MaxKeys {
		// a report naming only some would count the others as unused
		return protocol.KeyUsage{}, nil, fmt.Errorf("values are sealed with %d keys, more than the %d a count can name", len(r.Keys), protocol.MaxKeys)
	}
	if len(r.Keys) == 0 {
		r.Keys = nil
	}
	return r, inRing, nil
}

// noteKeys records the key set a count uses: a key not in the last set is
// added at a new gen, so values no key matched before are tried with it.
// A key that left the set and comes back counts as added again.
func (u *Usage) noteKeys(inRing map[string]bool) {
	fresh := false
	for fp := range inRing {
		if _, ok := u.added[fp]; !ok {
			fresh = true
		}
	}
	if fresh {
		u.gen++
	}
	for fp := range u.added {
		if !inRing[fp] {
			delete(u.added, fp)
		}
	}
	for fp := range inRing {
		if _, ok := u.added[fp]; !ok {
			u.added[fp] = u.gen
		}
	}
}

// keyRing reads every key Secret in the controller's namespace, under any
// value of the key label (a key relabeled as compromised still decrypts),
// as the controller reads one when it starts. A Secret that would not load
// is left out.
func (u *Usage) keyRing(ctx context.Context) ([]sealingKey, error) {
	list, err := u.kube.CoreV1().Secrets(u.namespace).List(ctx, metav1.ListOptions{LabelSelector: keyLabel})
	if err != nil {
		return nil, fmt.Errorf("failed to list key secrets in %s: %w", u.namespace, err)
	}
	var ring []sealingKey
	for i := range list.Items {
		s := &list.Items[i]
		fp, ok := secretFingerprint(s)
		if !ok || slices.ContainsFunc(ring, func(k sealingKey) bool { return k.fingerprint == fp }) {
			continue
		}
		priv, err := readKeyPair(s.Data["tls.crt"], s.Data["tls.key"])
		if err != nil {
			u.logger.WarnContext(ctx, "skipping a key secret that does not load; values sealed with its key count as unmatched",
				"event", "controller.key_unusable", "secret", s.Name, "error", err)
			continue
		}
		k := sealingKey{fingerprint: fp, priv: priv}
		if parsed, _, err := keys.ParseCert(s.Data["tls.crt"]); err == nil {
			k.notBefore = parsed.NotBefore
		}
		ring = append(ring, k)
	}
	return ring, nil
}

// list calls fn for each SealedSecret in namespace (every namespace when
// empty) that selector selects, a page at a time.
func (u *Usage) list(ctx context.Context, namespace, selector string, fn func(*unstructured.Unstructured)) error {
	opts := metav1.ListOptions{Limit: usagePageSize, LabelSelector: selector}
	for {
		page, err := u.sealedSecrets.Resource(sealedSecretsResource).Namespace(namespace).List(ctx, opts)
		if err != nil {
			where := "every namespace"
			if namespace != "" {
				where = namespace
			}
			return fmt.Errorf("failed to list SealedSecrets in %s: %w", where, err)
		}
		for i := range page.Items {
			fn(&page.Items[i])
		}
		if opts.Continue = page.GetContinue(); opts.Continue == "" {
			return nil
		}
	}
}

// match works out which key sealed each value of a SealedSecret, from what
// an earlier count found (prev) while the object is unchanged: then only
// values none of the keys matched are tried again, with the keys added
// since.
func (u *Usage) match(obj *unstructured.Unstructured, prev *sealedUsage, ring []sealingKey) *sealedUsage {
	changed := prev == nil || prev.uid != obj.GetUID() || prev.resourceVersion != obj.GetResourceVersion()
	if !changed && (prev.tried == u.gen || !slices.Contains(prev.values, "")) {
		return prev
	}
	values := sealedValues(obj.Object)
	labels := decryptionLabels(obj)
	if changed {
		s := &sealedUsage{uid: obj.GetUID(), resourceVersion: obj.GetResourceVersion(), values: make([]string, len(values)), tried: u.gen}
		for i, v := range values {
			s.values[i] = matchValue(v, labels, ring)
		}
		return s
	}
	var newer []sealingKey
	for _, k := range ring {
		if u.added[k.fingerprint] > prev.tried {
			newer = append(newer, k)
		}
	}
	s := &sealedUsage{uid: prev.uid, resourceVersion: prev.resourceVersion, values: slices.Clone(prev.values), tried: u.gen}
	for i, fp := range s.values {
		if fp == "" && i < len(values) {
			s.values[i] = matchValue(values[i], labels, newer)
		}
	}
	return s
}

// sealedValues returns a SealedSecret's ciphertexts, in a stable order:
// each value of spec.encryptedData by its key, then the legacy spec.data,
// a whole Secret sealed as one value. A value that is not base64 is nil,
// which no key decrypts.
func sealedValues(obj map[string]any) [][]byte {
	spec, _ := obj["spec"].(map[string]any)
	var out [][]byte
	decode := func(v any) []byte {
		s, _ := v.(string)
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) == 0 {
			return nil
		}
		return b
	}
	if data, ok := spec["encryptedData"].(map[string]any); ok {
		for _, name := range slices.Sorted(maps.Keys(data)) {
			out = append(out, decode(data[name]))
		}
	}
	if legacy, ok := spec["data"]; ok && legacy != nil && legacy != "" {
		out = append(out, decode(legacy))
	}
	return out
}

// decryptionLabels returns the labels a SealedSecret's values may be sealed
// with: first the one its scope gives, as the controller reads the scope
// annotations from the SealedSecret's own metadata (SecretScope and
// EncryptionLabel, in v1alpha1's unseal), then the other two. A value a key
// decrypts under another scope's label is still that key's reference.
func decryptionLabels(obj *unstructured.Unstructured) [][]byte {
	ns, name := obj.GetNamespace(), obj.GetName()
	first := ssv1alpha1.SecretScope(obj)
	out := [][]byte{ssv1alpha1.EncryptionLabel(ns, name, first)}
	for _, scope := range []ssv1alpha1.SealingScope{ssv1alpha1.StrictScope, ssv1alpha1.NamespaceWideScope, ssv1alpha1.ClusterWideScope} {
		if scope != first {
			out = append(out, ssv1alpha1.EncryptionLabel(ns, name, scope))
		}
	}
	return out
}

// matchValue returns the fingerprint of the key in ring that sealed a
// value, trying each label in turn, or "" when none did. It decrypts only
// the RSA-OAEP part, with SHA-256 as the controller does, and clears the
// one-time key that yields at once.
func matchValue(ciphertext []byte, labels [][]byte, ring []sealingKey) string {
	if len(ciphertext) < 2 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(ciphertext))
	if len(ciphertext) < 2+n {
		return ""
	}
	wrapped := ciphertext[2 : 2+n]
	for _, label := range labels {
		for _, k := range ring {
			// an RSA ciphertext is as long as its key's modulus
			if k.priv.Size() != n {
				continue
			}
			sessionKey, err := rsa.DecryptOAEP(sha256.New(), nil, k.priv, wrapped, label)
			if err == nil {
				clear(sessionKey)
				return k.fingerprint
			}
		}
	}
	return ""
}
