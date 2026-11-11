package agent

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"runtime"
	"slices"
	"sort"
	"sync"
	"time"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	sscrypto "github.com/bitnami/sealed-secrets/pkg/crypto"
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
//
// A count lists every SealedSecret first, keeping of those it has not
// matched before only the RSA part of each value, and decrypts after, on a
// few goroutines: a long count cannot outlive the list's continue tokens,
// and what it matched is kept even when it is cut short, so the next count
// goes on from there.

// sealedSecretsResource is the SealedSecrets API. They are read with the
// dynamic client: the agent needs a few of their fields, not the
// controller's types.
var sealedSecretsResource = schema.GroupVersionResource{Group: "bitnami.com", Version: "v1alpha1", Resource: "sealedsecrets"}

// Counting.
const (
	// usagePageSize is how many SealedSecrets one list call returns. A page
	// is held decoded while it is read: a few MiB for SealedSecrets of many
	// values each, applied with kubectl (which keeps a copy of each).
	usagePageSize = 100
	// usageScanTimeout bounds one count, so a stuck call does not stop
	// the counts after it.
	usageScanTimeout = 10 * time.Minute
	// usageMaxPending bounds the values one count decrypts afresh, about
	// 26 MiB of RSA parts with 4096-bit keys: the rest wait for the next
	// count, and this one reports itself incomplete.
	usageMaxPending = 50_000
	// usageMaxWorkers bounds the goroutines that decrypt.
	usageMaxWorkers = 4
)

// Usage counts the values the controller's SealedSecrets hold by the key
// that sealed them. It runs on its own, every interval, never in the way of
// check-ins; a removal counts again before it removes a key. It needs the
// cleanup capability's RBAC (list SealedSecrets) and keys' (list Secrets).
type Usage struct {
	kube          kubernetes.Interface
	sealedSecrets dynamic.Interface
	namespace     string
	deployment    string
	interval      time.Duration
	workers       int
	maxPending    int
	logger        *slog.Logger
	now           func() time.Time

	// running holds a token while a count runs, one at a time; a caller
	// waiting for it gives up when its context ends. It guards what counts
	// keep: cached holds what each SealedSecret's values matched, until the
	// object changes (namespace/name, then UID and resourceVersion); gen
	// counts the counts whose key set gained a key, and added holds the gen
	// each key in the set was added at, so an unmatched value is tried
	// again with keys added since; matched is how many values each key
	// matched last, so the likeliest key is tried first.
	running chan struct{}
	cached  map[string]*sealedUsage
	gen     int
	added   map[string]int
	matched map[string]int
	// onMatched, when set, is called as each SealedSecret is matched, for
	// tests
	onMatched func(id string)

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
	// Interval is the least time between the starts of two counts, and the
	// pause after a count that failed or overran it.
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
		workers:       max(1, min(usageMaxWorkers, runtime.GOMAXPROCS(0))),
		maxPending:    usageMaxPending,
		logger:        logger,
		now:           now,
		running:       make(chan struct{}, 1),
		cached:        map[string]*sealedUsage{},
		added:         map[string]int{},
		matched:       map[string]int{},
	}
}

// Run counts now, then at most every interval, until ctx ends. After a count
// that failed, or took longer than the interval, it waits the whole
// interval, so a count that cannot finish does not run back to back.
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
		sleep(ctx, u.pause(time.Since(started), err != nil))
	}
	return nil
}

// pause is how long Run waits after a count that took elapsed: the rest of
// the interval, or all of it after a count that failed or overran it.
func (u *Usage) pause(elapsed time.Duration, failed bool) time.Duration {
	if wait := u.interval - elapsed; !failed && wait > 0 {
		return wait
	}
	return u.interval
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
// too, with its error and no counts; it returns the error as well. It waits
// for a count already running, until ctx ends; a count cut short by
// shutdown is not kept as the latest, though what it matched is.
func (u *Usage) Count(ctx context.Context) (protocol.KeyUsage, error) {
	r, _, err := u.count(ctx)
	return r, err
}

// count is Count, which also returns the fingerprints of the keys it
// counted with: a key Secret that did not load is not among them.
func (u *Usage) count(ctx context.Context) (protocol.KeyUsage, map[string]bool, error) {
	select {
	case u.running <- struct{}{}:
	case <-ctx.Done():
		return protocol.KeyUsage{}, nil, fmt.Errorf("failed to count the values sealed with each key: waiting for the count running: %w", ctx.Err())
	}
	defer func() { <-u.running }()
	r, ring, err := u.scan(ctx)
	if err != nil {
		r = protocol.KeyUsage{Error: truncate(err.Error(), protocol.MaxUsageError)}
	}
	r.ScannedAt = u.now().UTC()
	if !errors.Is(ctx.Err(), context.Canceled) {
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

// pendingObject is a SealedSecret a count must decrypt values of: one new or
// changed (prev nil), or one with unmatched values to try again with the
// keys added since prev was tried. It holds only the RSA part of each
// value.
type pendingObject struct {
	id              string
	uid             types.UID
	resourceVersion string
	labels          [][]byte
	wrapped         [][]byte
	prev            *sealedUsage
}

// scan counts once. The caller holds running.
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

	// list everything first, so no continue token waits on decryption
	seen, pending, deferred, err := u.listAll(ctx, scope)
	if err != nil {
		return protocol.KeyUsage{}, nil, err
	}
	done := u.decrypt(ctx, pending, ring)
	maps.Copy(seen, done)
	if len(done) < len(pending) {
		// cut short: keep what this count matched beside what was matched
		// before, so the next goes on from there
		maps.Copy(u.cached, seen)
		return protocol.KeyUsage{}, nil, fmt.Errorf("failed to count the values sealed with each key: matched %d of %d SealedSecrets before %w; the next count goes on from there",
			len(done), len(pending), ctx.Err())
	}
	// SealedSecrets gone since are forgotten
	u.cached = seen
	if deferred > 0 {
		return protocol.KeyUsage{}, nil, fmt.Errorf("counted part of the values sealed with each key: %d SealedSecrets wait for the next count, which goes on from there", deferred)
	}

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

// listAll lists the SealedSecrets the controller watches. It returns those
// whose earlier match stands, by namespace/name; those to decrypt, with
// only what that needs; and how many are left for a later count, past
// maxPending values to decrypt.
func (u *Usage) listAll(ctx context.Context, scope watchScope) (map[string]*sealedUsage, []pendingObject, int, error) {
	seen := map[string]*sealedUsage{}
	var pending []pendingObject
	values, deferred := 0, 0
	namespaces := scope.namespaces
	if namespaces == nil {
		namespaces = []string{metav1.NamespaceAll}
	}
	for _, ns := range namespaces {
		err := u.list(ctx, ns, scope.labelSelector, func(obj *unstructured.Unstructured) {
			id := obj.GetNamespace() + "/" + obj.GetName()
			prev := u.cached[id]
			changed := prev == nil || prev.uid != obj.GetUID() || prev.resourceVersion != obj.GetResourceVersion()
			if !changed && (prev.tried == u.gen || !slices.Contains(prev.values, "")) {
				seen[id] = prev
				return
			}
			wrapped := wrappedKeys(obj.Object)
			if values+len(wrapped) > u.maxPending && len(pending) > 0 {
				if changed {
					deferred++
				} else {
					// its earlier match stands meanwhile
					seen[id] = prev
				}
				return
			}
			p := pendingObject{id: id, uid: obj.GetUID(), resourceVersion: obj.GetResourceVersion(), labels: decryptionLabels(obj), wrapped: wrapped}
			if !changed {
				p.prev = prev
			}
			values += len(wrapped)
			pending = append(pending, p)
		})
		if err != nil {
			return nil, nil, 0, err
		}
	}
	return seen, pending, deferred, nil
}

// decrypt works out which key sealed each pending value, on a few
// goroutines, and returns what it finished, by namespace/name: all of it
// unless ctx ended first. Unchanged SealedSecrets are tried only with the
// keys added since they were.
func (u *Usage) decrypt(ctx context.Context, pending []pendingObject, ring []sealingKey) map[string]*sealedUsage {
	results := make([]*sealedUsage, len(pending))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(u.workers, max(len(pending), 1)) {
		wg.Go(func() {
			for i := range jobs {
				p := pending[i]
				keys := ring
				if p.prev != nil {
					keys = slices.DeleteFunc(slices.Clone(ring), func(k sealingKey) bool { return u.added[k.fingerprint] <= p.prev.tried })
				}
				if s, ok := matchObject(ctx, p, keys, u.gen); ok {
					results[i] = s
					if u.onMatched != nil {
						u.onMatched(p.id)
					}
				}
			}
		})
	}
	for i := range pending {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	out := map[string]*sealedUsage{}
	for i, s := range results {
		if s != nil {
			out[pending[i].id] = s
		}
	}
	return out
}

// matchObject matches a pending SealedSecret's values with keys: every
// value of one new or changed, only those still unmatched of one tried
// before. It reports false when ctx ended before it finished.
func matchObject(ctx context.Context, p pendingObject, keys []sealingKey, gen int) (*sealedUsage, bool) {
	s := &sealedUsage{uid: p.uid, resourceVersion: p.resourceVersion, values: make([]string, len(p.wrapped)), tried: gen}
	if p.prev != nil {
		copy(s.values, p.prev.values)
	}
	for i, wrapped := range p.wrapped {
		if ctx.Err() != nil {
			return nil, false
		}
		if s.values[i] == "" {
			s.values[i] = matchValue(wrapped, p.labels, keys)
		}
	}
	return s, true
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

// keyRing reads the cluster's keys for one count (readKeyRing).
func (u *Usage) keyRing(ctx context.Context) ([]sealingKey, error) {
	return readKeyRing(ctx, u.kube, u.namespace, u.logger, "values sealed with its key count as unmatched")
}

// readKeyRing reads every key Secret in the controller's namespace, under
// any value of the key label (a key relabeled as compromised still
// decrypts), as the controller reads one when it starts, and names each by
// its private key, as the controller does (keyregistry.go). A Secret that
// would not load is left out, and logged with consequence.
func readKeyRing(ctx context.Context, kube kubernetes.Interface, namespace string, logger *slog.Logger, consequence string) ([]sealingKey, error) {
	list, err := kube.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: keyLabel})
	if err != nil {
		return nil, fmt.Errorf("failed to list key secrets in %s: %w", namespace, err)
	}
	var ring []sealingKey
	for i := range list.Items {
		s := &list.Items[i]
		priv, err := readKeyPair(s.Data["tls.crt"], s.Data["tls.key"])
		if err != nil {
			logger.WarnContext(ctx, "skipping a key secret that does not load; "+consequence,
				"event", "controller.key_unusable", "secret", s.Name, "error", err)
			continue
		}
		fp, err := sscrypto.PublicKeyFingerprint(&priv.PublicKey)
		if err != nil || slices.ContainsFunc(ring, func(k sealingKey) bool { return k.fingerprint == fp }) {
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

// wrappedKeys returns the RSA part of each of a SealedSecret's ciphertexts,
// in a stable order: each value of spec.encryptedData by its key, then the
// legacy spec.data, a whole Secret sealed as one value. Only the head of
// each value is decoded. A value too short or not base64 is nil, which no
// key decrypts.
func wrappedKeys(obj map[string]any) [][]byte {
	spec, _ := obj["spec"].(map[string]any)
	var out [][]byte
	if data, ok := spec["encryptedData"].(map[string]any); ok {
		for _, name := range slices.Sorted(maps.Keys(data)) {
			s, _ := data[name].(string)
			out = append(out, rsaPart(s))
		}
	}
	if legacy, ok := spec["data"]; ok && legacy != nil && legacy != "" {
		s, _ := legacy.(string)
		out = append(out, rsaPart(s))
	}
	return out
}

// rsaPart decodes the head of a base64 ciphertext, its 2-byte length and
// the RSA ciphertext after it, and returns the RSA ciphertext alone.
func rsaPart(b64 string) []byte {
	if len(b64) < 4 {
		return nil
	}
	head, err := base64.StdEncoding.DecodeString(b64[:4])
	if err != nil || len(head) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(head))
	// the whole base64 quanta covering 2+n bytes
	chars := (2 + n + 2) / 3 * 4
	if n == 0 || chars > len(b64) {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(b64[:chars])
	if err != nil || len(b) < 2+n {
		return nil
	}
	return b[2 : 2+n : 2+n]
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
// value, from its RSA part (wrapped), trying each label in turn, or "" when
// none did. It decrypts with RSA-OAEP and SHA-256 as the controller does,
// and clears the one-time key that yields at once.
func matchValue(wrapped []byte, labels [][]byte, ring []sealingKey) string {
	if len(wrapped) == 0 {
		return ""
	}
	for _, label := range labels {
		for _, k := range ring {
			// an RSA ciphertext is as long as its key's modulus
			if k.priv.Size() != len(wrapped) {
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
