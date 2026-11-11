package repos

import (
	"container/list"
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
)

// Cache sizes and lifetimes. A full cache drops what was used least
// recently.
const (
	// installedTTL is how long the installation's repository list is reused:
	// a repository the App is newly installed on is listed within it.
	installedTTL = 5 * time.Minute
	// repositoryTTL is how long a repository's details (default branch,
	// archived) are reused.
	repositoryTTL = time.Minute

	// permissions are kept for the list's 10 minutes: enough for dozens of
	// users of an installation of a thousand repositories
	maxPermissionEntries = 50_000
	maxRepositories      = 2_000
	maxSnapshots         = 1_000
	// a discovery reads up to maxCandidates blobs, so this keeps the blobs
	// of dozens of repositories' heads
	maxParsedBlobs = 20_000
)

// Cache holds GitHub's answers for every env a process serves. They come
// from one GitHub App installation, so the envs share them rather than each
// asking GitHub again. Keys name everything an answer depends on (the user,
// the env and its annotations, the discovery globs), so no env sees another
// env's results. Concurrent lookups of the same thing make one call.
type Cache struct {
	installed   *lru[[]githubapp.Repository]
	repos       *lru[githubapp.Repository]
	permissions *lru[permission]
	snapshots   *lru[snapshot]
	parsed      *lru[parsedBlob]
	calls       singleflight.Group
}

// NewCache returns an empty Cache.
func NewCache() *Cache {
	return &Cache{
		installed:   newLRU[[]githubapp.Repository](1),
		repos:       newLRU[githubapp.Repository](maxRepositories),
		permissions: newLRU[permission](maxPermissionEntries),
		snapshots:   newLRU[snapshot](maxSnapshots),
		parsed:      newLRU[parsedBlob](maxParsedBlobs),
	}
}

// sharedCallTimeout bounds a GitHub call that callers share: longer than
// any request waits for one, so it outlives the caller that started it, but
// not for ever.
const sharedCallTimeout = 30 * time.Second

// once runs fn for the first of concurrent callers with the same key; the
// others wait for its result. fn runs apart from the callers' contexts (with
// their values), under its own time limit, so one caller giving up or
// running out of time does not fail the others. Each caller waits only as
// long as its own context lets it.
func once[T any](ctx context.Context, c *Cache, key string, fn func(context.Context) (T, error)) (T, error) {
	shared := context.WithoutCancel(ctx)
	results := c.calls.DoChan(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(shared, sharedCallTimeout)
		defer cancel()
		return fn(ctx)
	})
	select {
	case res := <-results:
		out, _ := res.Val.(T)
		return out, res.Err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// lru is a map of at most max entries that drops the least recently used
// one to make room. An entry can expire.
type lru[V any] struct {
	mu    sync.Mutex
	max   int
	order *list.List // of *lruEntry[V], most recently used first
	items map[string]*list.Element
}

type lruEntry[V any] struct {
	key   string
	value V
	// expires is when the entry stops being returned; zero is never
	expires time.Time
}

func newLRU[V any](maxEntries int) *lru[V] {
	return &lru[V]{max: maxEntries, order: list.New(), items: map[string]*list.Element{}}
}

func (c *lru[V]) get(key string, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero V
	el, ok := c.items[key]
	if !ok {
		return zero, false
	}
	e := el.Value.(*lruEntry[V])
	if !e.expires.IsZero() && !now.Before(e.expires) {
		c.order.Remove(el)
		delete(c.items, key)
		return zero, false
	}
	c.order.MoveToFront(el)
	return e.value, true
}

func (c *lru[V]) put(key string, value V, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*lruEntry[V])
		e.value, e.expires = value, expires
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&lruEntry[V]{key: key, value: value, expires: expires})
	for c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruEntry[V]).key)
	}
}

func (c *lru[V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
