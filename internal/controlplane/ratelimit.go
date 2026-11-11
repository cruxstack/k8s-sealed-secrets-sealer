package controlplane

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// rateLimit allows at most max requests of a kind in each fixed window, per
// user or per session.
type rateLimit struct {
	// name keys the limit's counters and names it in logs.
	name   string
	max    int
	window time.Duration
	// perSession counts per session (the path's {id}) instead of per user.
	perSession bool
}

// Request rate limits for signed-in users (docs/design.md, section 12):
// generous for a person using the UI, tight for a script. Each call they
// cover costs GitHub requests, KMS or agent work. The counters are kept in
// the store, so the limits hold across instances.
var (
	limitRepos        = rateLimit{name: "repos", max: 10, window: time.Minute}
	limitFiles        = rateLimit{name: "files", max: 30, window: time.Minute}
	limitSessions     = rateLimit{name: "sessions", max: 10, window: time.Minute}
	limitSessionSeals = rateLimit{name: "session-seals", max: 20, window: time.Minute, perSession: true}
	limitSeals        = rateLimit{name: "seals", max: 30, window: time.Minute}
	limitPulls        = rateLimit{name: "pulls", max: 5, window: time.Minute}
	limitReseals      = rateLimit{name: "reseals", max: 10, window: time.Minute}
	// limitRepoChecks counts the permission lookups repository lists make
	// on GitHub, not the lists: a list on an instance that has not checked
	// lately costs one per repository installed, and on Lambda that is
	// most lists. It allows a full list of up to a thousand repositories
	// every ten minutes, when the list's permissions lapse; a list that
	// starts within it may finish past it.
	limitRepoChecks = rateLimit{name: "repo-checks", max: 1000, window: 10 * time.Minute}
)

// limit admits a signed-in user's request to next while it is within every
// one of limits, and otherwise answers 429 with Retry-After. A GET it
// limits must come from the UI's own scripts: another site's page could
// otherwise spend the user's limits with links and redirects.
func (s *Server) limit(next http.HandlerFunc, limits ...rateLimit) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !fromThisSite(r) {
			writeError(w, http.StatusForbidden, "this request must come from the sealer's own pages")
			return
		}
		for _, l := range limits {
			key, ok := limitKey(r, l)
			if ok && !s.admit(w, r, l, key, 1) {
				return
			}
		}
		next(w, r)
	}
}

// limitKey names the counter of a limit for a request: the user's, or the
// session's in the path. A path naming no valid session has none.
func limitKey(r *http.Request, l rateLimit) (string, bool) {
	key := l.name + "#" + strconv.FormatInt(userauth.UserFrom(r.Context()).ID, 10)
	if l.perSession {
		id := r.PathValue("id")
		if _, err := ulid.ParseStrict(id); err != nil {
			// no such session: the handler refuses the request
			return "", false
		}
		key += "#" + id
	}
	return key, true
}

// fromThisSite reports whether a request comes from the UI's scripts rather
// than a navigation another site started. Browsers say so in
// Sec-Fetch-Site; the UI also sends X-Requested-With, which another site's
// page cannot send without CORS, which this server never allows.
func fromThisSite(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Site") == "same-origin" || r.Header.Get("X-Requested-With") != ""
}

// admit counts n requests, or calls a request makes, against a limit, and
// reports whether it had room for them. When it had not, it answers 429
// with Retry-After.
func (s *Server) admit(w http.ResponseWriter, r *http.Request, l rateLimit, key string, n int) bool {
	ctx := r.Context()
	now := s.now()
	end := now.Truncate(l.window).Add(l.window)
	if s.countRequests(ctx, l, key, n, end, now) {
		return true
	}
	user := userauth.UserFrom(ctx)
	retry := time.Duration(max(math.Ceil(end.Sub(now).Seconds()), 1)) * time.Second
	s.logger.WarnContext(ctx, "request rate limited",
		"event", "request.rate_limited", "env", s.env, "limit", l.name,
		"user", user.Login, "user_id", user.ID, "path", r.URL.Path)
	w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
	writeError(w, http.StatusTooManyRequests, "too many requests; try again in "+aboutDuration(retry))
	return false
}

// charge counts n calls a request made against a limit once they are
// made, so later requests find it reached; this one is answered already.
func (s *Server) charge(ctx context.Context, l rateLimit, key string, n int) {
	if n <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	now := s.now()
	s.countRequests(ctx, l, key, n, now.Truncate(l.window).Add(l.window), now)
}

// countRequests counts n against key in the store, or in this instance
// when the store cannot: a store throttling a busy counter must not lift
// its limit.
func (s *Server) countRequests(ctx context.Context, l rateLimit, key string, n int, end, now time.Time) bool {
	ok, err := s.store.CountRequest(ctx, key, n, l.max, end)
	if err == nil {
		return ok
	}
	s.logger.WarnContext(ctx, "failed to count request; counting it in this instance",
		"env", s.env, "limit", l.name, "error", err)
	return s.localCounts.count(key, n, l.max, end, now)
}

// localCounts counts requests in this instance, for when the store cannot.
type localCounts struct {
	mu     sync.Mutex
	counts map[localWindow]int
}

type localWindow struct {
	key string
	end int64
}

// maxLocalCounts bounds the windows counted in an instance; past it, those
// that ended are forgotten, and then every one.
const maxLocalCounts = 10_000

func (c *localCounts) count(key string, n, limit int, end, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[localWindow]int{}
	}
	if len(c.counts) >= maxLocalCounts {
		for w := range c.counts {
			if w.end <= now.Unix() {
				delete(c.counts, w)
			}
		}
		if len(c.counts) >= maxLocalCounts {
			clear(c.counts)
		}
	}
	w := localWindow{key: key, end: end.Unix()}
	if c.counts[w] >= limit {
		return false
	}
	c.counts[w] += n
	return true
}
