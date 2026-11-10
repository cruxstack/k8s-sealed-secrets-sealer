package controlplane

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
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
)

// limit admits a signed-in user's request to next while it is within every
// one of limits, and otherwise answers 429 with Retry-After.
func (s *Server) limit(next http.HandlerFunc, limits ...rateLimit) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := userauth.UserFrom(ctx)
		now := s.now()
		for _, l := range limits {
			key := l.name + "#" + strconv.FormatInt(user.ID, 10)
			if l.perSession {
				id := r.PathValue("id")
				if _, err := ulid.ParseStrict(id); err != nil {
					// no such session: the handler refuses the request
					continue
				}
				key += "#" + id
			}
			end := now.Truncate(l.window).Add(l.window)
			ok, err := s.store.CountRequest(ctx, key, l.max, end)
			if err != nil {
				// a limit guards the service; it does not stop it working
				s.logger.WarnContext(ctx, "failed to count request; letting it through",
					"env", s.env, "limit", l.name, "user_id", user.ID, "error", err)
				continue
			}
			if !ok {
				retry := max(int(math.Ceil(end.Sub(now).Seconds())), 1)
				s.logger.WarnContext(ctx, "request rate limited",
					"event", "request.rate_limited", "env", s.env, "limit", l.name,
					"user", user.Login, "user_id", user.ID, "path", r.URL.Path)
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many requests; try again in %d seconds", retry))
				return
			}
		}
		next(w, r)
	}
}
